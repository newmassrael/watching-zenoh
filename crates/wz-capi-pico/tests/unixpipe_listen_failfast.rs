// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! CALLER fail-fast discriminator, pico half (§5.27, R311y391).
//!
//! The pico twin of `wz-ap-demo`'s `run_router` fail-fast: pico's
//! `z_open(listen)` holds N concurrent inbound peers off ONE accept loop
//! (`listener_multipeer.rs`), so a non-mesh-capable acceptor — a
//! single-connection unixpipe, whose non-blocking FIFO open returns at once —
//! would reject-throttle every accept forever, "listening" yet holding 0 faces.
//! `drive_listen` rejects such a `--listen` at bind (consulting
//! `BoundListener::supports_mesh_multi_peer`), so `z_open` reports the open
//! failure to the C caller.
//!
//! `transport-link-unixpipe` is a SUPERSET feature, not a zenoh-pico-native link
//! (real pico has no unixpipe), and it is off-default — so the whole module is
//! gated on it; without it `bind_endpoint("unixpipe/..")` fails at the
//! accept-backend gate and the guard is unreachable. This is the ONLY lane that
//! reaches a real `BoundListener::Unixpipe` through the pico C ABI.

#[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
mod failfast {
    use std::ffi::CString;

    use wz_capi_pico::{
        z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
        z_owned_session_t, z_session_drop, z_session_loan_mut, z_session_move, zp_config_insert,
        Z_CONFIG_LISTEN_KEY, Z_ERR_GENERIC, Z_OK,
    };

    /// `z_open(listen="unixpipe/..")` must FAIL: the mesh listener cannot hold
    /// faces on a single-connection unixpipe acceptor, so `drive_listen` rejects
    /// it at bind and `z_open` returns `Z_ERR_GENERIC`.
    ///
    /// RED reproduction (proof this binds to the guard, not the vehicle): remove
    /// the `if !listener.supports_mesh_multi_peer()` guard in `drive_listen` ->
    /// `bind_endpoint` succeeds -> `tx.send(true)` -> `z_open` returns `Z_OK` (a
    /// listening session with a background reject-throttle loop) -> this
    /// `assert_eq` fails. With the feature ON, `bind_endpoint("unixpipe/..")`
    /// genuinely succeeds (produces a `BoundListener::Unixpipe`), so the failure
    /// comes from the guard, NOT from a bind error.
    #[test]
    fn pico_z_open_rejects_a_unixpipe_listen_at_bind() {
        let base = std::env::temp_dir()
            .join(format!("wz-capi-pico-failfast-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        // Pre-clean any stale FIFO nodes from a crashed prior run (no-flaky):
        // bind_unixpipe's mkfifo EEXIST-fails on a leftover pair.
        let _ = std::fs::remove_file(format!("{base}_uplink"));
        let _ = std::fs::remove_file(format!("{base}_downlink"));

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
            if rc == Z_OK {
                // RED path only: the guard is gone and the session actually
                // opened; close it so the background accept loop thread does not
                // leak before we fail the assertion below.
                z_close(z_session_loan_mut(&mut session), std::ptr::null());
                z_session_drop(z_session_move(&mut session));
            }
            assert_eq!(
                rc, Z_ERR_GENERIC,
                "pico z_open(listen=unixpipe/..) must reject a single-connection \
                 unixpipe listener at bind (a mesh listener cannot hold faces on it)"
            );
        }

        // bind_endpoint mkfifo'd the pair before the fail-fast returned; unlink.
        let _ = std::fs::remove_file(format!("{base}_uplink"));
        let _ = std::fs::remove_file(format!("{base}_downlink"));
    }
}
