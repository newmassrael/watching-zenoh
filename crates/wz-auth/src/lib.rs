// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The auth methods a node plugs into the session handshake (§5.16), the wz mirror of zenoh's
//! `io/zenoh-transport/src/unicast/establishment/ext/auth/` methods.
//!
//! The handshake's half of authentication is not here: the Z_EXT_AUTH sub-extension and the
//! per-method demux, [`AuthDispatch`](wz_session_core::auth_dispatch::AuthDispatch), are in
//! `wz-session-core`, which the drive loop reads on every frame. A method here implements
//! [`AuthMethod`](wz_session_core::auth_dispatch::AuthMethod) and is handed to
//! `AuthDispatch::new` by whoever builds the session. This crate is built on the core and the core
//! never names it (`scripts/lib/layer_direction_gate.py`).

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod usrpwd;
