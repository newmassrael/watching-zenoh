// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The storage plane of a node (§5.11, §5.24), the wz mirror of zenoh's
//! `zenoh-plugin-storage-manager`: the server layer that hosts named storages on the session.
//!
//! [`storage_manager`] hosts N named storages over a registry of named volumes. The backend,
//! volume and config types it composes are still in `wz-session-core`, under `storage-backend`,
//! and join this crate in later steps of the server-layer split. A module keeps the name it had
//! in the core, so a downstream path changes only its crate and a citation of the file still
//! names one file. This crate is built on the core and the core never names it
//! (`scripts/lib/layer_direction_gate.py`).

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod storage_manager;
