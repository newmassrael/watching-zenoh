// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The storage plane of a node (§5.11, §5.24), the wz mirror of zenoh's
//! `zenoh-plugin-storage-manager`: the server layer that hosts named storages on the session.
//!
//! [`storage_manager`] hosts N named storages over a registry of named volumes, and
//! `storage_plugin_config` (under `adminspace-config-hotreload`) reads the manager's
//! `plugins.storage_manager` document and the difference between two of them. The backend,
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

/// R2785 — the §5.23 `adminspace-config-hotreload` DECLARATIVE input: the
/// storage manager's `plugins.storage_manager` document read the way upstream's
/// `PluginConfig` reader reads it, and upstream's `ConfigDiff` between two of
/// them. The base a startup config and a runtime config write share; the host
/// holding the storage manager applies the diffs.
#[cfg(feature = "adminspace-config-hotreload")]
pub mod storage_plugin_config;
