// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The storage plane of a node (§5.11, §5.24), the wz mirror of zenoh's
//! `zenoh-plugin-storage-manager` and `zenoh-backend-traits`: the server layer that hosts
//! named storages on the session.
//!
//! The backend seam ([`storage_backend`]), the service gate ([`storage_state`]) and the volume
//! ([`storage_volume`]) are always here; the history backend, the strip-prefix transforms,
//! replication and the aligner are each behind the feature of their name. [`storage_manager`]
//! hosts N named storages over a registry of named volumes, and `storage_plugin_config` (under
//! `adminspace-config-hotreload`) reads the manager's `plugins.storage_manager` document and the
//! difference between two of them. The one storage type still in `wz-session-core` is the config
//! (`storage_config`, under its `storage-backend`), which the admin space's storage-add arm reads
//! and which joins this crate when the admin space leaves the core.
//!
//! A module keeps the name it had in the core, so a downstream path changes only its crate and a
//! citation of the file still names one file. This crate is built on the core and the core never
//! names it (`scripts/lib/layer_direction_gate.py`).

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

// R311uw — the `storage-backend` atom (§5.11 storage, 1/4): the pluggable
// `storage_backend::StorageBackend` seam + an in-memory backend
// (`storage_backend::MemoryStorage`). A faithful mirror of zenoh's
// `zenoh-backend-traits` `Storage` trait + the bundled `memory_backend`. The
// BTreeMap / String / Vec backing + the core's `sample` TimestampHint /
// EncodingHint the `StoredData` embeds. Runtime-agnostic backend layer; the
// wz-runtime-tokio StorageService driver wraps it.
pub mod storage_backend;

// R311ux — the storage *service gate* (§5.11 storage, atom 2/4): the
// newer-wins versioning decision + the query-match set
// (`storage_state::StorageState`). The runtime-agnostic half of a
// storage service — pure no_std, no Subscriber / Queryable / async — that
// turns the dumb `storage_backend::StorageBackend` into a storage by
// applying zenoh's `guard_cache_if_latest` newer-wins gate (older
// Put/Delete -> Outdated; Delete leaves a tombstone timestamp) and
// resolving a (wildcard) query into the matching stored entries via the
// core's shared `keyexpr_match::keyexpr_intersects_target` scan. The
// wz-runtime-tokio StorageService driver (Subscriber + complete Queryable +
// select loop) wraps a `StorageState` (atom 3).
pub mod storage_state;

// R311y55 — the §5.24 storage *Volume* layer: the FACTORY
// (`storage_volume::Volume`) above the §5.11 per-store
// `storage_backend::StorageBackend`, plus the `storage_volume::Capability` /
// `storage_volume::Persistence` guarantees and the base in-memory
// `storage_volume::MemoryVolume`. The wz mirror of zenoh
// `zenoh-backend-traits` `Volume` + `MemoryBackend` — the keystone a storage
// MANAGER drives to host N named storages. FOUNDATIONAL: no own cfg toggle;
// the toggleable manager atoms (multi-storage-host / strip-prefix / GC)
// compose on it.
pub mod storage_volume;

pub mod storage_manager;

/// R2785 — the §5.23 `adminspace-config-hotreload` DECLARATIVE input: the
/// storage manager's `plugins.storage_manager` document read the way upstream's
/// `PluginConfig` reader reads it, and upstream's `ConfigDiff` between two of
/// them. The base a startup config and a runtime config write share; the host
/// holding the storage manager applies the diffs.
#[cfg(feature = "adminspace-config-hotreload")]
pub mod storage_plugin_config;

// R311y58 — the §5.24 `storage-mgr-strip-prefix` atom: the
// `storage_strip_prefix::strip_prefix` / `storage_strip_prefix::restore_prefix`
// key transforms a storage manager applies so a storage holds keys RELATIVE to a
// mount point (the wz mirror of zenoh's `strip_prefix` / `prefix`). Closes the
// R311wt aligner strip_prefix gap at the LOGIC level; the live manager/backend
// application (which needs a §5.11 backend Option-key change for the exact-match
// none-key) is a documented follow-up.
#[cfg(feature = "storage-mgr-strip-prefix")]
pub mod storage_strip_prefix;

// R311uz — the `storage-history` atom (§5.11 storage, 2/4): an in-memory
// `History::All` backend (`storage_history::HistoryStorage`) that keeps
// every version per key, the multi-version counterpart of
// `storage_backend::MemoryStorage`. The newer-wins gate skips an `All`
// backend (every version retained); a query replies all versions.
#[cfg(feature = "storage-history")]
pub mod storage_history;

// Round 311vh — the storage-replication *primitives* atom (§5.11 storage,
// replication 1/N): the `storage_replication::Fingerprint`, the
// time-bucket classification (`storage_replication::IntervalIdx` /
// `storage_replication::SubIntervalIdx`), the
// `storage_replication::ReplicationConfig` + its compatibility
// fingerprint, and the `storage_replication::event_fingerprint` a
// replica's Digest is assembled from. Pure no_std xxh3 logic — a faithful,
// byte-exact mirror of zenoh's `zenoh-plugin-storage-manager`
// `replication::{digest,classification,configuration,log}`. Its wire codec is
// built on the core's `wire_bincode` (its `wire-bincode` feature).
#[cfg(feature = "storage-replication")]
pub mod storage_replication;

// Round 311vr — the storage-aligner *event metadata* atom (§5.11 storage,
// aligner 1/N): the `storage_aligner::Action` + `storage_aligner::EventMetadata`
// a replica exchanges to pull the entries a
// `storage_replication::DigestDiff` localised. The metadata's
// `fingerprint` (`storage_aligner::EventMetadata::fingerprint`) reuses the
// `storage_replication::event_fingerprint` SSOT, so an event's identity
// agrees between the digest and the aligner. Pure no_std logic — a faithful
// mirror of zenoh's `zenoh-plugin-storage-manager` `replication::log`
// metadata (all four `Action` variants round-trip on the wire as of R311wt
// slice-1). The AlignmentQuery / AlignmentReply protocol + the answer / pull
// engines + the aligner driver are the follow-up atoms. Gated on
// `storage-aligner` (implies `storage-replication`).
#[cfg(feature = "storage-aligner")]
pub mod storage_aligner;
