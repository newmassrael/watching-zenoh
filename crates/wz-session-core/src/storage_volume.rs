// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.24 storage Volume layer — the FACTORY above the §5.11 per-store
//! [`StorageBackend`](crate::storage_backend::StorageBackend). The wz mirror of
//! zenoh `zenoh-backend-traits` `Volume`
//! (`plugins/zenoh-backend-traits/src/lib.rs:184`): a [`Volume`] advertises its
//! [`Capability`] and CREATES per-storage `StorageBackend` instances — the seam a
//! storage MANAGER drives to host N named storages over one backend kind. Where
//! §5.11 is "one store", §5.24 is "the factory + manager above the stores".
//!
//! FOUNDATIONAL (always compiled under `storage-backend`, no own cfg toggle): the
//! trait seam + capability type + the base in-memory volume the future storage
//! manager builds on. The toggleable manager features (multi-storage-host,
//! strip-prefix, GC, wildcard-updates) compose ON this once `storage-mgr-config`
//! lands.
//!
//! R311y57 — [`Volume::create_storage`] takes the declarative [`StorageConfig`]
//! (the storage-mgr-config data model). Divergences from zenoh: wz's
//! `create_storage` is SYNC (zenoh's is `async`); it returns
//! `Result<Box<dyn StorageBackend + Send>, VolumeError>` (R311y60 — fallible like
//! zenoh's `ZResult`, so a future Durable volume lands without a breaking trait
//! change; R311y61 — `+ Send` so a volume-created backend can drive an async
//! runtime storage service, which the tokio `StorageService` hosts across worker
//! threads, mirroring zenoh's `Send + Sync` `Storage`); `get_admin_status`
//! (admin JSON) belongs to the adminspace layer, not this runtime-agnostic
//! kernel seam.
//!
//! NOTE (honest status): applying a config's `key_expr` / `strip_prefix` /
//! `complete` to the live key path is the storage manager / SERVICE's job, NOT the
//! volume's — `MemoryVolume::create_storage` deliberately makes a BARE backend and
//! does not consult the config beyond it (the architectural split, faithful to
//! zenoh, whose MemoryBackend likewise creates a bare store; strip/complete are
//! applied by the service layer, `storage-manager/lib.rs:429`/`475`). What WAS a
//! standing gap when this note was written — no caller driving a non-default config
//! through the service — is now CLOSED (R311y61): `StorageService::declare_with_backend`
//! applies `config.strip_prefix` / `config.complete`, and `RuntimeStorageManager`
//! drives a `create_storage`-produced backend through it per `StorageConfig`, proven
//! e2e (wz-runtime-tokio `storage_manager_service` tests). zenoh's MemoryBackend also
//! retains the config for its admin-status, which wz's runtime-agnostic seam does not.

use crate::storage_backend::{History, MemoryStorage, StorageBackend};
use crate::storage_config::StorageConfig;
use alloc::boxed::Box;
use alloc::string::String;

/// The crash-persistence guarantee of a volume's storages — zenoh `Persistence`
/// (`backend-traits/lib.rs:142`). [`Volatile`](Persistence::Volatile) (default)
/// makes no post-crash guarantee (the storage is a cache);
/// [`Durable`](Persistence::Durable) survives a restart (metadata + values
/// persisted). wz's in-memory volume is `Volatile`; a `Durable` volume
/// (filesystem / db) is an out-of-scope external-backend atom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Persistence {
    /// No guarantee on content after a crash — a cache. zenoh `Persistence::Volatile`.
    #[default]
    Volatile,
    /// Survives a restart with all saved values + metadata. zenoh `Persistence::Durable`.
    Durable,
}

/// A volume's guarantees — zenoh `Capability { persistence, history }`
/// (`backend-traits/lib.rs:130`): the storage manager reads these to make
/// trade-off decisions (e.g. an [`History::All`] volume retains every version, so
/// the newer-wins gate above it is skipped). `history` reuses the §5.11
/// [`History`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// The crash-persistence guarantee.
    pub persistence: Persistence,
    /// Per-key version retention (`Latest` | `All`).
    pub history: History,
}

/// Why a [`Volume`] could not create a storage — the wz analogue of zenoh's
/// `ZResult` (`Volume::create_storage` is fallible, `backend-traits/lib.rs:194`).
/// The in-memory volume never fails, but a future Durable volume (filesystem / db)
/// reports a backend-open failure here, so the factory seam is FORWARD-STABLE: a
/// fallible backend lands without a breaking trait change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeError {
    /// The volume could not create the storage (e.g. a Durable backend failed to
    /// open its store), with a human-readable reason.
    CreateFailed(String),
}

impl core::fmt::Display for VolumeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VolumeError::CreateFailed(m) => write!(f, "volume failed to create storage: {m}"),
        }
    }
}

/// The storage-backend FACTORY seam — zenoh `Volume`
/// (`backend-traits/lib.rs:184`). A volume advertises its [`Capability`] and
/// creates per-storage [`StorageBackend`] instances; ONE volume backs N named
/// storages in the manager.
pub trait Volume {
    /// This volume's guarantees (zenoh `Volume::get_capability`). The manager
    /// consults it before routing a storage's data through the newer-wins gate.
    fn capability(&self) -> Capability;

    /// Create a per-storage backend instance for `config` (zenoh
    /// `Volume::create_storage(props)`), or [`VolumeError`] if the volume cannot
    /// (a Durable backend may fail to open). Boxed so the manager holds
    /// heterogeneous storages behind the [`StorageBackend`] seam. A config-agnostic
    /// backend (e.g. in-memory) may ignore `config`; applying the config's
    /// `key_expr` / `strip_prefix` / `complete` above the backend is the storage
    /// manager / service's job — NOT yet wired (the R311y55 carry's follow-up).
    fn create_storage(
        &self,
        config: &StorageConfig,
    ) -> Result<Box<dyn StorageBackend + Send>, VolumeError>;
}

/// The built-in in-memory volume — zenoh `MemoryBackend`
/// (`memory_backend/mod.rs:32`), the base volume the manager always has. Each
/// [`create_storage`](Volume::create_storage) yields a fresh, empty, independent
/// [`MemoryStorage`]; capability is `{Volatile, Latest}` (a non-persistent,
/// newest-only cache — the in-memory backend keeps no history and survives no
/// crash).
#[derive(Debug, Default)]
pub struct MemoryVolume;

impl Volume for MemoryVolume {
    fn capability(&self) -> Capability {
        Capability {
            persistence: Persistence::Volatile,
            history: History::Latest,
        }
    }

    fn create_storage(
        &self,
        _config: &StorageConfig,
    ) -> Result<Box<dyn StorageBackend + Send>, VolumeError> {
        // Always succeeds: a fresh in-memory store, config-agnostic. zenoh's
        // MemoryBackend likewise just makes a store (it retains the config only for
        // its admin-status, which wz's kernel seam does not carry); applying the
        // config's key_expr / strip_prefix / complete is the manager/service's job
        // and is NOT yet wired (a documented follow-up).
        Ok(Box::new(MemoryStorage::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::TimestampHint;
    use crate::storage_backend::StorageInsertionResult;
    use alloc::vec;

    fn ts(time: u64) -> TimestampHint {
        TimestampHint {
            time,
            zid: vec![0x01],
        }
    }

    #[test]
    fn persistence_default_is_volatile() {
        // zenoh Persistence default = Volatile (the cache posture).
        assert_eq!(Persistence::default(), Persistence::Volatile);
    }

    #[test]
    fn memory_volume_capability_is_volatile_latest() {
        // zenoh MemoryBackend: non-persistent, newest-only.
        assert_eq!(
            MemoryVolume.capability(),
            Capability {
                persistence: Persistence::Volatile,
                history: History::Latest,
            }
        );
    }

    #[test]
    fn memory_volume_creates_a_working_independent_storage() {
        // The factory yields a USABLE StorageBackend (put -> Inserted, get
        // round-trip), and two create_storage() calls are INDEPENDENT stores
        // (the manager hosts each named storage separately).
        let vol = MemoryVolume;
        let cfg = StorageConfig::new("demo", "demo/**", "mem");
        let mut s1 = vol
            .create_storage(&cfg)
            .expect("in-memory create never fails");
        assert_eq!(
            s1.put(Some("demo/a"), vec![1, 2, 3], None, ts(10)),
            StorageInsertionResult::Inserted
        );
        assert_eq!(
            s1.get(Some("demo/a")).expect("present after put").payload,
            vec![1, 2, 3]
        );

        let s2 = vol
            .create_storage(&cfg)
            .expect("in-memory create never fails");
        assert!(
            s2.get(Some("demo/a")).is_none(),
            "a second storage from the same volume is an independent instance"
        );
    }
}
