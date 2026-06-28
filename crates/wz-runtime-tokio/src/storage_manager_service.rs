// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y62 — the storage MANAGER driver (§5.24): the AP tokio binding that
//! hosts N LIVE [`StorageService`]s over a volume registry, driven by
//! [`StorageConfig`]s.
//!
//! The kernel [`wz_session_core::storage_manager::StorageManager`] (R311y57) is
//! the SYNC, runtime-agnostic registry: it resolves a config's `volume_id` to a
//! [`Volume`](wz_session_core::storage_volume::Volume), creates a backend, and
//! holds the bare [`StorageBackend`] by name. It has no Session — it cannot
//! capture Put/Delete samples or answer queries. [`RuntimeStorageManager`] here
//! is its LIVE counterpart: per [`StorageConfig`] it resolves+creates the
//! backend via a shared
//! [`VolumeRegistry`](wz_session_core::storage_manager::VolumeRegistry::create_backend),
//! then declares a live [`StorageService`] on a [`Session`] (a capture
//! subscriber + a queryable, with the config's `strip_prefix` / `complete`
//! applied) and holds it by name. Dropping the manager undeclares every hosted
//! storage (each [`StorageService`]'s RAII `Drop`).
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh's `StorageRuntimeInner` (the `storages` map +
//! `spawn_storage`, `plugins/zenoh-plugin-storage-manager/src/lib.rs:100,263`):
//! `spawn_storage` resolves the volume then `create_and_start_storage` spawns
//! the async StorageService task and the runtime holds a stopper handle. wz's
//! [`RuntimeStorageManager::add_storage`] is the same shape — resolve (via the
//! shared [`VolumeRegistry`]) then declare a live [`StorageService`] — but the
//! service is its own RAII lifetime owner (no separate stopper / task handle),
//! and wz keys storages FLATLY by name (zenoh's outer `volume->name` double-map
//! is for plugin grouping; storage names are unique per manager).
//!
//! ## Why a shared volume registry
//!
//! [`RuntimeStorageManager`] holds a [`VolumeRegistry`] directly — the SAME
//! registry the kernel [`StorageManager`] composes — for volume registration,
//! `volume_id` resolution, and the resolve+create step
//! ([`register_volume`](RuntimeStorageManager::register_volume) +
//! [`VolumeRegistry::create_backend`](wz_session_core::storage_manager::VolumeRegistry::create_backend)),
//! so the registry and its
//! [`VolumeNotFound`](wz_session_core::storage_manager::VolumeRegistryError::VolumeNotFound)
//! /
//! [`VolumeCreate`](wz_session_core::storage_manager::VolumeRegistryError::VolumeCreate)
//! errors are a single source of truth shared by both managers (no duplicated
//! registry). There is no embedded kernel [`StorageManager`] and so no dead
//! `storages` map: the kernel manager's hold-the-backend
//! [`add_storage`](wz_session_core::storage_manager::StorageManager::add_storage)
//! is the no_std / MCU sync hosting path; here the LIVE services hold their
//! backends instead.

use std::collections::BTreeMap;

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::storage_backend::StorageBackend;
use wz_session_core::storage_config::StorageConfig;
use wz_session_core::storage_manager::{VolumeRegistry, VolumeRegistryError};
use wz_session_core::storage_volume::Volume;

use crate::session::{Session, Unicast};
use crate::session_glue::SessionLinkActions;
use crate::storage_service::{StorageService, StorageServiceError};

/// A storage hosted by [`RuntimeStorageManager`]: a live [`StorageService`]
/// over a volume-created backend. The backend is `Box<dyn StorageBackend +
/// Send>` (the [`Volume::create_storage`](wz_session_core::storage_volume::Volume::create_storage)
/// output) so one manager hosts heterogeneous backends behind one type.
type HostedStorage<R, T> = StorageService<R, T, Box<dyn StorageBackend + Send>>;

/// Why [`RuntimeStorageManager::add_storage`] failed.
#[derive(Debug)]
pub enum RuntimeStorageManagerError {
    /// A storage with this name is already hosted (names are unique per
    /// manager) — the live-service counterpart of the kernel manager's
    /// [`DuplicateStorage`](wz_session_core::storage_manager::StorageManagerError::DuplicateStorage).
    DuplicateStorage(String),
    /// The shared [`VolumeRegistry`] could not resolve the volume or create the
    /// backend (the propagated
    /// [`VolumeRegistryError`](wz_session_core::storage_manager::VolumeRegistryError):
    /// `VolumeNotFound` / `VolumeCreate`). Nothing is hosted.
    Volume(VolumeRegistryError),
    /// The live [`StorageService`] declaration was rejected (a bad keyexpr, a
    /// disabled queryable, an empty `local_zid`, …). Nothing is hosted.
    Service(StorageServiceError),
}

impl core::fmt::Display for RuntimeStorageManagerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RuntimeStorageManagerError::DuplicateStorage(n) => {
                write!(f, "a storage named '{n}' is already hosted")
            }
            RuntimeStorageManagerError::Volume(e) => write!(f, "{e}"),
            // StorageServiceError is Debug-only (it wraps Subscribe / Queryable
            // declaration errors), so render it via Debug.
            RuntimeStorageManagerError::Service(e) => {
                write!(f, "storage service declaration failed: {e:?}")
            }
        }
    }
}

/// Hosts N live [`StorageService`]s over a volume registry — the AP runtime
/// counterpart of the sync kernel [`StorageManager`]. Empty by default;
/// register volumes, then add storages from their [`StorageConfig`]s.
pub struct RuntimeStorageManager<R: SessionRuntime, T: TimeSource> {
    /// The shared volume registry — registration + the resolve/create step. No
    /// dead host map (see the module note).
    registry: VolumeRegistry,
    /// The live services, keyed by storage name (sorted, BTreeMap order).
    services: BTreeMap<String, HostedStorage<R, T>>,
}

impl<R: SessionRuntime, T: TimeSource> RuntimeStorageManager<R, T> {
    /// An empty manager — no volumes, no storages.
    pub fn new() -> Self {
        Self {
            registry: VolumeRegistry::new(),
            services: BTreeMap::new(),
        }
    }

    /// Register `volume` under `volume_id` so a [`StorageConfig`] naming it can
    /// be hosted. Re-registering an id replaces the prior volume for FUTURE
    /// [`add_storage`](Self::add_storage) calls (delegates to the shared
    /// [`VolumeRegistry`]).
    pub fn register_volume(&mut self, volume_id: impl Into<String>, volume: Box<dyn Volume>) {
        self.registry.register_volume(volume_id, volume);
    }

    /// The live storage named `name`, if any — the inspection / query handle
    /// (e.g. [`StorageService::with_state`]).
    pub fn storage(&self, name: &str) -> Option<&HostedStorage<R, T>> {
        self.services.get(name)
    }

    /// The names of the hosted storages, sorted (BTreeMap order).
    pub fn storage_names(&self) -> impl Iterator<Item = &str> {
        self.services.keys().map(|k| k.as_str())
    }

    /// The number of hosted storages.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Whether no storage is hosted.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Remove and tear down the live storage named `name`, returning whether
    /// one was hosted. Dropping the held [`StorageService`] undeclares its
    /// capture subscriber + queryable (RAII) — the live-service analogue of
    /// zenoh's `StorageMessage::Stop` (`kill_storage`,
    /// `plugin-storage-manager/src/lib.rs:248`). After removal the name is free
    /// to re-add; the add-it counterpart is [`add_storage`](Self::add_storage).
    pub fn remove_storage(&mut self, name: &str) -> bool {
        self.services.remove(name).is_some()
    }
}

impl<R: SessionRuntime, T: TimeSource> Default for RuntimeStorageManager<R, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R, T> RuntimeStorageManager<R, T>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    /// Host a new live storage from `config` on `session`: resolve
    /// `config.volume_id` to a registered volume + create its backend (via the
    /// shared [`VolumeRegistry`]), then declare a live [`StorageService`] (capture
    /// subscriber + queryable, with the config's `key_expr` / `complete` /
    /// `strip_prefix` applied) and hold it by `config.name`. The live-service
    /// shape of zenoh `spawn_storage`. Errors — and hosts nothing — if the name
    /// is already hosted
    /// ([`DuplicateStorage`](RuntimeStorageManagerError::DuplicateStorage)), the
    /// volume is unresolved / fails
    /// ([`Volume`](RuntimeStorageManagerError::Volume)), or the service
    /// declaration is rejected ([`Service`](RuntimeStorageManagerError::Service)).
    /// `local_zid` is the storage's fallback-stamp identity (must be non-empty).
    pub fn add_storage(
        &mut self,
        session: &Session<R, T, Unicast>,
        config: &StorageConfig,
        local_zid: Vec<u8>,
    ) -> Result<(), RuntimeStorageManagerError> {
        if self.services.contains_key(&config.name) {
            return Err(RuntimeStorageManagerError::DuplicateStorage(
                config.name.clone(),
            ));
        }
        // Resolve + create via the shared volume registry (the SSOT); the
        // backend is NOT held there — the live service owns it.
        let backend = self
            .registry
            .create_backend(config)
            .map_err(RuntimeStorageManagerError::Volume)?;
        let service = StorageService::declare_with_backend(session, config, local_zid, backend)
            .map_err(RuntimeStorageManagerError::Service)?;
        self.services.insert(config.name.clone(), service);
        Ok(())
    }
}

#[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;
    use wz_session_core::storage_volume::MemoryVolume;

    // The `_driver` Arc is kept alive inside the actions (which hold their own
    // clone), so the session is self-sufficient once built — these tests do not
    // assert on emitted frames. R/T are pinned to TokioSession's TokioRuntime /
    // TokioTime; the manager's type is inferred from `add_storage(&session, ..)`.
    fn make_session() -> TokioSession {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        TokioSession::new(actions, observer, clock)
    }

    #[test]
    fn add_storage_unknown_volume_errs_and_hosts_nothing() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));

        let r = mgr.add_storage(
            &session,
            &StorageConfig::new("s1", "demo/**", "nope"),
            vec![0x01],
        );
        assert!(matches!(
            r,
            Err(RuntimeStorageManagerError::Volume(
                VolumeRegistryError::VolumeNotFound(_)
            ))
        ));
        assert!(
            mgr.storage("s1").is_none(),
            "nothing hosted on volume error"
        );
        assert!(mgr.is_empty());
    }

    #[test]
    fn add_storage_duplicate_name_errs() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));

        mgr.add_storage(
            &session,
            &StorageConfig::new("s1", "a/**", "mem"),
            vec![0x01],
        )
        .expect("first add hosts the storage");
        let r = mgr.add_storage(
            &session,
            &StorageConfig::new("s1", "b/**", "mem"),
            vec![0x01],
        );
        assert!(matches!(
            r,
            Err(RuntimeStorageManagerError::DuplicateStorage(n)) if n == "s1"
        ));
        assert_eq!(mgr.len(), 1, "the duplicate did not replace the original");
    }

    #[test]
    fn remove_storage_undeclares_and_frees_the_name() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));

        mgr.add_storage(
            &session,
            &StorageConfig::new("s1", "a/**", "mem"),
            vec![0x01],
        )
        .expect("first add hosts the storage");
        assert_eq!(mgr.len(), 1);

        assert!(mgr.remove_storage("s1"), "a hosted storage is removed");
        assert!(mgr.storage("s1").is_none(), "gone after remove");
        assert!(mgr.is_empty());
        assert!(
            !mgr.remove_storage("s1"),
            "an absent storage removes to false"
        );

        // The name is freed: re-adding it no longer hits DuplicateStorage.
        mgr.add_storage(
            &session,
            &StorageConfig::new("s1", "b/**", "mem"),
            vec![0x01],
        )
        .expect("the name is free to re-add after removal");
        assert_eq!(mgr.len(), 1);
    }

    // The COMPOSITION proof through the manager: it hosts N live
    // strip-configured storages, each isolated by its keyexpr, each applying
    // strip on the live capture + restore on a query — driven entirely by the
    // per-storage StorageConfig.
    #[cfg(feature = "storage-mgr-strip-prefix")]
    #[test]
    fn manager_hosts_two_strip_configured_storages_each_isolated() {
        use crate::session::PublishOptions;
        use wz_session_core::locality::Locality;

        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));

        let mut kitchen = StorageConfig::new("kitchen", "home/kitchen/**", "mem");
        kitchen.strip_prefix = Some("home/kitchen".into());
        let mut bath = StorageConfig::new("bath", "home/bath/**", "mem");
        bath.strip_prefix = Some("home/bath".into());

        mgr.add_storage(&session, &kitchen, vec![0x01])
            .expect("kitchen storage hosts");
        mgr.add_storage(&session, &bath, vec![0x02])
            .expect("bath storage hosts");
        assert_eq!(
            mgr.storage_names().collect::<Vec<_>>(),
            vec!["bath", "kitchen"]
        );

        // A loopback publish under the kitchen mount fires ONLY the kitchen
        // capture subscriber (bath's keyexpr does not match).
        let fired = session
            .publish(
                "home/kitchen/temp",
                b"k",
                PublishOptions::put().with_locality(Locality::SessionLocal),
            )
            .expect("loopback publish");
        assert_eq!(fired, 1, "only the kitchen storage captured the put");

        mgr.storage("kitchen").unwrap().with_state(|st| {
            // Captured under the RELATIVE (stripped) key.
            assert_eq!(
                st.get(Some("temp")).map(|d| d.payload.clone()),
                Some(b"k".to_vec()),
                "kitchen stored the key relative to its mount"
            );
            // A query restores the full keyexpr.
            let hits = st.matching_entries("home/kitchen/*");
            assert_eq!(hits.len(), 1);
            assert_eq!(
                hits[0].0, "home/kitchen/temp",
                "the query restores the mount prefix"
            );
        });

        // The bath storage is independent — it captured nothing.
        mgr.storage("bath").unwrap().with_state(|st| {
            assert!(
                st.get(Some("temp")).is_none(),
                "bath did not capture the kitchen put (keyexpr isolation)"
            );
        });
    }
}
