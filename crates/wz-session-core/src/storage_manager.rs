// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.24 storage MANAGER — hosting N named storages over a registry of named
//! volumes. The wz mirror of zenoh's plugin-storage-manager (the `storages` map +
//! `spawn_storage`, `plugins/zenoh-plugin-storage-manager/src/lib.rs:100,263): a
//! [`StorageManager`] holds named [`Volume`](crate::storage_volume::Volume)s and,
//! per a [`StorageConfig`], resolves the config's `volume_id` to a volume, has it
//! `create_storage` the backend, and holds the result by storage name for lookup.
//!
//! SYNC + runtime-agnostic KERNEL: this is the volume->storage hosting registry,
//! no async. zenoh runs one async StorageService task per storage (the capture +
//! query-answer loop); that DRIVER is the wz-runtime-tokio §5.11 storage service,
//! a SEPARATE concern that would wrap a manager-hosted backend. wz keys storages
//! FLATLY by name (zenoh's outer-keyed `volume->name` double-map is for plugin
//! grouping; storage names are unique within a manager, so a flat `name->storage`
//! map is the simpler faithful shape).

use crate::storage_backend::StorageBackend;
use crate::storage_config::StorageConfig;
use crate::storage_volume::{Volume, VolumeError};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;

/// Why [`VolumeRegistry::create_backend`] could not resolve a config to a
/// backend — the resolve+create error of the shared volume registry. The
/// [`StorageManager`] maps this onto its flat [`StorageManagerError`]; the
/// runtime manager wraps it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeRegistryError {
    /// The config's `volume_id` is not a registered volume — zenoh's "Cannot find
    /// volume '{}' to spawn storage '{}'" (`storage-manager/lib.rs:268`).
    VolumeNotFound(String),
    /// The resolved volume failed to create the storage — the propagated
    /// [`VolumeError`] (zenoh's `spawn_storage` propagates the backend's create
    /// error). No backend is produced.
    VolumeCreate(VolumeError),
}

impl core::fmt::Display for VolumeRegistryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VolumeRegistryError::VolumeNotFound(v) => {
                write!(f, "no registered volume '{v}' to back the storage")
            }
            VolumeRegistryError::VolumeCreate(e) => write!(f, "{e}"),
        }
    }
}

/// A registry of named [`Volume`]s + the resolve+create step — the single source
/// of truth for `volume_id` resolution shared by BOTH the sync kernel
/// [`StorageManager`] and the wz-runtime-tokio `RuntimeStorageManager`. Mirrors
/// the volume-resolution half of zenoh's `spawn_storage` (resolve the named
/// volume before creating the storage, `plugin-storage-manager/src/lib.rs:263`).
/// Empty by default; register volumes, then create backends from
/// [`StorageConfig`]s.
#[derive(Default)]
pub struct VolumeRegistry {
    volumes: BTreeMap<String, Box<dyn Volume>>,
}

impl VolumeRegistry {
    /// An empty registry — no volumes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `volume` under `volume_id` so a [`StorageConfig`] naming it can be
    /// resolved. Re-registering an id replaces the prior volume — it backs only
    /// FUTURE [`create_backend`](Self::create_backend) calls; backends already
    /// created keep their original volume.
    pub fn register_volume(&mut self, volume_id: impl Into<String>, volume: Box<dyn Volume>) {
        self.volumes.insert(volume_id.into(), volume);
    }

    /// Resolve `config.volume_id` to a registered volume and have it create a
    /// backend — the resolve+create SSOT. The wz mirror of zenoh resolving the
    /// volume before spawning the storage task (`spawn_storage`, lib.rs:263).
    /// Errors if the volume is unregistered
    /// ([`VolumeNotFound`](VolumeRegistryError::VolumeNotFound)) or the volume
    /// fails to create the backend
    /// ([`VolumeCreate`](VolumeRegistryError::VolumeCreate)).
    pub fn create_backend(
        &self,
        config: &StorageConfig,
    ) -> Result<Box<dyn StorageBackend + Send>, VolumeRegistryError> {
        let volume = self
            .volumes
            .get(&config.volume_id)
            .ok_or_else(|| VolumeRegistryError::VolumeNotFound(config.volume_id.clone()))?;
        volume
            .create_storage(config)
            .map_err(VolumeRegistryError::VolumeCreate)
    }

    /// R311y828 — every registered volume as `(id, volume)`, id-sorted (the
    /// backing `BTreeMap`). The enumeration the admin
    /// `status/plugins/storage_manager/volumes/**` legs render from, the wz
    /// counterpart of upstream walking its own `plugins_manager
    /// .started_plugins_iter()` for the same sub-tree
    /// (`zenoh-plugin-storage-manager/src/lib.rs:353-368`).
    ///
    /// Sorted rather than insertion-ordered for the reason the plugin registry is:
    /// a reply SEQUENCE that varies per process is the kind of thing a foreign
    /// client's transcript assertion breaks on, and it would break only sometimes.
    pub fn volumes(&self) -> impl Iterator<Item = (&str, &dyn Volume)> {
        self.volumes.iter().map(|(id, v)| (id.as_str(), &**v))
    }
}

/// Why [`StorageManager::add_storage`] rejected a config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageManagerError {
    /// The config's `volume_id` is not a registered volume — zenoh's "Cannot find
    /// volume '{}' to spawn storage '{}'" (`storage-manager/lib.rs:268`).
    VolumeNotFound(String),
    /// A storage with this name is already hosted (names are unique per manager).
    DuplicateStorage(String),
    /// The resolved volume failed to create the storage — the propagated
    /// [`VolumeError`] (zenoh's `spawn_storage` propagates the backend's create
    /// error). The storage is not hosted.
    VolumeCreate(VolumeError),
}

impl core::fmt::Display for StorageManagerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageManagerError::VolumeNotFound(v) => {
                write!(f, "no registered volume '{v}' to back the storage")
            }
            StorageManagerError::DuplicateStorage(n) => {
                write!(f, "a storage named '{n}' is already hosted")
            }
            StorageManagerError::VolumeCreate(e) => write!(f, "{e}"),
        }
    }
}

/// Hosts N named storages over a [`VolumeRegistry`] — zenoh's storage manager
/// (the `storages` map + `spawn_storage`, `lib.rs:100,263`), the sync
/// runtime-agnostic kernel half (the async per-storage service is the runtime
/// driver). Composes the shared registry for `volume_id` resolution; holds the
/// created backends by name. Empty by default; register volumes, then add
/// storages.
#[derive(Default)]
pub struct StorageManager {
    registry: VolumeRegistry,
    storages: BTreeMap<String, Box<dyn StorageBackend>>,
}

impl StorageManager {
    /// An empty manager — no volumes, no storages.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `volume` under `volume_id` so a [`StorageConfig`] naming it can be
    /// hosted. Re-registering an id replaces the prior volume — it backs only
    /// FUTURE [`add_storage`](Self::add_storage) calls; already-created storages
    /// keep their original backend. Delegates to the composed [`VolumeRegistry`].
    pub fn register_volume(&mut self, volume_id: impl Into<String>, volume: Box<dyn Volume>) {
        self.registry.register_volume(volume_id, volume);
    }

    /// Host a new storage from `config`: resolve `config.volume_id` to a registered
    /// volume, have it create the backend, and hold it by `config.name`. The wz
    /// mirror of zenoh `spawn_storage` (resolve volume -> create -> insert,
    /// `lib.rs:263`). Errors if the volume is unregistered
    /// ([`VolumeNotFound`](StorageManagerError::VolumeNotFound)) or the name is
    /// already hosted ([`DuplicateStorage`](StorageManagerError::DuplicateStorage));
    /// in either case nothing is inserted. The resolve+create step is the shared
    /// [`VolumeRegistry::create_backend`]; its [`VolumeRegistryError`] is mapped
    /// onto this manager's flat [`StorageManagerError`].
    pub fn add_storage(&mut self, config: &StorageConfig) -> Result<(), StorageManagerError> {
        if self.storages.contains_key(&config.name) {
            return Err(StorageManagerError::DuplicateStorage(config.name.clone()));
        }
        let backend = self.registry.create_backend(config).map_err(|e| match e {
            VolumeRegistryError::VolumeNotFound(s) => StorageManagerError::VolumeNotFound(s),
            VolumeRegistryError::VolumeCreate(v) => StorageManagerError::VolumeCreate(v),
        })?;
        self.storages.insert(config.name.clone(), backend);
        Ok(())
    }

    /// Remove and tear down the hosted storage named `name`, returning whether
    /// one was present. The bare backend is dropped (an in-memory store has no
    /// persistence, so its data is gone), and `name` is freed to re-add. The
    /// add-it counterpart is [`add_storage`](Self::add_storage); zenoh tears a
    /// storage down on reconfigure via `StorageMessage::Stop` (`kill_storage`,
    /// `plugin-storage-manager/src/lib.rs:248`).
    pub fn remove_storage(&mut self, name: &str) -> bool {
        self.storages.remove(name).is_some()
    }

    /// The hosted storage named `name`, if any (shared — the query/read path).
    pub fn storage(&self, name: &str) -> Option<&dyn StorageBackend> {
        self.storages.get(name).map(|b| b.as_ref())
    }

    /// The hosted storage named `name`, mutable (the put/delete path). Spelled as
    /// a `match` rather than `.map(|b| b.as_mut())` (the shape `storage` uses):
    /// the `&mut` reborrow through the closure trips closure-lifetime inference,
    /// so the explicit match is required, not a stylistic asymmetry.
    pub fn storage_mut(&mut self, name: &str) -> Option<&mut dyn StorageBackend> {
        match self.storages.get_mut(name) {
            Some(b) => Some(b.as_mut()),
            None => None,
        }
    }

    /// The names of the hosted storages, sorted (BTreeMap order).
    pub fn storage_names(&self) -> impl Iterator<Item = &str> {
        self.storages.keys().map(|k| k.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::TimestampHint;
    use crate::storage_backend::StorageInsertionResult;
    use crate::storage_volume::MemoryVolume;
    use alloc::vec;
    use alloc::vec::Vec;

    fn ts(time: u64) -> TimestampHint {
        TimestampHint {
            time,
            zid: vec![0x01],
        }
    }

    fn mgr_with_mem() -> StorageManager {
        let mut m = StorageManager::new();
        m.register_volume("mem", Box::new(MemoryVolume));
        m
    }

    fn registry_with_mem() -> VolumeRegistry {
        let mut r = VolumeRegistry::new();
        r.register_volume("mem", Box::new(MemoryVolume));
        r
    }

    // A volume whose create_storage always fails — exercises the VolumeCreate
    // error seam (the in-memory volume never fails, so without this the fallible
    // path would be untested).
    struct FailingVolume;
    impl Volume for FailingVolume {
        fn capability(&self) -> crate::storage_volume::Capability {
            crate::storage_volume::Capability {
                persistence: crate::storage_volume::Persistence::Volatile,
                history: crate::storage_backend::History::Latest,
            }
        }
        fn create_storage(
            &self,
            _config: &StorageConfig,
        ) -> Result<Box<dyn StorageBackend + Send>, VolumeError> {
            Err(VolumeError::CreateFailed(alloc::string::String::from(
                "test backend open failed",
            )))
        }
    }

    #[test]
    fn add_storage_propagates_a_volume_create_failure() {
        let mut m = StorageManager::new();
        m.register_volume("failing", Box::new(FailingVolume));
        let r = m.add_storage(&StorageConfig::new("s1", "a/**", "failing"));
        assert!(matches!(
            r,
            Err(StorageManagerError::VolumeCreate(
                VolumeError::CreateFailed(_)
            ))
        ));
        assert!(
            m.storage("s1").is_none(),
            "nothing hosted on create failure"
        );
    }

    #[test]
    fn add_storage_creates_a_working_named_storage() {
        // spawn_storage: resolve the volume -> create -> host by name; the hosted
        // backend is usable (put -> Inserted, get round-trip).
        let mut m = mgr_with_mem();
        m.add_storage(&StorageConfig::new("s1", "demo/**", "mem"))
            .unwrap();
        let s = m.storage_mut("s1").expect("s1 hosted");
        assert_eq!(
            s.put(Some("demo/a"), vec![1], None, ts(10)).unwrap(),
            StorageInsertionResult::Inserted
        );
        assert_eq!(
            m.storage("s1")
                .unwrap()
                .get(Some("demo/a"))
                .unwrap()
                .payload,
            vec![1]
        );
    }

    #[test]
    fn add_storage_unknown_volume_errs() {
        // zenoh "Cannot find volume" — an unregistered volume_id is rejected and
        // nothing is hosted.
        let mut m = StorageManager::new();
        assert_eq!(
            m.add_storage(&StorageConfig::new("s1", "demo/**", "nope")),
            Err(StorageManagerError::VolumeNotFound("nope".into()))
        );
        assert!(m.storage("s1").is_none());
    }

    #[test]
    fn create_backend_resolves_a_volume_without_holding() {
        // VolumeRegistry::create_backend resolves the volume + makes a USABLE
        // backend — the resolve+create SSOT. The registry holds no storages
        // (the R311y62 live-service owner / the StorageManager holds the result).
        let r = registry_with_mem();
        let mut backend = r
            .create_backend(&StorageConfig::new("s1", "demo/**", "mem"))
            .expect("the mem volume creates a backend");
        assert_eq!(
            backend.put(Some("demo/a"), vec![1], None, ts(10)).unwrap(),
            StorageInsertionResult::Inserted
        );
    }

    #[test]
    fn create_backend_unknown_volume_errs() {
        let r = VolumeRegistry::new();
        assert_eq!(
            r.create_backend(&StorageConfig::new("s1", "demo/**", "nope"))
                .err(),
            Some(VolumeRegistryError::VolumeNotFound("nope".into()))
        );
    }

    #[test]
    fn add_storage_duplicate_name_errs() {
        let mut m = mgr_with_mem();
        m.add_storage(&StorageConfig::new("s1", "a/**", "mem"))
            .unwrap();
        assert_eq!(
            m.add_storage(&StorageConfig::new("s1", "b/**", "mem")),
            Err(StorageManagerError::DuplicateStorage("s1".into()))
        );
    }

    #[test]
    fn remove_storage_tears_down_and_frees_the_name() {
        let mut m = mgr_with_mem();
        m.add_storage(&StorageConfig::new("s1", "a/**", "mem"))
            .unwrap();
        assert!(m.remove_storage("s1"), "a hosted storage is removed");
        assert!(m.storage("s1").is_none(), "gone after remove");
        assert!(
            !m.remove_storage("s1"),
            "an absent storage removes to false"
        );
        // The name is freed: a re-add with the same name no longer collides.
        m.add_storage(&StorageConfig::new("s1", "b/**", "mem"))
            .expect("the name is free to re-add after removal");
        assert!(m.storage("s1").is_some());
    }

    #[test]
    fn hosted_storages_are_independent_and_listed() {
        let mut m = mgr_with_mem();
        m.add_storage(&StorageConfig::new("s1", "a/**", "mem"))
            .unwrap();
        m.add_storage(&StorageConfig::new("s2", "b/**", "mem"))
            .unwrap();
        m.storage_mut("s1")
            .unwrap()
            .put(Some("a/x"), vec![1], None, ts(1))
            .unwrap();
        // s2 is a separate store from one MemoryVolume: it does not see s1's key.
        assert!(m.storage("s2").unwrap().get(Some("a/x")).is_none());
        let names: Vec<&str> = m.storage_names().collect();
        assert_eq!(names, vec!["s1", "s2"]);
    }
}
