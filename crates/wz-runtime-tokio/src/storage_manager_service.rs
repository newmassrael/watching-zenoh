// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
#[cfg(feature = "adminspace-config-hotreload")]
use wz_session_core::json5::Json5Value;
#[cfg(feature = "adminspace-config-hotreload")]
use wz_session_core::storage_plugin_config::{
    diffs, ConfigDiff, StoragePluginConfig, VolumeDecl, STORAGE_MANAGER_PLUGIN,
};

/// R2787 — the volume a started storage-manager plugin always has, upstream's
/// `MEMORY_BACKEND_NAME` volume: "The "memory" volume is always available",
/// in upstream's own reference config.
#[cfg(feature = "adminspace-config-hotreload")]
const PLUGIN_MEMORY_VOLUME: &str = "memory";

/// A storage hosted by [`RuntimeStorageManager`]: a live [`StorageService`]
/// over a volume-created backend. The backend is `Box<dyn StorageBackend +
/// Send>` (the [`Volume::create_storage`](wz_session_core::storage_volume::Volume::create_storage)
/// output) so one manager hosts heterogeneous backends behind one type.
type HostedStorage<R, T> = StorageService<R, T, Box<dyn StorageBackend + Send>>;

/// R311y496 — one hosted storage: its live service and the [`StorageConfig`] it
/// was declared from.
///
/// The config is held rather than dropped after the declare because a storage
/// OUTLIVES the session its handles are bound to. Re-establishing that binding
/// ([`RuntimeStorageManager::rebind_all`]) needs the same `key_expr` and
/// `complete` the storage was mounted with, and taking them from a caller would
/// make it possible to silently re-mount a storage somewhere else while calling
/// it a rebind.
struct HostedEntry<R: SessionRuntime, T: TimeSource> {
    config: StorageConfig,
    service: HostedStorage<R, T>,
    /// R311y503 — this storage's periodic garbage collector, held for the
    /// storage's lifetime because [`GarbageCollector`] is RAII: dropping the
    /// handle aborts the sweep task, so `remove_storage` tears the collector down
    /// with the service it belongs to. This field IS the production spawn site
    /// the `storage-mgr-garbage-collection` atom was missing — before it, the
    /// collector existed and was unit-tested but nothing in the live storage
    /// lifecycle ever constructed one, so a deployed storage never GC'd its
    /// wildcard registries. zenoh registers its `GarbageCollectionEvent` at the
    /// same point: inside the storage's own start, next to the subscriber and
    /// queryable it declares (`storages_mgt/service.rs:117-137`).
    #[cfg(feature = "storage-mgr-garbage-collection")]
    _gc: crate::storage_gc_service::GarbageCollector,
}

/// R2696 — why a wire `volume-add` could not be turned into a [`Volume`].
///
/// The counterpart of upstream refusing to `declare_dynamic_plugin_by_name` for
/// a backend it cannot find (`plugins/zenoh-plugin-storage-manager/src/lib.rs` @
/// `fn spawn_volume`). wz resolves COMPILED backends instead of `dlopen`ing one,
/// so "not found" here means "not in this build" — which is a different fact and
/// says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeBuildError {
    /// No backend of this name is compiled into this build. It is NOT a claim
    /// that wz has no such backend: `fs` reads this way without
    /// `storage-backend-filesystem`.
    UnknownBackend(String),
    /// The backend was named and asked correctly, and could not be built — the
    /// filesystem volume cannot create or canonicalize its root.
    ///
    /// R2802 replaced `MissingParameter`, whose one producer was `fs` without a
    /// `root`. That refusal rested on "a volume with no root would be rooted
    /// wherever the process stands", and upstream roots it somewhere definite:
    /// `ZENOH_BACKEND_FS_ROOT`, else under the zenoh home. A stock
    /// `volumes: { fs: { backend: "fs" } }` names no root and must build.
    Unavailable {
        /// The backend that was asked for.
        backend: String,
        /// Why it could not be built.
        reason: String,
    },
    /// The client sent parameters this backend does not read. Refused rather
    /// than ignored: a volume silently built from a config it did not honour is
    /// a volume the operator cannot reason about, and `?rooot=/srv` must not
    /// produce a volume rooted somewhere else.
    UnknownParameters {
        /// The backend that was asked for.
        backend: String,
        /// The keys it does not read, in the order the payload sent them.
        keys: Vec<String>,
    },
}

impl core::fmt::Display for VolumeBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VolumeBuildError::UnknownBackend(b) => {
                write!(f, "no storage backend '{b}' is compiled into this build")
            }
            VolumeBuildError::Unavailable { backend, reason } => {
                write!(
                    f,
                    "storage backend '{backend}' could not be built: {reason}"
                )
            }
            VolumeBuildError::UnknownParameters { backend, keys } => {
                write!(
                    f,
                    "storage backend '{backend}' does not read {}",
                    keys.join(", ")
                )
            }
        }
    }
}

/// R2696 — build the volume a wire `volume-add` named, from the COMPILED
/// backends this build carries.
///
/// The wz counterpart of upstream's `spawn_volume`
/// (`plugins/zenoh-plugin-storage-manager/src/lib.rs` @ `fn spawn_volume`),
/// which resolves a backend name to a dynamic plugin and starts it. wz composes
/// its backends, so this resolves a NAME to a constructor and the refusal for an
/// unknown one names the build rather than a missing library.
///
/// The parameter vocabulary is each backend's own, and it is derived from the
/// constructor rather than invented: `fs` takes `root` because
/// [`FilesystemVolume::new`](crate::filesystem_storage::FilesystemVolume::new)
/// takes a `root`. That name is wz's, not mirrored -- upstream's fs volume reads
/// no parameter at all and takes its root from the environment -- so it is
/// OPTIONAL (R2802): without it the volume is rooted exactly where upstream's
/// is (`FilesystemVolume::from_env`, which exists only in a build carrying the
/// backend).
///
/// ⚠ `mem` takes NO parameters and says so rather than ignoring them, for the
/// reason [`UnknownParameters`](VolumeBuildError::UnknownParameters) carries.
///
/// ⚠ The dlopen backend (`storage-mgr-dynamic-volume-loading`) is deliberately
/// not reachable from here — see
/// [`AdminConfigWrite::AddVolume`](wz_session_core::adminspace::AdminConfigWrite::AddVolume),
/// which states why upstream's `paths` field is not carried on the wire.
pub fn build_volume(
    backend: &str,
    volume_cfg: &[(String, String)],
) -> Result<Box<dyn Volume>, VolumeBuildError> {
    /// The keys a backend does not read, preserving the payload's order.
    fn unknown_keys(volume_cfg: &[(String, String)], known: &[&str]) -> Vec<String> {
        volume_cfg
            .iter()
            .map(|(k, _)| k)
            .filter(|k| !known.contains(&k.as_str()))
            .cloned()
            .collect()
    }

    match backend {
        // R2787 — `memory` is upstream's name for the same backend
        // (`plugins/zenoh-plugin-storage-manager/src/lib.rs` @ `const MEMORY_BACKEND_NAME: &str = "memory";`),
        // and a stock document names it: `volumes: { v: { backend: "memory" } }`.
        "mem" | "memory" => {
            let unknown = unknown_keys(volume_cfg, &[]);
            if !unknown.is_empty() {
                return Err(VolumeBuildError::UnknownParameters {
                    backend: String::from(backend),
                    keys: unknown,
                });
            }
            Ok(Box::new(wz_session_core::storage_volume::MemoryVolume))
        }
        #[cfg(feature = "storage-backend-filesystem")]
        "fs" => {
            let unknown = unknown_keys(volume_cfg, &["root"]);
            if !unknown.is_empty() {
                return Err(VolumeBuildError::UnknownParameters {
                    backend: String::from(backend),
                    keys: unknown,
                });
            }
            // R2802 — `root` is wz's, and optional: without it the volume is
            // rooted where upstream's plugin roots it (see `from_env`).
            let Some(root) = volume_cfg
                .iter()
                .find(|(k, _)| k == "root")
                .map(|(_, v)| v.as_str())
            else {
                return crate::filesystem_storage::FilesystemVolume::from_env()
                    .map(|v| Box::new(v) as Box<dyn Volume>)
                    .map_err(|e| VolumeBuildError::Unavailable {
                        backend: String::from(backend),
                        reason: e.to_string(),
                    });
            };
            Ok(Box::new(crate::filesystem_storage::FilesystemVolume::new(
                root,
            )))
        }
        other => Err(VolumeBuildError::UnknownBackend(String::from(other))),
    }
}

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

/// R2787 — why one step of the storage manager's document could not be applied.
///
/// The `Display` texts are upstream's own log lines where it has one
/// ("Cannot spawn volume", "Cannot find volume … to stop it"), because an
/// operator moving a deployment reads the same log for the same failure.
#[cfg(feature = "adminspace-config-hotreload")]
#[derive(Debug)]
pub enum PluginApplyError {
    /// A `DeleteVolume` named a volume this manager does not have.
    UnknownVolume(String),
    /// A declared volume could not be built from this build's backends.
    Volume {
        /// The volume.
        volume: String,
        /// Why.
        error: VolumeBuildError,
    },
    /// A declared volume names libraries (`__path__`) and none could serve it.
    DynamicVolume {
        /// The volume.
        volume: String,
        /// Why.
        reason: String,
    },
    /// A declared storage could not be hosted.
    Storage {
        /// The storage.
        storage: String,
        /// Why.
        error: RuntimeStorageManagerError,
    },
}

#[cfg(feature = "adminspace-config-hotreload")]
impl core::fmt::Display for PluginApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PluginApplyError::UnknownVolume(v) => write!(f, "Cannot find volume '{v}' to stop it"),
            PluginApplyError::Volume { volume, error } => {
                write!(f, "Cannot spawn volume '{volume}': {error}")
            }
            PluginApplyError::DynamicVolume { volume, reason } => {
                write!(f, "Cannot spawn volume '{volume}': {reason}")
            }
            PluginApplyError::Storage { storage, error } => {
                write!(f, "Cannot spawn storage '{storage}': {error}")
            }
        }
    }
}

/// R2787 — build the volume a DOCUMENT declared, the declarative twin of
/// [`build_volume`].
///
/// A volume with no `__path__` is one of this build's backends, named by its
/// `backend` or by its own name (upstream's `VolumeConfig::backend`); its
/// parameters are its `rest` minus `backend`, which names the backend and is no
/// parameter of it. A value that is not a string reaches the backend as its
/// JSON text.
///
/// A volume WITH `__path__` is loaded from the first path that loads, which is
/// upstream's rule for a plugin declared by paths, and is handed its whole
/// `rest` as its configuration, as upstream hands its `VolumeConfig` to the
/// library. A build without dynamic volume loading refuses it by name.
#[cfg(feature = "adminspace-config-hotreload")]
fn build_declared_volume(volume: &VolumeDecl) -> Result<Box<dyn Volume>, PluginApplyError> {
    let Some(paths) = &volume.paths else {
        let params: Vec<(String, String)> = volume
            .rest
            .iter()
            .filter(|(key, _)| key != "backend")
            .map(|(key, value)| {
                let text = match value {
                    Json5Value::String(s) => s.clone(),
                    other => other.to_json5_text(),
                };
                (key.clone(), text)
            })
            .collect();
        return build_volume(volume.backend(), &params).map_err(|error| PluginApplyError::Volume {
            volume: volume.name.clone(),
            error,
        });
    };
    #[cfg(all(unix, feature = "storage-mgr-dynamic-volume-loading"))]
    {
        let config = (!volume.rest.is_empty())
            .then(|| Json5Value::Object(volume.rest.clone()).to_json5_text());
        let mut failures = Vec::with_capacity(paths.len());
        for path in paths {
            match crate::dynamic_volume::DynamicVolume::load(path) {
                Ok(loaded) => {
                    return match loaded.configure(config.as_deref()) {
                        Ok(()) => Ok(Box::new(loaded)),
                        Err(e) => Err(PluginApplyError::DynamicVolume {
                            volume: volume.name.clone(),
                            reason: format!("{path} refused its configuration: {e}"),
                        }),
                    };
                }
                Err(e) => failures.push(format!("{path}: {e}")),
            }
        }
        Err(PluginApplyError::DynamicVolume {
            volume: volume.name.clone(),
            reason: if failures.is_empty() {
                String::from("`__path__` names no library")
            } else {
                failures.join("; ")
            },
        })
    }
    #[cfg(not(all(unix, feature = "storage-mgr-dynamic-volume-loading")))]
    {
        let _ = paths;
        Err(PluginApplyError::DynamicVolume {
            volume: volume.name.clone(),
            reason: String::from(
                "this build loads no volume from a library path (it lacks \
                 `storage-mgr-dynamic-volume-loading`)",
            ),
        })
    }
}

/// Hosts N live [`StorageService`]s over a volume registry — the AP runtime
/// counterpart of the sync kernel [`StorageManager`]. Empty by default;
/// register volumes, then add storages from their [`StorageConfig`]s.
pub struct RuntimeStorageManager<R: SessionRuntime, T: TimeSource> {
    /// The shared volume registry — registration + the resolve/create step. No
    /// dead host map (see the module note).
    registry: VolumeRegistry,
    /// The live services and their configs, keyed by storage name (sorted,
    /// BTreeMap order).
    services: BTreeMap<String, HostedEntry<R, T>>,
    /// R2787 — the document the storage-manager PLUGIN is running with, or
    /// `None` when it is not running. Upstream's plugin is a thing that is
    /// started and stopped as its `plugins/storage_manager` document appears
    /// and goes; this is that state, held here because this is the manager it
    /// drives. The storages and volumes a client adds through the intent verbs
    /// are not the plugin's and are not recorded in it.
    #[cfg(feature = "adminspace-config-hotreload")]
    plugin: Option<StoragePluginConfig>,
}

impl<R: SessionRuntime, T: TimeSource> RuntimeStorageManager<R, T> {
    /// An empty manager — no volumes, no storages.
    pub fn new() -> Self {
        Self {
            registry: VolumeRegistry::new(),
            services: BTreeMap::new(),
            #[cfg(feature = "adminspace-config-hotreload")]
            plugin: None,
        }
    }

    /// R2787 — whether the storage-manager plugin is running.
    #[cfg(feature = "adminspace-config-hotreload")]
    pub fn plugin_running(&self) -> bool {
        self.plugin.is_some()
    }

    /// R2787 — stop the storage-manager plugin: every storage and volume its
    /// document declared, then the `memory` volume its start registered. A
    /// plugin that is not running is left alone.
    ///
    /// Upstream stops a plugin by dropping it, and with it everything it
    /// spawned; this is the same set, named, because here the plugin shares its
    /// manager with the intent verbs and must not take their storages with it.
    #[cfg(feature = "adminspace-config-hotreload")]
    pub fn stop_plugin(&mut self) {
        let Some(config) = self.plugin.take() else {
            return;
        };
        for storage in &config.storages {
            self.remove_storage(&storage.name);
        }
        for volume in &config.volumes {
            self.remove_volume(&volume.name);
        }
        self.remove_volume(PLUGIN_MEMORY_VOLUME);
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
        self.services.get(name).map(|e| &e.service)
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

    /// R2696 — unregister the volume named `volume_id` AND tear down every live
    /// storage hosted on it, returning those storages' names in hosted order, or
    /// `None` when no such volume was registered.
    ///
    /// The wz counterpart of upstream's `kill_volume`
    /// (`plugins/zenoh-plugin-storage-manager/src/lib.rs` @ `fn kill_volume`),
    /// and the CASCADE is the whole of it: upstream stops every storage in the
    /// volume's own `storages` map before stopping the volume, because a storage
    /// outliving its volume answers queries out of a backend nothing can
    /// re-create. wz holds no volume-keyed storage map — the ownership is
    /// recorded the other way round, in each hosted
    /// [`StorageConfig::volume_id`](wz_session_core::storage_config::StorageConfig)
    /// — so the set is derived here rather than looked up, which is also why this
    /// cannot live on [`VolumeRegistry`]: the registry holds volumes and cannot
    /// see who resolved through it. This is the one layer holding both maps.
    /// (The target is left implicit because the type is already in scope here;
    /// spelling it out is what rustdoc calls a redundant explicit link target,
    /// and Layer C1bz counts one of those exactly as it counts an unresolved
    /// link.)
    ///
    /// An unknown name is refused with no side effect: the hosted set is
    /// computed without mutating, the volume is removed, and the storages go
    /// last. A refusal that has already destroyed live state is not a refusal.
    ///
    /// ⚠ THAT ORDERING IS DEFENSIVE, NOT AN OBSERVABLE DIVERGENCE, and the
    /// distinction was MEASURED rather than assumed — an earlier draft of this
    /// comment claimed the stronger thing and a control proved it empty. The
    /// hosted set is DERIVED from the volume id, so for a volume that is not
    /// registered it is always empty and the two orderings cannot be told apart.
    /// Upstream is the same shape for the same reason (`self.storages.remove(name)`
    /// on an unknown name yields nothing before its `ok_or` refuses), so the
    /// difference in statement order between the two functions has no consequence
    /// either way. What IS observable, and what the witness holds, is that a
    /// refusal is distinguishable from a successful removal of nothing.
    ///
    /// Dropping each [`StorageService`] undeclares its capture subscriber and
    /// queryable (RAII), exactly as [`remove_storage`](Self::remove_storage)
    /// documents — this is that operation over a derived set, not a second
    /// teardown path.
    pub fn remove_volume(&mut self, volume_id: &str) -> Option<Vec<String>> {
        let hosted: Vec<String> = self
            .services
            .iter()
            .filter(|(_, entry)| entry.config.volume_id == volume_id)
            .map(|(name, _)| name.clone())
            .collect();
        if !self.registry.remove_volume(volume_id) {
            return None;
        }
        for name in &hosted {
            self.services.remove(name);
        }
        Some(hosted)
    }

    /// R311y828 — this manager's live state as the admin sub-tree below
    /// `@/<zid>/<whatami>/status/plugins/storage_manager`, the wz analogue of
    /// `StoragesPlugin`'s `adminspace_getter`
    /// (`zenoh-plugin-storage-manager/src/lib.rs:336-389`). Feed the result to
    /// [`AdminPlugin::with_status_leaves`](wz_session_core::adminspace::AdminPlugin::with_status_leaves)
    /// on the `storage_manager` record the admin handler builds, and the answerer
    /// serves it.
    ///
    /// The leaves, in upstream's own emission order:
    ///
    /// - `version` — `PLUGIN_VERSION` upstream (`:344-351`); the node build
    ///   version here, since a statically composed subsystem has no version of its
    ///   own to be at.
    /// - `volumes/<id>/__path__` and `volumes/<id>` — one pair per REGISTERED
    ///   volume (`:353-368`). Registered, not merely used: upstream walks its
    ///   volume plugin manager, so a volume that currently backs no storage still
    ///   appears, and an operator can tell "no such volume" from "that volume has
    ///   no storages".
    /// - `storages/<name>` — one per HOSTED storage (`:370-388`), body the
    ///   storage's config, which is what upstream's `GetStatus` round-trip
    ///   ultimately answers with. wz reads it straight off the retained
    ///   `StorageConfig` instead of messaging the storage task: the config is
    ///   immutable for the storage's lifetime, so the message would be a slower
    ///   route to the same bytes — and upstream needs it only because its config
    ///   lives inside the task.
    ///
    /// Taking a snapshot is what lets an admin handler that cannot borrow the
    /// manager (`Send + 'static`) still report it; the caller refreshes the
    /// snapshot wherever it already reflects a storage add/remove, so the
    /// freshness contract is the one it already keeps for the `Started` bit.
    #[cfg(feature = "adminspace-plugins-handlers")]
    pub fn admin_status_leaves(
        &self,
        version: &str,
    ) -> Vec<wz_session_core::adminspace::AdminPluginStatusLeaf> {
        use wz_session_core::adminspace::{AdminPluginStatusLeaf, WZ_STATIC_PLUGIN_PATH};

        let mut leaves = Vec::new();
        let mut version_json = String::new();
        wz_session_core::json::escape_into(version, &mut version_json);
        leaves.push(AdminPluginStatusLeaf::new("version", version_json));
        for (id, volume) in self.registry.volumes() {
            let path = volume
                .admin_path()
                .unwrap_or_else(|| String::from(WZ_STATIC_PLUGIN_PATH));
            let mut path_json = String::new();
            wz_session_core::json::escape_into(&path, &mut path_json);
            leaves.push(AdminPluginStatusLeaf::new(
                format!("volumes/{id}/__path__"),
                path_json,
            ));
            // R2804 — the volume's OWN body: the capability by default, and
            // what upstream's counterpart reports where the volume carries it
            // (`Volume::admin_status`).
            leaves.push(AdminPluginStatusLeaf::new(
                format!("volumes/{id}"),
                volume.admin_status(version),
            ));
        }
        for (name, entry) in &self.services {
            leaves.push(AdminPluginStatusLeaf::new(
                format!("storages/{name}"),
                entry.config.to_admin_json(),
            ));
        }
        leaves
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
    /// R311y503 — the extra bounds sit on the METHOD, not on the impl block, so
    /// only the path that now spawns a task carries them: the collector is a
    /// `tokio::spawn`, which needs the session's runtime and clock to be `Send`
    /// and `'static`. Every production caller (the `TokioSession` storage host)
    /// already satisfies them.
    pub fn add_storage(
        &mut self,
        session: &Session<R, T, Unicast>,
        config: &StorageConfig,
        local_zid: Vec<u8>,
    ) -> Result<(), RuntimeStorageManagerError>
    where
        R: 'static,
        T: Send + Sync,
        Session<R, T, Unicast>: Clone + Send + 'static,
    {
        if self.services.contains_key(&config.name) {
            return Err(RuntimeStorageManagerError::DuplicateStorage(
                config.name.clone(),
            ));
        }
        // Resolve + create via the shared volume registry (the SSOT); the
        // backend is NOT held there — the live service owns it.
        //
        // R2802 — on a COPY the volume may amend, and it is the amended copy this
        // entry keeps: upstream's storage keeps the config its volume handed
        // back, and that is what its admin status reports (the fs backend's
        // `dir_full_path`).
        let mut config = config.clone();
        let backend = self
            .registry
            .create_backend(&mut config)
            .map_err(RuntimeStorageManagerError::Volume)?;
        let service = StorageService::declare_with_backend(session, &config, local_zid, backend)
            .map_err(RuntimeStorageManagerError::Service)?;
        // The storage's periodic GC, started WITH the storage and torn down with
        // it (the handle lives in the entry). zenoh does this inside the storage's
        // own start; wz's equivalent lifetime owner is this manager, which is what
        // `remove_storage` drops. Spawned AFTER the declaration succeeds, so a
        // rejected storage leaves no orphan task behind.
        #[cfg(feature = "storage-mgr-garbage-collection")]
        let gc = crate::storage_gc_service::GarbageCollector::spawn(
            session,
            service.shared_state(),
            config.garbage_collection.clone(),
            &config.name,
        );
        self.services.insert(
            config.name.clone(),
            HostedEntry {
                config,
                service,
                #[cfg(feature = "storage-mgr-garbage-collection")]
                _gc: gc,
            },
        );
        Ok(())
    }

    /// R311y496 — re-establish every hosted storage's declaration on `session`,
    /// keeping all stored data
    /// ([`StorageService::rebind`](crate::storage_service::StorageService::rebind)).
    ///
    /// A host that serves ONE client session at a time must call this on each
    /// accepted session. A storage is created on whichever session carried the
    /// request that created it, and its capture subscriber and answering
    /// queryable die with that session; without a rebinding, every later client
    /// reaches a storage that is hosted (`len() > 0`, so the admin plane reports
    /// it live) yet captures nothing and answers nothing. That divergence — the
    /// admin plane and the storage plane disagreeing about the same storage — is
    /// what R311y496 measured against a real zenoh-pico before fixing it.
    ///
    /// Applies to every hosted storage or to none: the first failure is
    /// returned, and the storages already rebound in this call keep their new
    /// binding (a partial rebinding is strictly better than none, and the caller
    /// that gets an `Err` is expected to drop the session rather than serve on
    /// it). Hosting nothing is a no-op success.
    pub fn rebind_all(
        &mut self,
        session: &Session<R, T, Unicast>,
        local_zid: Vec<u8>,
    ) -> Result<(), RuntimeStorageManagerError> {
        for entry in self.services.values_mut() {
            entry
                .service
                .rebind(session, &entry.config, local_zid.clone())
                .map_err(RuntimeStorageManagerError::Service)?;
        }
        Ok(())
    }

    /// R2787 — start the storage-manager plugin with `config`, as upstream's
    /// `plugins/zenoh-plugin-storage-manager/src/lib.rs` @ `fn new(runtime: DynamicRuntime, config: PluginConfig) -> ZResult<Self> {`
    /// does: the `memory` volume, then every declared volume, then every
    /// declared storage. A step that fails is RETURNED and the rest still run —
    /// upstream's own words for it are "Failure of loading of one volume or
    /// storage should not affect others" — so the plugin is running afterwards
    /// whatever the list says, exactly as upstream's is.
    ///
    /// ⚠ UPSTREAM ALSO REFUSES TO START WITHOUT `timestamping`, and wz does not:
    /// the refusal exists because a stored sample must carry a timestamp and
    /// upstream's session can only mint one with an HLC. A wz storage stamps an
    /// unstamped sample itself (the `local_zid` it is given here is that
    /// stamp's identity), so the precondition holds by construction.
    #[cfg(feature = "adminspace-config-hotreload")]
    pub fn start_plugin(
        &mut self,
        session: &Session<R, T, Unicast>,
        config: StoragePluginConfig,
        local_zid: &[u8],
    ) -> Vec<PluginApplyError>
    where
        R: 'static,
        T: Send + Sync,
        Session<R, T, Unicast>: Clone + Send + 'static,
    {
        self.register_volume(
            PLUGIN_MEMORY_VOLUME,
            Box::new(wz_session_core::storage_volume::MemoryVolume),
        );
        let mut failures = Vec::new();
        let steps = config
            .volumes
            .iter()
            .cloned()
            .map(ConfigDiff::AddVolume)
            .chain(config.storages.iter().cloned().map(ConfigDiff::AddStorage));
        for step in steps {
            if let Err(e) = self.apply_plugin_step(session, &step, local_zid) {
                failures.push(e);
            }
        }
        self.plugin = Some(config);
        failures
    }

    /// R2787 — move the running plugin from `old` to `new`, as upstream's
    /// `plugins/zenoh-plugin-storage-manager/src/lib.rs` @ `fn update<I: IntoIterator<Item = ConfigDiff>>(&mut self, diffs: I) -> ZResult<()> {`
    /// does: the `diffs` in their order, STOPPING at the first that fails.
    ///
    /// ⚠ WHAT WAS APPLIED BEFORE THE FAILURE STAYS APPLIED, and that is
    /// upstream's shape, not an oversight here: its loop returns at the first
    /// `?`. A rollback would have to re-create a torn-down memory storage WITH
    /// its data, which nothing can, so offering one would be a pretence. The
    /// caller refuses the config write, so the section keeps `old`, and the
    /// next write is diffed against it — which re-attempts what did not land.
    ///
    /// ⚠ A CHANGED VOLUME TAKES ITS STORAGES WITH IT, also upstream's: the
    /// volume's delete is upstream's `kill_volume`, which stops every storage on
    /// it, and a storage whose OWN declaration did not change earns no add in
    /// the diff, so it is not re-created.
    #[cfg(feature = "adminspace-config-hotreload")]
    pub fn update_plugin(
        &mut self,
        session: &Session<R, T, Unicast>,
        old: &StoragePluginConfig,
        new: StoragePluginConfig,
        local_zid: &[u8],
    ) -> Result<(), PluginApplyError>
    where
        R: 'static,
        T: Send + Sync,
        Session<R, T, Unicast>: Clone + Send + 'static,
    {
        for step in diffs(old, &new) {
            self.apply_plugin_step(session, &step, local_zid)?;
        }
        self.plugin = Some(new);
        Ok(())
    }

    /// One step of the plugin's document applied to this manager — upstream's
    /// `update` arms, each on the operation this manager already has.
    #[cfg(feature = "adminspace-config-hotreload")]
    fn apply_plugin_step(
        &mut self,
        session: &Session<R, T, Unicast>,
        step: &ConfigDiff,
        local_zid: &[u8],
    ) -> Result<(), PluginApplyError>
    where
        R: 'static,
        T: Send + Sync,
        Session<R, T, Unicast>: Clone + Send + 'static,
    {
        match step {
            ConfigDiff::DeleteVolume(volume) => self
                .remove_volume(&volume.name)
                .map(|_| ())
                .ok_or_else(|| PluginApplyError::UnknownVolume(volume.name.clone())),
            ConfigDiff::AddVolume(volume) => {
                let built = build_declared_volume(volume)?;
                self.register_volume(volume.name.clone(), built);
                Ok(())
            }
            // Upstream's `kill_storage` stops a storage it finds and says
            // nothing about one it does not.
            ConfigDiff::DeleteStorage(storage) => {
                self.remove_storage(&storage.name);
                Ok(())
            }
            ConfigDiff::AddStorage(storage) => self
                .add_storage(session, &storage.to_storage_config(), local_zid.to_vec())
                .map_err(|error| PluginApplyError::Storage {
                    storage: storage.name.clone(),
                    error,
                }),
        }
    }
}

/// R2787 — the storage manager as a running plugin: the validator and the
/// notification plane a `plugins/storage_manager` write reaches
/// ([`crate::plugins_config::PluginsSink`]).
///
/// Built per write around the manager a host holds, because the manager is
/// task-local (the `Volume` trait carries no `Send`) and a sink only BORROWS
/// it for the one call. What a start could not do is not an error of the write
/// that triggered it — upstream logs it — so it is kept for the host to log
/// ([`Self::take_reports`]).
///
/// * Validator: a plugin other than `storage_manager` is not this host's to
///   check, and a storage manager that is not running has nothing to check —
///   both accept, as upstream accepts for a plugin it has not started. A
///   running one parses the old and the new document and applies the
///   difference; a document it cannot read, or a step it cannot apply,
///   refuses the write.
/// * Notification plane: the document appearing starts the plugin, and its
///   going stops it.
#[cfg(feature = "adminspace-config-hotreload")]
pub struct StorageManagerSink<'a, R: SessionRuntime, T: TimeSource> {
    manager: core::cell::RefCell<&'a mut RuntimeStorageManager<R, T>>,
    session: &'a Session<R, T, Unicast>,
    local_zid: &'a [u8],
    reports: core::cell::RefCell<Vec<String>>,
}

#[cfg(feature = "adminspace-config-hotreload")]
impl<'a, R: SessionRuntime, T: TimeSource> StorageManagerSink<'a, R, T> {
    /// A sink over `manager`, hosting storages on `session` with `local_zid`
    /// as their stamping identity.
    pub fn new(
        manager: &'a mut RuntimeStorageManager<R, T>,
        session: &'a Session<R, T, Unicast>,
        local_zid: &'a [u8],
    ) -> Self {
        Self {
            manager: core::cell::RefCell::new(manager),
            session,
            local_zid,
            reports: core::cell::RefCell::new(Vec::new()),
        }
    }

    /// What happened that the host should log and that refused nothing: a
    /// start's failed steps, or a document a start could not read.
    pub fn take_reports(&self) -> Vec<String> {
        core::mem::take(&mut *self.reports.borrow_mut())
    }
}

#[cfg(feature = "adminspace-config-hotreload")]
impl<R, T> crate::plugins_config::PluginsSink for StorageManagerSink<'_, R, T>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Clone + Send + 'static,
{
    fn check_config(
        &self,
        plugin: &str,
        _path: &str,
        current: &Json5Value,
        new: &Json5Value,
    ) -> Result<Option<Json5Value>, String> {
        if plugin != STORAGE_MANAGER_PLUGIN {
            return Ok(None);
        }
        let mut manager = self.manager.borrow_mut();
        if !manager.plugin_running() {
            return Ok(None);
        }
        let old = StoragePluginConfig::from_json5(plugin, current).map_err(|e| e.to_string())?;
        let new = StoragePluginConfig::from_json5(plugin, new).map_err(|e| e.to_string())?;
        manager
            .update_plugin(self.session, &old, new, self.local_zid)
            .map_err(|e| e.to_string())?;
        Ok(None)
    }

    fn plugins_changed(&self, plugins: &crate::plugins_config::PluginsConfig) {
        let mut manager = self.manager.borrow_mut();
        match (
            plugins.plugin(STORAGE_MANAGER_PLUGIN),
            manager.plugin_running(),
        ) {
            (Some(doc), false) => {
                match StoragePluginConfig::from_json5(STORAGE_MANAGER_PLUGIN, doc) {
                    Ok(config) => {
                        let failures = manager.start_plugin(self.session, config, self.local_zid);
                        self.reports
                            .borrow_mut()
                            .extend(failures.iter().map(ToString::to_string));
                    }
                    Err(e) => self.reports.borrow_mut().push(format!(
                        "Failed to load plugin `{STORAGE_MANAGER_PLUGIN}`: {e}"
                    )),
                }
            }
            (None, true) => manager.stop_plugin(),
            _ => {}
        }
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

    // R311y828 — the admin sub-tree the `adminspace-plugins-handlers` atom's
    // named residual said was unserved. It was NOT vacuous: `storage_manager` is
    // the one subsystem wz claims to mirror, it is exactly the upstream plugin
    // that implements `adminspace_getter`, and this manager owns live volumes and
    // storages the admin plane could not see.
    #[cfg(feature = "adminspace-plugins-handlers")]
    #[tokio::test]
    async fn admin_leaves_report_every_registered_volume_and_hosted_storage() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        // TWO volumes, and only ONE of them ever backs a storage — upstream walks
        // the volume registry, not the storages' volumes, so an operator can tell
        // "no such volume" from "that volume is idle". A one-volume fixture would
        // pass under either rule.
        mgr.register_volume("mem", Box::new(MemoryVolume));
        mgr.register_volume("spare", Box::new(MemoryVolume));

        // Before any storage: the volumes are already visible, and no storage is.
        let idle = mgr.admin_status_leaves("9.9.9");
        let idle_keys: Vec<&str> = idle.iter().map(|l| l.suffix.as_str()).collect();
        assert_eq!(
            idle_keys,
            vec![
                "version",
                "volumes/mem/__path__",
                "volumes/mem",
                "volumes/spare/__path__",
                "volumes/spare",
            ],
            "registered volumes report before any storage exists"
        );

        mgr.add_storage(
            &session,
            &StorageConfig::new("s1", "demo/**", "mem"),
            vec![0x01],
        )
        .expect("storage hosts");

        let live = mgr.admin_status_leaves("9.9.9");
        let by_suffix = |s: &str| -> String {
            let have: Vec<&str> = live.iter().map(|l| l.suffix.as_str()).collect();
            live.iter()
                .find(|l| l.suffix == s)
                .unwrap_or_else(|| panic!("no leaf at {s}; have {have:?}"))
                .json_body
                .clone()
        };
        assert_eq!(
            by_suffix("version"),
            "\"9.9.9\"",
            "the version leaf is a JSON string, not a bare token"
        );
        assert_eq!(
            by_suffix("volumes/mem/__path__"),
            "\"__static__\"",
            "a statically composed volume reports the static marker"
        );
        assert_eq!(
            by_suffix("volumes/mem"),
            r#"{"capability":{"history":"Latest","persistence":"Volatile"}}"#,
            "the in-memory volume's real capability"
        );
        assert_eq!(
            by_suffix("storages/s1"),
            r#"{"key_expr":"demo/**","volume":"mem"}"#,
            "the hosted storage's config, upstream's Storage::get_admin_status body"
        );

        // The DISCRIMINATOR: the sub-tree tracks the manager rather than being a
        // constant. Removing the storage removes exactly its leaf and leaves both
        // volumes in place — a snapshot rendered once at declare time would keep
        // reporting `storages/s1` here.
        assert!(mgr.remove_storage("s1"));
        let torn_down = mgr.admin_status_leaves("9.9.9");
        let after: Vec<&str> = torn_down.iter().map(|l| l.suffix.as_str()).collect();
        assert_eq!(
            after, idle_keys,
            "the storage leaf is gone and nothing else moved"
        );
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

    /// R2743 — THE HOSTED E12 RED, made deterministic.
    ///
    /// Layer E12 fails when a one-shot pico `z_put` has already closed by the
    /// time its `storage-add` is applied: the host reads the write off a socket
    /// whose TX half is gone, and `add_storage`'s queryable declaration then has
    /// no transport. ⚠ THE E2E TEST CANNOT BE THE CONTROL — it is a race this
    /// machine wins, measured: the leg passes locally in 0.29s, and forcing a
    /// 400ms delay between stashing the intent and applying it (which moved the
    /// run to 1.17s, so the probe was live) STILL passed. Delaying the apply is
    /// not the mechanism; the TX half being dead BEFORE the intent arrives is,
    /// which the hosted log shows by ordering `writer_task write failed: Broken
    /// pipe` ahead of `config-write intent stashed`.
    ///
    /// So the control is here, one layer down and deterministic.
    /// `reset_for_reopen` closes the F2 transport-availability gate — the same
    /// gate a released link closes — so the declare rejects
    /// `TransportUnavailable` exactly as it did hosted, with no timing in it.
    ///
    /// WHAT IT PINS: a storage whose declaration cannot reach the wire is still
    /// HOSTED. The data is the `StorageState` over the volume-created backend
    /// and belongs to the storage; the subscriber and queryable are a binding to
    /// one session, which `rebind_all` re-establishes on the next accepted one.
    /// Today `add_storage` conflates the two and registers nothing at all, so a
    /// write that was received is silently lost.
    #[cfg(feature = "session-reconnect")]
    #[tokio::test]
    async fn a_storage_survives_a_declaration_that_cannot_reach_the_wire() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        // F2: the transport-availability gate stays closed until Established is
        // re-entered, which is what a released link leaves behind.
        actions.reset_for_reopen();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let dead_tx = TokioSession::new(actions, observer, clock);

        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));
        mgr.add_storage(
            &dead_tx,
            &StorageConfig::new("demo", "demo/**", "mem"),
            vec![0x01],
        )
        .expect("a received storage-add is not lost because the peer already left");

        assert_eq!(
            mgr.len(),
            1,
            "the storage is HOSTED even though its declaration never reached the wire"
        );
        // ⚠ THE COUNT ALONE IS NOT THE WITNESS. `len() == 1` would also hold if
        // the declaration had quietly SUCCEEDED, which would mean the tolerated
        // arm never ran and this test proved nothing about it. Asserting the
        // storage is UNBOUND is what pins that the declare really was refused
        // and the storage survived it anyway.
        assert!(
            !mgr.storage("demo")
                .expect("hosted under its configured name")
                .is_bound(),
            "it is hosted UNBOUND: the declare was refused, and that is the state \
             this fix exists to make representable"
        );

        // And the binding is what `rebind_all` is for: on a live session the
        // storage acquires its subscriber and queryable without losing data.
        let live = make_session();
        mgr.rebind_all(&live, vec![0x01])
            .expect("a hosted-but-unbound storage is exactly what rebind_all repairs");
        assert!(
            mgr.storage("demo")
                .expect("still hosted after rebinding")
                .is_bound(),
            "rebind_all attached the handles the dead session could not"
        );
    }

    /// R2743 — THE OTHER DIRECTION, without which the tolerance above is only
    /// a comment. A declaration refused for a reason that is a FACT ABOUT THE
    /// CONFIG must still error and host nothing: re-declaring it on a later
    /// session would fail identically, so hosting it would mean carrying a
    /// storage that can never bind — the permanent version of the very
    /// divergence this fix exists to remove.
    ///
    /// A non-canonical keyexpr is that case: the outbound pico-safety gate
    /// refuses it at declare time on ANY session, live or dead.
    #[tokio::test]
    async fn a_storage_the_config_itself_forbids_is_still_refused() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));

        // `demo/**/` is non-canonical (trailing slash); the keyexpr gate
        // refuses it, and that refusal is not about any transport.
        let err = mgr
            .add_storage(
                &session,
                &StorageConfig::new("bad", "demo/**/", "mem"),
                vec![0x01],
            )
            .expect_err("a config the keyexpr gate refuses is not a hostable storage");

        assert!(
            mgr.is_empty(),
            "and nothing is hosted: {err:?} is permanent, so an unbound entry \
             would never become bound"
        );
    }

    // R2696 — the CASCADE, which is the whole of upstream's `kill_volume`
    // (`plugins/zenoh-plugin-storage-manager/src/lib.rs` @ `fn kill_volume`).
    // Three storages over two volumes, so the assertion can tell "tore down the
    // right set" from "tore down everything": a cascade that ignored the volume
    // id would pass a one-volume fixture.
    #[tokio::test]
    async fn remove_volume_takes_the_storages_hosted_on_it_and_leaves_the_others() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));
        mgr.register_volume("other", Box::new(MemoryVolume));
        for (name, volume) in [("s1", "mem"), ("s2", "other"), ("s3", "mem")] {
            mgr.add_storage(
                &session,
                &StorageConfig::new(name, "demo/**", volume),
                vec![0x01],
            )
            .expect("the fixture hosts all three");
        }

        let torn_down = mgr.remove_volume("mem").expect("the volume was registered");

        assert_eq!(
            torn_down,
            vec![String::from("s1"), String::from("s3")],
            "exactly the storages hosted on 'mem', named so an operator sees which went"
        );
        assert!(mgr.storage("s1").is_none(), "s1 went with its volume");
        assert!(mgr.storage("s3").is_none(), "s3 went with its volume");
        assert!(
            mgr.storage("s2").is_some(),
            "s2 is hosted on 'other' and the cascade must not reach it"
        );
        // And the volume itself is gone from the registry, not merely emptied of
        // storages: a re-add naming it must fail to RESOLVE.
        assert!(matches!(
            mgr.add_storage(
                &session,
                &StorageConfig::new("s4", "demo/**", "mem"),
                vec![0x01],
            ),
            Err(RuntimeStorageManagerError::Volume(
                VolumeRegistryError::VolumeNotFound(_)
            ))
        ));
    }

    // R2696 — an unknown volume is REFUSED, and the refusal is distinguishable
    // from "removed a volume that happened to host nothing". The caller acts on
    // that difference: the demo host logs a warning for one and an info for the
    // other, and a client that mistypes an id must not read success.
    //
    // ⚠ THIS TEST'S SUBJECT WAS NARROWED BY ITS OWN CONTROL. It first asserted
    // an ORDERING (refuse before tearing anything down), and the control that
    // reversed the two statements came back GREEN — because the hosted set is
    // derived from the volume id and is therefore always empty for a volume that
    // is not registered. The ordering was unobservable, so asserting it was
    // asserting nothing; what survives is the refusal itself, which the control
    // below does red.
    #[tokio::test]
    async fn remove_volume_refuses_an_unknown_name_rather_than_reporting_an_empty_success() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));
        mgr.add_storage(
            &session,
            &StorageConfig::new("s1", "demo/**", "mem"),
            vec![0x01],
        )
        .expect("the fixture hosts one storage");

        assert_eq!(
            mgr.remove_volume("nope"),
            None,
            "an unregistered volume is refused, never reported as a removal of nothing"
        );
        // And the ANTI-VACUITY arm: a volume that IS registered and hosts
        // nothing reports success with an empty set, so the two answers this
        // test is separating are both reachable in the same fixture.
        mgr.register_volume("empty", Box::new(MemoryVolume));
        assert_eq!(
            mgr.remove_volume("empty"),
            Some(Vec::new()),
            "a registered volume hosting nothing is removed, and says it took nothing"
        );
        assert!(mgr.storage("s1").is_some(), "neither call tore s1 down");
        mgr.add_storage(
            &session,
            &StorageConfig::new("s2", "demo/**", "mem"),
            vec![0x01],
        )
        .expect("'mem' is still registered after a refused removal");
    }

    /// R2787 — a storage-manager document, read the way the plugin reads it.
    #[cfg(feature = "adminspace-config-hotreload")]
    fn plugin_doc(text: &str) -> StoragePluginConfig {
        StoragePluginConfig::from_json5(
            STORAGE_MANAGER_PLUGIN,
            &wz_session_core::json5::parse(text).expect("json5"),
        )
        .expect("a document the plugin reads")
    }

    /// R2787 — the admin body of the storage named `name`, which is the one
    /// place the manager shows a hosted storage's config from outside.
    #[cfg(feature = "adminspace-config-hotreload")]
    fn hosted_body<R: SessionRuntime, T: TimeSource>(
        mgr: &RuntimeStorageManager<R, T>,
        name: &str,
    ) -> Option<String> {
        let suffix = format!("storages/{name}");
        mgr.admin_status_leaves("v")
            .into_iter()
            .find(|leaf| leaf.suffix == suffix)
            .map(|leaf| leaf.json_body)
    }

    /// R2787 — upstream's start: the `memory` volume, then every declared
    /// volume, then every declared storage, each on the volume it names.
    #[cfg(feature = "adminspace-config-hotreload")]
    #[tokio::test]
    async fn a_started_plugin_hosts_its_document_on_the_memory_volume_and_its_own() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        assert!(!mgr.plugin_running());
        let failures = mgr.start_plugin(
            &session,
            plugin_doc(
                r#"{ volumes: { extra: { backend: "memory" } },
                     storages: { a: { key_expr: "a/**", volume: "memory" },
                                 b: { key_expr: "b/**", volume: "extra" } } }"#,
            ),
            &[0x01],
        );
        assert!(failures.is_empty(), "{failures:?}");
        assert!(mgr.plugin_running());
        assert_eq!(mgr.storage_names().collect::<Vec<_>>(), vec!["a", "b"]);
        assert_eq!(
            hosted_body(&mgr, "b").as_deref(),
            Some(r#"{"key_expr":"b/**","volume":"extra"}"#),
            "b is hosted on the volume its document declared"
        );
    }

    /// R2787 — upstream's start does not stop at a failing step: "Failure of
    /// loading of one volume or storage should not affect others".
    #[cfg(feature = "adminspace-config-hotreload")]
    #[tokio::test]
    async fn a_start_reports_the_step_that_failed_and_still_runs_the_rest() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        let failures = mgr.start_plugin(
            &session,
            plugin_doc(
                r#"{ volumes: { odd: { backend: "no-such-backend" } },
                     storages: { bad: { key_expr: "x/**", volume: "nope" },
                                 good: { key_expr: "g/**", volume: "memory" } } }"#,
            ),
            &[0x01],
        );
        let said: Vec<String> = failures.iter().map(ToString::to_string).collect();
        assert_eq!(said.len(), 2, "{said:?}");
        assert!(said[0].starts_with("Cannot spawn volume 'odd'"), "{said:?}");
        assert!(
            said[1].starts_with("Cannot spawn storage 'bad'"),
            "{said:?}"
        );
        assert_eq!(mgr.storage_names().collect::<Vec<_>>(), vec!["good"]);
        assert!(
            mgr.plugin_running(),
            "the plugin runs whatever its steps said"
        );
    }

    /// R2787 — upstream's update: the diff in its order, stopping at the first
    /// failing step, what went before it staying applied, and the plugin still
    /// running the OLD document (the caller refuses the write).
    #[cfg(feature = "adminspace-config-hotreload")]
    #[tokio::test]
    async fn an_update_applies_the_diff_and_stops_at_the_first_failing_step() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        let old = plugin_doc(r#"{ storages: { a: { key_expr: "a/**", volume: "memory" } } }"#);
        assert!(mgr.start_plugin(&session, old.clone(), &[0x01]).is_empty());

        let moved = plugin_doc(r#"{ storages: { a: { key_expr: "a/x/**", volume: "memory" } } }"#);
        mgr.update_plugin(&session, &old, moved.clone(), &[0x01])
            .expect("a changed storage is its delete and its add");
        assert_eq!(
            hosted_body(&mgr, "a").as_deref(),
            Some(r#"{"key_expr":"a/x/**","volume":"memory"}"#)
        );

        let failing = plugin_doc(
            r#"{ storages: { a: { key_expr: "a/y/**", volume: "memory" },
                             z: { key_expr: "z/**", volume: "nope" } } }"#,
        );
        let err = mgr
            .update_plugin(&session, &moved, failing, &[0x01])
            .expect_err("z names a volume nobody declared");
        assert!(
            matches!(&err, PluginApplyError::Storage { storage, .. } if storage == "z"),
            "{err}"
        );
        assert_eq!(
            hosted_body(&mgr, "a").as_deref(),
            Some(r#"{"key_expr":"a/y/**","volume":"memory"}"#),
            "the step before the failure stays applied, as upstream's does"
        );
        assert!(mgr.storage("z").is_none());
    }

    /// R2787 — stopping the plugin takes what ITS document declared and the
    /// `memory` volume its start registered, and nothing a client added through
    /// the intent verbs.
    #[cfg(feature = "adminspace-config-hotreload")]
    #[tokio::test]
    async fn stopping_the_plugin_takes_its_own_and_leaves_the_intents() {
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));
        mgr.add_storage(
            &session,
            &StorageConfig::new("intent", "i/**", "mem"),
            vec![0x01],
        )
        .expect("an intent storage");
        assert!(mgr
            .start_plugin(
                &session,
                plugin_doc(
                    r#"{ volumes: { v: { backend: "mem" } },
                         storages: { p: { key_expr: "p/**", volume: "v" },
                                     q: { key_expr: "q/**", volume: "memory" } } }"#,
                ),
                &[0x01],
            )
            .is_empty());
        mgr.stop_plugin();
        assert!(!mgr.plugin_running());
        assert_eq!(mgr.storage_names().collect::<Vec<_>>(), vec!["intent"]);
        let leaves: Vec<String> = mgr
            .admin_status_leaves("v")
            .into_iter()
            .map(|leaf| leaf.suffix)
            .filter(|suffix| suffix.starts_with("volumes/") && !suffix.ends_with("__path__"))
            .collect();
        assert_eq!(
            leaves,
            vec![String::from("volumes/mem")],
            "only the host's own volume is left"
        );
    }

    /// R2787 — the manager as a `plugins` sink: what it validates, what it
    /// leaves alone, and the notification plane starting and stopping it.
    #[cfg(feature = "adminspace-config-hotreload")]
    #[tokio::test]
    async fn the_sink_validates_only_a_running_storage_manager_and_follows_its_document() {
        use crate::plugins_config::{PluginsConfig, PluginsSink};
        let doc = |text: &str| wz_session_core::json5::parse(text).expect("json5");
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        {
            let sink = StorageManagerSink::new(&mut mgr, &session, &[0x01]);
            // Another plugin, and a storage manager that is not running: both
            // are accepted unchecked, as upstream accepts them.
            assert_eq!(
                sink.check_config("rest", "", &doc("{}"), &doc("{ http_port: 8000 }")),
                Ok(None)
            );
            assert_eq!(
                sink.check_config(
                    STORAGE_MANAGER_PLUGIN,
                    "",
                    &doc("{}"),
                    &doc("{ storages: 1 }")
                ),
                Ok(None)
            );
            // The document appearing starts the plugin.
            let section = PluginsConfig::from_section(&doc(
                r#"{ storage_manager: { storages: { s: { key_expr: "s/**", volume: "memory" } } } }"#,
            ))
            .unwrap();
            sink.plugins_changed(&section);
            assert!(sink.take_reports().is_empty());
        }
        assert!(mgr.plugin_running());
        assert_eq!(mgr.storage_names().collect::<Vec<_>>(), vec!["s"]);
        {
            let sink = StorageManagerSink::new(&mut mgr, &session, &[0x01]);
            let current = doc(r#"{ storages: { s: { key_expr: "s/**", volume: "memory" } } }"#);
            // Running now: a document it cannot read is refused, and so is a
            // step it cannot apply.
            assert!(sink
                .check_config(
                    STORAGE_MANAGER_PLUGIN,
                    "",
                    &current,
                    &doc("{ storages: 1 }")
                )
                .is_err());
            assert!(sink
                .check_config(
                    STORAGE_MANAGER_PLUGIN,
                    "storages/t",
                    &current,
                    &doc(r#"{ storages: { s: { key_expr: "s/**", volume: "memory" },
                                          t: { key_expr: "t/**", volume: "nope" } } }"#),
                )
                .is_err());
            // A readable, applicable change is applied.
            assert_eq!(
                sink.check_config(
                    STORAGE_MANAGER_PLUGIN,
                    "storages/u",
                    &current,
                    &doc(r#"{ storages: { s: { key_expr: "s/**", volume: "memory" },
                                          u: { key_expr: "u/**", volume: "memory" } } }"#),
                ),
                Ok(None)
            );
            // The document going stops the plugin.
            sink.plugins_changed(&PluginsConfig::new());
        }
        assert!(!mgr.plugin_running());
        assert!(mgr.is_empty(), "the plugin's storages went with it");
    }

    // R2696 — the wire's backend name resolves against what THIS BUILD carries,
    // and every refusal names what it refused.
    #[test]
    fn build_volume_resolves_mem_and_names_what_it_cannot_build() {
        assert!(
            build_volume("mem", &[]).is_ok(),
            "the in-memory backend is unconditional"
        );
        // `.err()` rather than `unwrap_err()` throughout: the Ok side is a
        // `Box<dyn Volume>`, which is not `Debug` and cannot be — the trait is
        // object-safe precisely because it carries no such bound.
        assert_eq!(
            build_volume("no-such-backend", &[]).err(),
            Some(VolumeBuildError::UnknownBackend(String::from(
                "no-such-backend"
            ))),
            "an unknown backend is refused BY NAME, never substituted"
        );
        // A backend that reads no parameters says so rather than ignoring them:
        // a volume built from a config it did not honour is one the operator
        // cannot reason about.
        assert_eq!(
            build_volume("mem", &[(String::from("root"), String::from("/srv"))]).err(),
            Some(VolumeBuildError::UnknownParameters {
                backend: String::from("mem"),
                keys: vec![String::from("root")],
            }),
        );
    }

    // R2696 — the filesystem backend's parameter contract, on the build that
    // carries it. The cfg is the CALLER's: without the feature there is no `fs`
    // arm to test and the catch-all's answer is already pinned above.
    //
    // R2802 — this test used to assert that `fs` with no `root` is refused, on
    // the premise that such a volume "would be rooted wherever the process
    // stands". Upstream roots it somewhere definite (`ZENOH_BACKEND_FS_ROOT`,
    // else under the zenoh home), so the no-root arm now builds that volume, and
    // its rule is witnessed where it lives without touching this process's
    // environment: `filesystem_storage::tests::the_root_is_derived_as_upstreams_plugin_derives_it`
    // and `..._creates_and_canonicalizes_the_derived_root`.
    #[cfg(feature = "storage-backend-filesystem")]
    #[test]
    fn build_volume_fs_takes_an_optional_root_and_reads_nothing_else() {
        assert!(build_volume("fs", &[(String::from("root"), String::from("/srv/wz"))]).is_ok());
        assert_eq!(
            build_volume(
                "fs",
                &[
                    (String::from("root"), String::from("/srv/wz")),
                    (String::from("rooot"), String::from("/srv/typo")),
                ]
            )
            .err(),
            Some(VolumeBuildError::UnknownParameters {
                backend: String::from("fs"),
                keys: vec![String::from("rooot")],
            }),
            "a typo'd key must not produce a volume rooted somewhere else"
        );
    }

    // R311y503 — a live storage now starts its periodic garbage collector
    // (`tokio::spawn`), so a test that hosts one must run inside a runtime,
    // exactly as production does. Nothing about the assertions changed.
    #[tokio::test]
    async fn add_storage_duplicate_name_errs() {
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

    // R311y239 — the COMPOSED config-hotreload mechanism (adminspace-config-hotreload):
    // an admin config-WRITE `storage-add` decodes (wz-session-core) → to_storage_config →
    // RuntimeStorageManager::add_storage spawns a LIVE storage → the dynamic registry
    // BUILDER compiled_plugins_dyn(.., !mgr.is_empty()) reports storage_manager Started;
    // a `storage-del` reverses it. SCOPE: this drives compiled_plugins_dyn DIRECTLY with
    // the manager's live state — it proves the parse→spawn→despawn→builder chain, not the
    // answer_admin_query reply path. That path IS covered, by Layer E6h against a foreign
    // pico client on the `--storage-host` demo mode; R311y828 corrected the parenthetical
    // here, which claimed no shipping host fed a live slice.
    #[cfg(feature = "adminspace-config-hotreload")]
    // R311y503 — a live storage now starts its periodic garbage collector
    // (`tokio::spawn`), so a test that hosts one must run inside a runtime,
    // exactly as production does. Nothing about the assertions changed.
    #[tokio::test]
    async fn config_hotreload_spawns_despawns_storage_and_reflects_plugin_state() {
        use crate::compiled_plugins_dyn;
        use wz_session_core::adminspace::{
            parse_admin_config_write, AdminConfigWrite, AdminConfigWriteBody,
            AdminConfigWriteOutcome, AdminConfigWriteSpace, AdminPluginState,
        };

        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));

        // Before any storage: registry reports storage_manager Loaded (compiled, not running).
        assert!(mgr.is_empty());
        assert_eq!(
            compiled_plugins_dyn("0.1.0", !mgr.is_empty())[0].state,
            AdminPluginState::Loaded
        );

        // A config-write `storage-add demo:demo/**` → AddStorage → StorageConfig → live spawn.
        let space = AdminConfigWriteSpace::new("z", "peer");
        let out = parse_admin_config_write(
            &space,
            "@/z/peer/config/storage-add",
            AdminConfigWriteBody::Put(b"demo:demo/**"),
            true,
            // R2658 — the decoder takes the config-key vocabulary as a
            // parameter, and this one says EVERY name is a config key. That is
            // deliberately the hostile input for these two asserts: a name wz
            // owns must reach its own arm even when the supplied vocabulary
            // claims it, which is what `ADMIN_CONFIG_WRITE_ACTIONS` guarantees.
            &|_| true,
        );
        let AdminConfigWriteOutcome::Apply(intent) = out else {
            panic!("storage-add must Apply: {out:?}");
        };
        let config = intent
            .to_storage_config()
            .expect("AddStorage -> StorageConfig");
        assert_eq!(config.name, "demo");
        assert_eq!(config.key_expr, "demo/**");
        mgr.add_storage(&session, &config, vec![0x01])
            .expect("spawn a live memory storage");

        // After add: the storage is hosted + the registry flips storage_manager Started.
        assert_eq!(mgr.len(), 1);
        assert!(mgr.storage("demo").is_some());
        assert_eq!(
            compiled_plugins_dyn("0.1.0", !mgr.is_empty())[0].state,
            AdminPluginState::Started,
            "a live storage -> the builder reports storage_manager Started (the state a \
             storage-hosting host would surface via the plugins admin reply)"
        );

        // A `storage-del demo` → RemoveStorage → despawn (RAII undeclare) → back to Loaded.
        let out = parse_admin_config_write(
            &space,
            "@/z/peer/config/storage-del",
            AdminConfigWriteBody::Put(b"demo"),
            true,
            &|_| true,
        );
        let AdminConfigWriteOutcome::Apply(AdminConfigWrite::RemoveStorage(name)) = out else {
            panic!("storage-del must Apply RemoveStorage: {out:?}");
        };
        assert!(mgr.remove_storage(&name), "despawn the named storage");
        assert!(mgr.is_empty());
        assert_eq!(
            compiled_plugins_dyn("0.1.0", !mgr.is_empty())[0].state,
            AdminPluginState::Loaded,
            "despawn -> storage_manager Loaded"
        );
    }

    // R311y503 — a live storage now starts its periodic garbage collector
    // (`tokio::spawn`), so a test that hosts one must run inside a runtime,
    // exactly as production does. Nothing about the assertions changed.
    #[tokio::test]
    async fn remove_storage_undeclares_and_frees_the_name() {
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

    // R311y503 — a live storage now starts its periodic garbage collector
    // (`tokio::spawn`), so a test that hosts one must run inside a runtime,
    // exactly as production does. Nothing about the assertions changed.
    #[tokio::test]
    async fn remove_storage_drops_the_capture_subscriber_no_more_loopback_fires() {
        use crate::session::PublishOptions;
        use wz_session_core::locality::Locality;

        // The teardown PROOF: removing a storage must actually UNDECLARE its
        // capture subscriber (the StorageService's RAII Drop), not merely drop
        // the map entry. While hosted, a loopback publish on the storage's
        // keyexpr fires the capture subscriber (fired == 1); after remove, the
        // SAME publish fires ZERO subscribers (fired == 0) — the subscriber is
        // genuinely gone from the observer's registry.
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("mem", Box::new(MemoryVolume));

        mgr.add_storage(
            &session,
            &StorageConfig::new("s1", "demo/**", "mem"),
            vec![0x01],
        )
        .expect("storage hosts");

        // Hosted: the loopback publish reaches the capture subscriber.
        let fired = session
            .publish(
                "demo/a",
                b"v1",
                PublishOptions::put().with_locality(Locality::SessionLocal),
            )
            .expect("loopback publish");
        assert_eq!(fired, 1, "the hosted storage's capture subscriber fired");

        assert!(mgr.remove_storage("s1"), "the storage is removed");

        // Removed: the SAME loopback publish fires NO subscribers — the RAII
        // Drop undeclared the capture subscriber.
        let fired_after = session
            .publish(
                "demo/a",
                b"v2",
                PublishOptions::put().with_locality(Locality::SessionLocal),
            )
            .expect("loopback publish after remove");
        assert_eq!(
            fired_after, 0,
            "remove undeclared the capture subscriber (RAII Drop), so no subscriber fires"
        );
    }

    // The COMPOSITION proof through the manager: it hosts N live
    // strip-configured storages, each isolated by its keyexpr, each applying
    // strip on the live capture + restore on a query — driven entirely by the
    // per-storage StorageConfig.
    #[cfg(feature = "storage-mgr-strip-prefix")]
    // R311y503 — a live storage now starts its periodic garbage collector
    // (`tokio::spawn`), so a test that hosts one must run inside a runtime,
    // exactly as production does. Nothing about the assertions changed.
    #[tokio::test]
    async fn manager_hosts_two_strip_configured_storages_each_isolated() {
        use crate::reply_sink::ReplyView;
        use crate::session::{PublishOptions, QueryOptions};
        use wz_session_core::locality::Locality;

        // A real loopback GET over the manager-hosted storages: drive the
        // declared queryable callbacks inline (SessionLocal locality) and record
        // every (keyexpr, payload) reply. The closure is `Send + 'static`, hence
        // the Arc<Mutex<..>> sink.
        fn loopback_query(session: &TokioSession, keyexpr: &str) -> Vec<(String, Vec<u8>)> {
            let replies = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
            let rec = Arc::clone(&replies);
            session
                .query(
                    keyexpr,
                    QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                    move |reply: &dyn ReplyView| {
                        rec.lock()
                            .expect("reply recorder poisoned")
                            .push((reply.keyexpr().to_string(), reply.payload().to_vec()));
                    },
                    |_rid| {},
                )
                .expect("loopback query fires the declared queryables inline");
            // Bind through a local so the MutexGuard temporary is dropped before
            // the function returns (a direct `.lock()..clone()` return trips the
            // borrow checker on the guard's lifetime).
            let recorded = replies.lock().expect("reply recorder poisoned").clone();
            recorded
        }

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

        // CAPTURE leg (kept): kitchen stored the key RELATIVE to its mount.
        mgr.storage("kitchen").unwrap().with_state(|st| {
            assert_eq!(
                st.get_newest(Some("temp")).unwrap().map(|d| d.payload),
                Some(b"k".to_vec()),
                "kitchen stored the key relative to its mount"
            );
        });

        // RESTORE leg (over the LIVE path): a real loopback GET on the kitchen
        // mount drives kitchen's declared queryable -> answer_into -> restore,
        // and the recorded reply carries the RESTORED full keyexpr with v=`k`.
        assert_eq!(
            loopback_query(&session, "home/kitchen/*"),
            vec![(String::from("home/kitchen/temp"), b"k".to_vec())],
            "the kitchen queryable restores the mount prefix on the live path"
        );

        // The bath storage is independent: a real loopback GET on the bath mount
        // returns NOTHING — bath captured nothing AND kitchen's queryable does
        // not match the bath keyexpr (keyexpr isolation across hosted storages).
        assert!(
            loopback_query(&session, "home/bath/*").is_empty(),
            "the bath mount yields no replies (isolation: bath empty, kitchen unmatched)"
        );
    }

    // A real loopback GET over a manager-hosted storage: drive the declared
    // queryable callbacks inline (SessionLocal) and record every (keyexpr,
    // payload) reply. The closure is `Send + 'static`, hence the Arc<Mutex<..>>.
    #[cfg(feature = "storage-backend-filesystem")]
    fn loopback_get(session: &TokioSession, keyexpr: &str) -> Vec<(String, Vec<u8>)> {
        use crate::reply_sink::ReplyView;
        use crate::session::QueryOptions;
        use wz_session_core::locality::Locality;

        let replies = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
        let rec = Arc::clone(&replies);
        session
            .query(
                keyexpr,
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                move |reply: &dyn ReplyView| {
                    rec.lock()
                        .expect("reply recorder poisoned")
                        .push((reply.keyexpr().to_string(), reply.payload().to_vec()));
                },
                |_rid| {},
            )
            .expect("loopback query fires the declared queryables inline");
        let recorded = replies.lock().expect("reply recorder poisoned").clone();
        recorded
    }

    // R311y280 — the COMPOSITION + DURABILITY proof: the storage-backend-filesystem
    // backend, driven through the REAL live path (RuntimeStorageManager -> add_storage
    // -> StorageService capture subscriber + queryable -> FilesystemStorage -> disk),
    // survives a manager restart. The isolated y279 backend unit test proves the
    // backend round-trips on disk; THIS proves the composed live service serves the
    // persisted value after a fresh manager re-hosts it (per composition-over-isolated-atoms).
    #[cfg(feature = "storage-backend-filesystem")]
    // R311y503 — a live storage now starts its periodic garbage collector
    // (`tokio::spawn`), so a test that hosts one must run inside a runtime,
    // exactly as production does. Nothing about the assertions changed.
    #[tokio::test]
    async fn filesystem_volume_composes_durably_across_a_manager_restart() {
        use crate::filesystem_storage::FilesystemVolume;
        use crate::session::PublishOptions;
        use wz_session_core::locality::Locality;

        let dir = tempfile::tempdir().expect("tempdir");
        // R2802 — an fs storage names its directory, as upstream's must.
        let mut cfg = StorageConfig::new("durable", "demo/**", "fs");
        cfg.volume_cfg.push((
            String::from("dir"),
            wz_session_core::json5::Json5Value::String(String::from("durable")),
        ));

        // Session 1: host an fs-backed storage, capture a Put over the live path.
        {
            let session = make_session();
            let mut mgr = RuntimeStorageManager::new();
            mgr.register_volume("fs", Box::new(FilesystemVolume::new(dir.path())));
            mgr.add_storage(&session, &cfg, vec![0x01])
                .expect("host an fs-backed storage");
            let fired = session
                .publish(
                    "demo/a",
                    b"v1",
                    PublishOptions::put().with_locality(Locality::SessionLocal),
                )
                .expect("loopback put");
            assert_eq!(fired, 1, "the fs storage's capture subscriber fired");
            assert_eq!(
                loopback_get(&session, "demo/a"),
                vec![(String::from("demo/a"), b"v1".to_vec())],
                "the value is served live from the fs-backed storage"
            );
        } // drop: the capture subscriber is undeclared + the backend dropped; the dir persists.

        // Session 2: a FRESH manager + fs volume on the SAME dir serves the value
        // persisted before the restart -- with NO new put it can only come from
        // disk (R2801: every read goes to the directory), through a
        // freshly-declared queryable.
        {
            let session = make_session();
            let mut mgr = RuntimeStorageManager::new();
            mgr.register_volume("fs", Box::new(FilesystemVolume::new(dir.path())));
            mgr.add_storage(&session, &cfg, vec![0x01])
                .expect("re-host over the same dir");
            assert_eq!(
                loopback_get(&session, "demo/a"),
                vec![(String::from("demo/a"), b"v1".to_vec())],
                "the fs-backed storage served the pre-restart value -- durable through the live driver"
            );
        }
    }

    // R2802 — the config a hosted storage KEEPS is the one its volume handed
    // back. Upstream's fs volume inserts `dir_full_path` into the config its
    // storage keeps and the admin plane reports that config; a manager hosting
    // its own pre-create copy would report a storage with no word of where its
    // data is. The root is given through a `..` so the reported path must also
    // be the CANONICAL one the sidecar keys its rows by.
    #[cfg(all(
        feature = "storage-backend-filesystem",
        feature = "adminspace-plugins-handlers"
    ))]
    #[tokio::test]
    async fn a_hosted_fs_storage_reports_the_directory_its_volume_resolved() {
        use crate::filesystem_storage::FilesystemVolume;

        let dir = tempfile::tempdir().expect("tempdir");
        let spelled = dir.path().join("x").join("..");
        let mut cfg = StorageConfig::new("reported", "demo/**", "fs");
        cfg.volume_cfg.push((
            String::from("dir"),
            wz_session_core::json5::Json5Value::String(String::from("d")),
        ));
        let session = make_session();
        let mut mgr = RuntimeStorageManager::new();
        mgr.register_volume("fs", Box::new(FilesystemVolume::new(spelled)));
        mgr.add_storage(&session, &cfg, vec![0x01])
            .expect("host an fs-backed storage");

        let body = mgr
            .admin_status_leaves("v")
            .into_iter()
            .find(|leaf| leaf.suffix == "storages/reported")
            .map(|leaf| leaf.json_body)
            .expect("the hosted storage reports");
        let mut want = String::from("\"dir_full_path\":");
        wz_session_core::json::escape_into(
            &dunce::canonicalize(dir.path())
                .expect("canonical tempdir")
                .join("d")
                .to_string_lossy(),
            &mut want,
        );
        assert!(body.contains(&want), "want {want} in {body}");
    }

    // R2804 — the fs VOLUME's own admin body is what upstream's fs volume
    // reports, its canonical root and the version, where every other wz volume
    // answers with its capability. The memory volume beside it keeps that
    // capability body, so the leaf is per volume rather than per manager.
    #[cfg(all(
        feature = "storage-backend-filesystem",
        feature = "adminspace-plugins-handlers"
    ))]
    #[test]
    fn the_fs_volume_reports_upstreams_root_and_version() {
        use crate::filesystem_storage::FilesystemVolume;

        let dir = tempfile::tempdir().expect("tempdir");
        // Spelled through a `..` over a directory that exists, so the body must
        // carry the canonical root rather than the host's spelling.
        std::fs::create_dir(dir.path().join("x")).expect("mkdir");
        let mut mgr = RuntimeStorageManager::<
            crate::runtime_impl::TokioRuntime,
            crate::runtime_impl::TokioTime,
        >::new();
        mgr.register_volume(
            "fs",
            Box::new(FilesystemVolume::new(dir.path().join("x").join(".."))),
        );
        mgr.register_volume("mem", Box::new(MemoryVolume));
        let leaves = mgr.admin_status_leaves("v");
        let body_at = |suffix: &str| {
            leaves
                .iter()
                .find(|leaf| leaf.suffix == suffix)
                .map(|leaf| leaf.json_body.clone())
                .unwrap_or_else(|| panic!("no admin leaf at {suffix}"))
        };
        let mut want = String::from("{\"root\":");
        wz_session_core::json::escape_into(
            &dunce::canonicalize(dir.path())
                .expect("canonical tempdir")
                .to_string_lossy(),
            &mut want,
        );
        want.push_str(",\"version\":\"v\"}");
        assert_eq!(body_at("volumes/fs"), want);
        assert_eq!(
            body_at("volumes/mem"),
            r#"{"capability":{"history":"Latest","persistence":"Volatile"}}"#
        );
    }

    // The DISCRIMINATOR for the durability proof above: the identical flow on a
    // (Volatile) MemoryVolume LOSES the value across the restart, so the fs test
    // proves persistence, not merely that a value round-trips within one session.
    #[cfg(feature = "storage-backend-filesystem")]
    // R311y503 — a live storage now starts its periodic garbage collector
    // (`tokio::spawn`), so a test that hosts one must run inside a runtime,
    // exactly as production does. Nothing about the assertions changed.
    #[tokio::test]
    async fn memory_volume_does_not_survive_a_manager_restart() {
        use crate::session::PublishOptions;
        use wz_session_core::locality::Locality;

        let cfg = StorageConfig::new("volatile", "demo/**", "mem");
        {
            let session = make_session();
            let mut mgr = RuntimeStorageManager::new();
            mgr.register_volume("mem", Box::new(MemoryVolume));
            mgr.add_storage(&session, &cfg, vec![0x01])
                .expect("host a memory storage");
            session
                .publish(
                    "demo/a",
                    b"v1",
                    PublishOptions::put().with_locality(Locality::SessionLocal),
                )
                .expect("loopback put");
            assert_eq!(
                loopback_get(&session, "demo/a"),
                vec![(String::from("demo/a"), b"v1".to_vec())],
                "served live in-session"
            );
        }
        {
            let session = make_session();
            let mut mgr = RuntimeStorageManager::new();
            mgr.register_volume("mem", Box::new(MemoryVolume));
            mgr.add_storage(&session, &cfg, vec![0x01])
                .expect("re-host a fresh memory storage");
            assert!(
                loopback_get(&session, "demo/a").is_empty(),
                "a Volatile memory storage starts empty after a restart -- the value is gone"
            );
        }
    }
}
