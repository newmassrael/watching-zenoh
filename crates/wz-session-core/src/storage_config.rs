// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.24 storage manager *config* — the declarative [`StorageConfig`] a storage
//! MANAGER uses to create + drive one named storage, the wz mirror of zenoh
//! `zenoh-backend-traits` `StorageConfig` (`plugins/zenoh-backend-traits/src/config.rs:60`)
//! + `GarbageCollectionConfig` (`:155`). The FOUNDATIONAL data model the
//! manager/behavior atoms (multi-storage-host / strip-prefix / complete-flag /
//! garbage-collection) read; this atom is the typed model only, the behaviors are
//! its own atoms.
//!
//! wz subset (typed-by-construction, the beyond-zenoh stance): `name` / `key_expr`
//! / `volume_id` / `complete` / `strip_prefix` / `garbage_collection`. OMITTED vs
//! zenoh's struct: the untyped `volume_cfg: serde_json::Value` backend blob (wz
//! has no untyped config tree — a typed backend config arrives with its backend
//! atom), the `replication: Option<ReplicaConfig>` (wz's replication is the
//! SEPARATE §5.11 `storage-replication` track), and the `PluginConfig` /
//! `VolumeConfig` plugin-LOADING wrapper (wz composes volumes at build time, not
//! via dlopen — `storage-mgr-dynamic-volume-loading` is out-of-scope-AP).
//!
//! FOUNDATIONAL: always compiled under `storage-backend`, no own cfg toggle. The
//! field is the model; the BEHAVIOR that reads each field is its own atom
//! (`complete` -> storage-mgr-complete-flag, `strip_prefix` -> storage-mgr-strip-prefix,
//! `garbage_collection` -> storage-mgr-garbage-collection), and the consumer that
//! turns a `StorageConfig` into a live storage is storage-mgr-multi-storage-host
//! (which will pass it to [`crate::storage_volume::Volume::create_storage`], closing
//! that R311y55 MVP config-free divergence).

use alloc::string::String;
use core::time::Duration;

/// Garbage-collection schedule for a storage's stale metadata — zenoh
/// `GarbageCollectionConfig` (`backend-traits/config.rs:155`). The
/// `storage-mgr-garbage-collection` BEHAVIOR atom reads these to schedule the
/// periodic sweep; this struct is the data model only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarbageCollectionConfig {
    /// The period between two garbage-collection sweeps. zenoh default 30s.
    pub period: Duration,
    /// Metadata older than this is collected. zenoh default 86400s (1 day).
    pub lifespan: Duration,
}

impl Default for GarbageCollectionConfig {
    /// zenoh's `GarbageCollectionConfig::default` (`config.rs:164-168`):
    /// period 30s, lifespan 86400s.
    fn default() -> Self {
        Self {
            period: Duration::from_secs(30),
            lifespan: Duration::from_secs(86400),
        }
    }
}

/// The declarative configuration of one named storage — zenoh `StorageConfig`
/// (`backend-traits/config.rs:60`). A storage manager creates a backend via the
/// named volume ([`volume_id`](StorageConfig::volume_id)) and drives it over the
/// [`key_expr`](StorageConfig::key_expr) it owns, applying
/// [`strip_prefix`](StorageConfig::strip_prefix) /
/// [`complete`](StorageConfig::complete) /
/// [`garbage_collection`](StorageConfig::garbage_collection) per the matching
/// behavior atoms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageConfig {
    /// The storage's unique name within the manager.
    pub name: String,
    /// The keyexpr this storage owns (the data it captures + answers queries on).
    pub key_expr: String,
    /// The name of the volume that backs this storage (zenoh `volume_id`); the
    /// manager resolves it to a [`crate::storage_volume::Volume`].
    pub volume_id: String,
    /// Whether this storage is AUTHORITATIVE for its keyexpr (a "complete"
    /// queryable that fully owns the space) vs partial. zenoh `complete`. WIRED
    /// (R311y61): the live `StorageService::declare_with_backend` reads this field
    /// into `QueryableOptions::with_complete(storage_queryable_complete(config.complete))`
    /// (the `storage-mgr-complete-flag` gate), retiring the R311y59 standalone
    /// `complete` param. (Pre-y61 this field was inert — the note here used to say
    /// so; it is now the SSOT the queryable's COMPLETE bit flows from.)
    pub complete: bool,
    /// An optional keyexpr prefix to STRIP from a key before storing (and
    /// re-prepend on read), so a storage can hold keys relative to a mount point.
    /// zenoh `strip_prefix`. WIRED (R311y61): the live service applies this field
    /// via `StorageState::with_strip_prefix(backend, config.strip_prefix)` (under
    /// the `storage-mgr-strip-prefix` feature) to the capture + query key path,
    /// including the §5.11 backend `Option`-key for the exact-prefix (mount-root)
    /// case; the composed strip-on-capture / restore-on-query is proven e2e through
    /// the manager (wz-runtime-tokio `storage_manager_service` tests). (Pre-y61 the
    /// logic existed but was not applied from this field — the note here used to
    /// say so.)
    pub strip_prefix: Option<String>,
    /// The stale-metadata GC schedule (the `storage-mgr-garbage-collection` atom).
    pub garbage_collection: GarbageCollectionConfig,
}

impl StorageConfig {
    /// A storage config for `name` owning `key_expr`, backed by volume
    /// `volume_id`, with the zenoh-faithful defaults: not `complete`, no
    /// `strip_prefix`, default GC schedule. The `pub` fields are then set
    /// directly for the non-default cases.
    pub fn new(
        name: impl Into<String>,
        key_expr: impl Into<String>,
        volume_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            key_expr: key_expr.into(),
            volume_id: volume_id.into(),
            complete: false,
            strip_prefix: None,
            garbage_collection: GarbageCollectionConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_default_matches_zenoh() {
        // zenoh GarbageCollectionConfig::default = period 30s / lifespan 86400s.
        let gc = GarbageCollectionConfig::default();
        assert_eq!(gc.period, Duration::from_secs(30));
        assert_eq!(gc.lifespan, Duration::from_secs(86400));
    }

    #[test]
    fn storage_config_new_has_zenoh_faithful_defaults() {
        let c = StorageConfig::new("demo", "demo/**", "mem");
        assert_eq!(c.name, "demo");
        assert_eq!(c.key_expr, "demo/**");
        assert_eq!(c.volume_id, "mem");
        assert!(
            !c.complete,
            "zenoh default: a storage is partial unless declared"
        );
        assert_eq!(c.strip_prefix, None);
        assert_eq!(c.garbage_collection, GarbageCollectionConfig::default());
    }

    #[test]
    fn storage_config_fields_are_settable() {
        let mut c = StorageConfig::new("d", "a/**", "mem");
        c.complete = true;
        c.strip_prefix = Some("a".into());
        assert!(c.complete);
        assert_eq!(c.strip_prefix.as_deref(), Some("a"));
    }
}
