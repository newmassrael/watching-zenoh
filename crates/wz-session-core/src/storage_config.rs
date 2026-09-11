// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.24 storage manager *config* — the declarative
//! [`StorageConfig`](crate::storage_config::StorageConfig) a storage
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
//! `VolumeConfig` plugin-LOADING wrapper.
//!
//! ⚠ R2542 — THE CLAUSE THAT USED TO CLOSE THAT SENTENCE IS STRUCK, because it
//! was false at this commit and it was steering work. It read "wz composes
//! volumes at build time, not via dlopen — `storage-mgr-dynamic-volume-loading`
//! is out-of-scope-AP". Both halves are wrong now: R311y497 BUILT runtime dlopen
//! of backend volumes, and this tree carries its three parts — the `wz-volume-abi`
//! crate, `wz-runtime-tokio`'s `dynamic_volume.rs`, and the `<name>[@<volume_id>]`
//! storage-add wire. The atom is graded PARTIAL by the inventory, not
//! out-of-scope; the four atoms this store actually grades OUT-OF-SCOPE are
//! `platform-qnx`, `scouting-passive`, `storage-backend-external-db` and
//! `storage-backend-rocksdb`. A header that contradicts the grade is worse than
//! silence: it is read as a scope decision and stops the work being picked up.
//!
//! ⚠ R2571 — THE `volume_cfg` OMISSION ABOVE IS NO LONGER TRUE, and the open
//! question it left ("what a per-storage payload should BE here") is answered.
//! [`StorageConfig::volume_cfg`](crate::storage_config::StorageConfig::volume_cfg)
//! carries it as a `Vec<(String, String)>`: wz types the SHAPE and reads none of
//! the contents, which keeps the typed-by-construction stance while giving a
//! backend exactly what upstream gives it. The answer was FORCED rather than
//! chosen — [`StorageConfig::to_admin_json`](crate::storage_config::StorageConfig::to_admin_json)
//! has to reproduce upstream's bare-string AND object renderings, and an opaque
//! blob cannot produce the second without parsing itself apart.
//!
//! The two halves that made it reachable: the wire gained upstream's object form
//! (`<name>@<volume_id>?<k>=<v>&…`, the `adminspace` module's
//! `parse_storage_add_payload`), and [`crate::storage_volume::Volume`]'s
//! `create_storage` already took `&StorageConfig`, so every backend can read it
//! with no trait change. The LOAD-time `--storage-volume-config <text>` is a
//! different axis and is unchanged: it configures a VOLUME by name, once; this
//! configures a STORAGE's use of one.
//!
//! FOUNDATIONAL: always compiled under `storage-backend`, no own cfg toggle. The
//! field is the model; the BEHAVIOR that reads each field is its own atom
//! (`complete` -> storage-mgr-complete-flag, `strip_prefix` -> storage-mgr-strip-prefix,
//! `garbage_collection` -> storage-mgr-garbage-collection), and the consumer that
//! turns a `StorageConfig` into a live storage is storage-mgr-multi-storage-host
//! (which will pass it to [`crate::storage_volume::Volume::create_storage`], closing
//! that R311y55 MVP config-free divergence).

// ⚠ EVERY intra-doc link in the `//!` block above is written as a FULL
// `crate::…` path, and that is not a style choice. lib.rs carries an outer `///`
// doc on `pub mod storage_config;` (`lib.rs:1196`), so rustdoc MERGES the two
// and resolves the merged text against the CRATE ROOT — where `StorageConfig` is
// not in scope, even though it is declared in this very file. R2571 wrote two
// bare `[`StorageConfig::…`]` links here and Layer C1bz redded at 539 against a
// budget of 537. Item-level `///` docs further down are NOT merged and resolve
// in module scope, which is why `[`Self::to_admin_json`]` on the field is fine.

use alloc::string::String;
use alloc::vec::Vec;
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
    /// R2571 — the PER-STORAGE volume payload, the wz analogue of zenoh's
    /// `volume_cfg`
    /// (`plugins/zenoh-backend-traits/src/config.rs` @ `pub volume_cfg: JsonValue,`).
    /// EMPTY is upstream's `Value::Null`: the storage named its volume with a
    /// bare id and carries no per-storage configuration for it.
    ///
    /// # Why a pair list and not an opaque blob
    ///
    /// This module's header left the design question open ("what a per-storage
    /// payload should BE here, given this module's typed-by-construction stance
    /// and that `wz-session-core` carries no `serde_json`"), and the answer is
    /// forced by the ADMIN side rather than chosen: [`Self::to_admin_json`] has
    /// to reproduce upstream's two shapes — a bare string when there is no
    /// payload, and an OBJECT with `id` inserted alongside the payload's own
    /// keys when there is (`config.rs` @ `v.insert("id".into(), self.volume_id.clone().into());`).
    /// An opaque `String` could not render the second without parsing itself
    /// back apart, which would put the structure here anyway and in a worse
    /// place. Pairs render directly.
    ///
    /// wz still never INTERPRETS the values — that is the backend's, exactly as
    /// upstream hands `volume_cfg` through `create_storage` untouched — so the
    /// typed-by-construction stance holds: this module types the SHAPE and reads
    /// none of the contents.
    pub volume_cfg: Vec<(String, String)>,
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
            // Upstream's `Value::Null` arm: a storage that named its volume by a
            // bare id carries no per-storage payload for it.
            volume_cfg: Vec::new(),
        }
    }

    /// R311y828 — this storage's admin-space status body, the wz analogue of
    /// zenoh's `Storage::get_admin_status()`, which the storage task answers with
    /// `self.config.to_json_value()` (`memory_backend/mod.rs:93-95`, reached from
    /// `storages_mgt/service.rs:199-203`). Upstream's shape
    /// (`zenoh-backend-traits/src/config.rs:406-425`) is
    /// `{"key_expr":…, "strip_prefix"?:…, "volume":…}`: `strip_prefix` is OMITTED
    /// when absent, and `volume` is the bare volume id (a string) unless the
    /// storage carried a per-volume config object, which wz's [`StorageConfig`]
    /// has no field for. The key order here is `serde_json`'s `Map` order, which
    /// is a `BTreeMap` (alphabetical) and happens to equal the insertion order.
    ///
    /// `complete` and `garbage_collection` are wz fields upstream keeps OUT of
    /// this body, and they stay out: a client parsing the admin plane of a wz node
    /// and of a zenoh node must not have to branch on which it is talking to.
    /// Hand-rolled for the same reason every other body in this workspace is —
    /// `wz-session-core` carries no `serde_json`.
    pub fn to_admin_json(&self) -> String {
        let mut out = String::from("{\"key_expr\":");
        crate::json::escape_into(&self.key_expr, &mut out);
        if let Some(prefix) = &self.strip_prefix {
            out.push_str(",\"strip_prefix\":");
            crate::json::escape_into(prefix, &mut out);
        }
        out.push_str(",\"volume\":");
        if self.volume_cfg.is_empty() {
            // Upstream's `Value::Null` arm — the bare volume id as a string.
            crate::json::escape_into(&self.volume_id, &mut out);
        } else {
            // Upstream's `Value::Object` arm. It builds the payload's own map
            // and THEN inserts `id` into it (`config.rs` @
            // `v.insert("id".into(), self.volume_id.clone().into());`), so `id`
            // wins over a payload key of the same name — reproduced here by
            // emitting the payload first and `id` last, which is also what a
            // last-wins JSON reader resolves to. The key ORDER differs from
            // upstream's `serde_json::Map` (a `BTreeMap`, alphabetical); JSON
            // object order is not semantic and every other body in this module
            // is hand-rolled for the same no-`serde_json` reason.
            out.push('{');
            for (key, value) in &self.volume_cfg {
                crate::json::escape_into(key, &mut out);
                out.push(':');
                crate::json::escape_into(value, &mut out);
                out.push(',');
            }
            out.push_str("\"id\":");
            crate::json::escape_into(&self.volume_id, &mut out);
            out.push('}');
        }
        out.push('}');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R2571 — upstream's `Value::Null` arm: no per-storage payload renders the
    /// volume as a bare STRING (`config.rs` @
    /// `Value::Null => Value::String(self.volume_id.clone()),`). This is the
    /// shape every pre-R2571 storage produced, so it is also the back-compat
    /// pin: a client parsing a wz admin body must not have to learn a new shape
    /// because a field was added.
    #[test]
    fn admin_volume_is_a_bare_string_when_there_is_no_payload() {
        let c = StorageConfig::new("demo", "demo/**", "mem");
        assert!(c.volume_cfg.is_empty(), "the default is upstream's Null");
        assert!(
            c.to_admin_json().contains(r#""volume":"mem""#),
            "got {}",
            c.to_admin_json()
        );
    }

    /// R2571 — upstream's `Value::Object` arm: a payload renders the volume as an
    /// OBJECT and `id` is inserted alongside the payload's own keys
    /// (`config.rs` @ `v.insert("id".into(), self.volume_id.clone().into());`).
    #[test]
    fn admin_volume_is_an_object_carrying_id_when_a_payload_is_present() {
        let mut c = StorageConfig::new("demo", "demo/**", "fs");
        c.volume_cfg = alloc::vec![
            (String::from("dir"), String::from("/tmp/wz")),
            (String::from("mode"), String::from("rw")),
        ];
        let body = c.to_admin_json();
        assert!(
            body.contains(r#""volume":{"dir":"/tmp/wz","mode":"rw","id":"fs"}"#),
            "got {body}"
        );
    }

    /// The payload's VALUES are escaped like every other string in this body —
    /// they are operator text and may carry a quote or a backslash, and an
    /// unescaped one would produce a body no JSON reader can parse.
    #[test]
    fn admin_volume_payload_is_escaped() {
        let mut c = StorageConfig::new("demo", "demo/**", "fs");
        c.volume_cfg = alloc::vec![(String::from("dir"), String::from("a\"b"))];
        assert!(
            c.to_admin_json().contains(r#""dir":"a\"b""#),
            "{}",
            c.to_admin_json()
        );
    }

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
        // R311y828 — the admin body upstream's `to_json_value` produces for the
        // same config: no `strip_prefix` key at all when it is None, and `volume`
        // as the bare id. `complete` / `garbage_collection` are absent by design.
        assert_eq!(
            c.to_admin_json(),
            r#"{"key_expr":"demo/**","volume":"mem"}"#
        );
    }

    #[test]
    fn storage_config_fields_are_settable() {
        let mut c = StorageConfig::new("d", "a/**", "mem");
        c.complete = true;
        c.strip_prefix = Some("a".into());
        assert!(c.complete);
        assert_eq!(c.strip_prefix.as_deref(), Some("a"));
        // R311y828 — `strip_prefix` APPEARS once set (upstream's
        // `if let Some(s) = &self.strip_prefix`), between `key_expr` and `volume`.
        // `complete = true` changes nothing: upstream's body has no such key.
        assert_eq!(
            c.to_admin_json(),
            r#"{"key_expr":"a/**","strip_prefix":"a","volume":"mem"}"#
        );
    }

    #[test]
    fn admin_json_escapes_a_keyexpr_that_would_break_the_body() {
        // The bodies are hand-rolled, so the escaper is load-bearing rather than
        // incidental: a `"` inside a keyexpr must not terminate the JSON string.
        // Keyexpr grammar does not forbid it, and an admin client parsing the
        // reply is the one that pays.
        let mut c = StorageConfig::new("d", "a/\"quoted\"/**", "mem");
        c.strip_prefix = Some("back\\slash".into());
        assert_eq!(
            c.to_admin_json(),
            r#"{"key_expr":"a/\"quoted\"/**","strip_prefix":"back\\slash","volume":"mem"}"#
        );
    }
}
