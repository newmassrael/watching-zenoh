// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2785 (§5.23 `adminspace-config-hotreload`) — the storage manager's
//! DECLARATIVE configuration, read the way upstream reads it, and the
//! difference between two of them.
//!
//! ## What this is the base of
//!
//! An operator's zenoh config names its storages in one place, the
//! `plugins.storage_manager` document of `volumes` and `storages`. Upstream
//! reads that document when the plugin starts, and on every later write to it
//! parses the OLD and the NEW document whole, computes their difference, and
//! applies the difference — refusing the write when a step fails
//! (`plugins/zenoh-plugin-storage-manager/src/lib.rs` @ `let diffs = ConfigDiff::diffs(old, new);`).
//!
//! wz had the operations a difference is made of — the storage and volume
//! intents, and the manager that applies them — and none of the document: no
//! reader for it and no diff over it. So a stock config's storages never
//! reached a wz node, and no write could be judged against the one before it.
//! Open-debt item 773 settled that wz takes the document; this module is the
//! part every consumer of it shares. It applies nothing: the host holding the
//! storage manager applies [`ConfigDiff`](crate::storage_plugin_config::ConfigDiff)s,
//! at startup (old = empty) and on a
//! runtime write alike.
//!
//! ## Upstream's semantics, measured at the pin
//!
//! * PARSE. [`StoragePluginConfig::from_json5`](crate::storage_plugin_config::StoragePluginConfig::from_json5) is
//!   `plugins/zenoh-backend-traits/src/config.rs` @ `impl<S: Into<String> + AsRef<str>, V: AsObject> TryFrom<(S, &V)> for PluginConfig {`,
//!   reading the fields in the order that code reads them, so the FIRST refusal
//!   is the same one. A present `null` is not an absence there — `get` returns
//!   `Some(Null)` and most fields refuse it — except where upstream's own arm
//!   accepts it, which is reproduced rather than tidied: `replication: null`
//!   enables replication with its defaults.
//! * ORDER AND DUPLICATES. The pinned lockfile's `serde_json` entry carries no
//!   `indexmap`, so `preserve_order` is off and upstream's `Map` is a
//!   `BTreeMap`. Volumes and storages are therefore visited in NAME order
//!   whatever order the document wrote them in, and a key written twice keeps
//!   its LAST value. Every object read here goes through that same shape.
//! * EQUALITY. A storage is equal to another when every field is, its volume
//!   payload compared as a `serde_json::Value` compares
//!   (`commons/zenoh-util/src/ffi/mod.rs` @ `impl PartialEq for JsonValue {`):
//!   key order is not semantic and an integer is not the float of the same
//!   value. A volume compares only three fields
//!   (`plugins/zenoh-backend-traits/src/config.rs` @ `self.name == other.name && self.paths == other.paths && self.rest == other.rest`),
//!   so flipping `__required__` alone is NOT a change — while `backend` IS one,
//!   because it is never removed from `rest`.
//! * DIFF. `plugins/zenoh-backend-traits/src/config.rs` @ `pub fn diffs(old: PluginConfig, new: PluginConfig) -> Vec<ConfigDiff> {`:
//!   deleted storages, deleted volumes, added volumes, added storages, in that
//!   order — what depends on something is torn down before it and built after
//!   it. A CHANGED storage is not edited in place; it is a delete of the old
//!   and an add of the new, which is why equality matters: an equality that
//!   saw a change where upstream sees none would restart the storage, and a
//!   restarted memory storage has lost its data.
//!
//! ## Where wz departs, and why
//!
//! * Two upstream PANICS are refusals here. `Duration::from_secs_f64` panics on
//!   a negative `replication.interval`, and the propagation-delay check
//!   (`plugins/zenoh-backend-traits/src/config.rs` @ `if (replication.interval - propagation_delay) < propagation_delay {`)
//!   subtracts two `Duration`s, which panics when the delay exceeds the
//!   interval. A config value must not be able to take a node down; both are
//!   refused as the too-high case they are.
//! * Refusals name the storage where upstream's garbage-collection and
//!   replication messages name the plugin — those texts reach an operator's
//!   log and nothing on the wire.
//! * `volume_cfg` reaches wz's `StorageConfig` as string pairs
//!   ([`StorageDecl::to_storage_config`](crate::storage_plugin_config::StorageDecl::to_storage_config));
//!   an object payload with no keys
//!   besides `id` therefore renders there as the bare-string form. The DIFF is
//!   unaffected: it compares the declaration, which keeps upstream's
//!   distinction between a bare `volume: "x"` and `volume: { id: "x" }`.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use crate::json5::Json5Value;
use crate::storage_config::{GarbageCollectionConfig, StorageConfig};

/// The plugin name upstream's storage manager declares itself under, and so
/// the key its document lives at below `plugins`.
pub const STORAGE_MANAGER_PLUGIN: &str = "storage_manager";

/// The storage manager's whole document — upstream's `PluginConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct StoragePluginConfig {
    /// The plugin's name, the key below `plugins` its document was read from.
    pub name: String,
    /// `__required__`, `true` when absent.
    pub required: bool,
    /// `backend_search_dirs` as written: `None` when absent, the one path of a
    /// string, or the paths of an array. wz loads no backend by search, so
    /// these are held for the operator and for equality, never walked.
    pub backend_search_dirs: Option<Vec<String>>,
    /// The declared volumes, in name order.
    pub volumes: Vec<VolumeDecl>,
    /// The declared storages, in name order.
    pub storages: Vec<StorageDecl>,
    /// Every other top-level key (`__path__`, `__config__`, …), in name order.
    pub rest: Vec<(String, Json5Value)>,
}

/// One declared volume — upstream's `VolumeConfig`.
#[derive(Debug, Clone)]
pub struct VolumeDecl {
    /// The volume's id, the key it was declared under.
    pub name: String,
    /// `backend`, when the declaration named one.
    pub backend: Option<String>,
    /// `__path__`: the libraries to load it from, when named.
    pub paths: Option<Vec<String>>,
    /// `__required__`, `true` when absent.
    pub required: bool,
    /// Every key but `__path__` and `__required__`, in name order. `backend`
    /// stays in here, exactly as it does upstream.
    pub rest: Vec<(String, Json5Value)>,
}

impl PartialEq for VolumeDecl {
    /// Upstream's three fields and no others — see the module doc.
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.paths == other.paths && pairs_eq(&self.rest, &other.rest)
    }
}

impl VolumeDecl {
    /// The backend this volume is built from: the one it names, else a backend
    /// of its own name — upstream's
    /// `plugins/zenoh-backend-traits/src/config.rs` @ `pub fn backend(&self) -> &str {`.
    pub fn backend(&self) -> &str {
        self.backend.as_deref().unwrap_or(&self.name)
    }
}

/// Replication settings — upstream's `ReplicaConfig`. wz's replication is its
/// own track (`storage-replication`); this is carried because upstream's
/// equality compares it, so a change to it must restart the storage here too.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplicaConfig {
    /// `interval`, read as seconds.
    pub interval: Duration,
    /// `sub_intervals`.
    pub sub_intervals: usize,
    /// `hot`.
    pub hot: u64,
    /// `warm`.
    pub warm: u64,
    /// `propagation_delay`, read as milliseconds.
    pub propagation_delay: Duration,
}

impl Default for ReplicaConfig {
    /// Upstream's defaults: 10 s, 5, 6, 30, 250 ms.
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            sub_intervals: 5,
            hot: 6,
            warm: 30,
            propagation_delay: Duration::from_millis(250),
        }
    }
}

/// One declared storage — upstream's `StorageConfig`, every field of it,
/// because every field takes part in its equality.
#[derive(Debug, Clone)]
pub struct StorageDecl {
    /// The storage's name, the key it was declared under.
    pub name: String,
    /// `key_expr`, a valid key expression in canon form.
    pub key_expr: String,
    /// `complete`.
    pub complete: bool,
    /// `strip_prefix`, a non-wild prefix of `key_expr`.
    pub strip_prefix: Option<String>,
    /// The volume's id: the string form of `volume`, or its object's `id`.
    pub volume_id: String,
    /// The object form's other keys, in name order; `None` for the string
    /// form, which upstream keeps apart from an object with no other keys.
    pub volume_cfg: Option<Vec<(String, Json5Value)>>,
    /// `garbage_collection`, upstream's defaults for what it leaves out.
    pub garbage_collection: GarbageCollectionConfig,
    /// `replication`, `None` when absent.
    pub replication: Option<ReplicaConfig>,
}

impl PartialEq for StorageDecl {
    fn eq(&self, other: &Self) -> bool {
        let volume_cfg_eq = match (&self.volume_cfg, &other.volume_cfg) {
            (None, None) => true,
            (Some(a), Some(b)) => pairs_eq(a, b),
            _ => false,
        };
        self.name == other.name
            && self.key_expr == other.key_expr
            && self.complete == other.complete
            && self.strip_prefix == other.strip_prefix
            && self.volume_id == other.volume_id
            && volume_cfg_eq
            && self.garbage_collection == other.garbage_collection
            && self.replication == other.replication
    }
}

impl StorageDecl {
    /// The wz [`StorageConfig`] the storage manager is driven by.
    ///
    /// Every field wz models is carried. `volume_cfg` becomes string pairs: a
    /// string value is itself, any other value its JSON text, so a backend
    /// reading `dir` gets the path and one reading a number gets its digits.
    /// `replication` has no field there and is not dropped silently by
    /// accident — see this type's doc.
    pub fn to_storage_config(&self) -> StorageConfig {
        let mut config = StorageConfig::new(&self.name, &self.key_expr, &self.volume_id);
        config.complete = self.complete;
        config.strip_prefix = self.strip_prefix.clone();
        config.garbage_collection = self.garbage_collection.clone();
        config.volume_cfg = self
            .volume_cfg
            .iter()
            .flatten()
            .map(|(key, value)| {
                let text = match value {
                    Json5Value::String(s) => s.clone(),
                    other => other.to_json5_text(),
                };
                (key.clone(), text)
            })
            .collect();
        config
    }
}

/// One step of the difference between two documents — upstream's
/// `ConfigDiff`, in the order [`diffs`] emits them.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigDiff {
    /// A volume the new document no longer declares as it was.
    DeleteVolume(VolumeDecl),
    /// A volume the old document did not declare as it now is.
    AddVolume(VolumeDecl),
    /// A storage the new document no longer declares as it was.
    DeleteStorage(StorageDecl),
    /// A storage the old document did not declare as it now is.
    AddStorage(StorageDecl),
}

/// The difference between `old` and `new`, in upstream's order: deleted
/// storages, deleted volumes, added volumes, added storages, each group in
/// name order. A changed entry appears as its delete and its add.
pub fn diffs(old: &StoragePluginConfig, new: &StoragePluginConfig) -> Vec<ConfigDiff> {
    let mut out = Vec::new();
    for storage in &old.storages {
        if !new.storages.contains(storage) {
            out.push(ConfigDiff::DeleteStorage(storage.clone()));
        }
    }
    for volume in &old.volumes {
        if !new.volumes.contains(volume) {
            out.push(ConfigDiff::DeleteVolume(volume.clone()));
        }
    }
    for volume in &new.volumes {
        if !old.volumes.contains(volume) {
            out.push(ConfigDiff::AddVolume(volume.clone()));
        }
    }
    for storage in &new.storages {
        if !old.storages.contains(storage) {
            out.push(ConfigDiff::AddStorage(storage.clone()));
        }
    }
    out
}

/// Why a storage manager document was refused. One variant per refusal
/// upstream's reader makes, plus the two panics it has that wz refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginConfigError {
    /// The plugin's document is not an object.
    NotAnObject {
        /// The plugin.
        plugin: String,
    },
    /// A plugin-level field has the wrong type.
    PluginField {
        /// The plugin.
        plugin: String,
        /// The field.
        field: &'static str,
        /// What it has to be.
        expected: &'static str,
    },
    /// A volume's declaration is not an object.
    VolumeNotAnObject {
        /// The volume.
        volume: String,
    },
    /// A volume-level field has the wrong type.
    VolumeField {
        /// The volume.
        volume: String,
        /// The field.
        field: &'static str,
        /// What it has to be.
        expected: &'static str,
    },
    /// A storage's declaration is not an object.
    StorageNotAnObject {
        /// The storage.
        storage: String,
    },
    /// A storage-level field is missing or has the wrong type.
    StorageField {
        /// The storage.
        storage: String,
        /// The field.
        field: &'static str,
        /// What it has to be.
        expected: &'static str,
    },
    /// `key_expr` is not a key expression in canon form.
    InvalidKeyExpr {
        /// The storage.
        storage: String,
        /// The text as written.
        key_expr: String,
    },
    /// `complete` is a string other than `"true"` or `"false"`.
    InvalidComplete {
        /// The storage.
        storage: String,
        /// The text as written.
        value: String,
    },
    /// `strip_prefix` does not begin `key_expr`.
    StripPrefixNotAPrefix {
        /// The storage.
        storage: String,
        /// The prefix as written.
        strip_prefix: String,
        /// The storage's key expression.
        key_expr: String,
    },
    /// `strip_prefix` is not a key expression in canon form.
    InvalidStripPrefix {
        /// The storage.
        storage: String,
        /// The prefix as written.
        strip_prefix: String,
    },
    /// `strip_prefix` carries a wildcard.
    WildStripPrefix {
        /// The storage.
        storage: String,
        /// The prefix as written.
        strip_prefix: String,
    },
    /// `replication.propagation_delay` is at least half of `interval`.
    PropagationDelayTooHigh {
        /// The storage.
        storage: String,
        /// The delay as written, in milliseconds.
        delay_ms: u64,
    },
}

impl fmt::Display for PluginConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnObject { plugin } => {
                write!(f, "configuration for plugin `{plugin}` must be an object")
            }
            Self::PluginField {
                plugin,
                field,
                expected,
            } => write!(f, "`{field}` of plugin `{plugin}` must be {expected}"),
            Self::VolumeNotAnObject { volume } => {
                write!(f, "configuration of volume `{volume}` must be an object")
            }
            Self::VolumeField {
                volume,
                field,
                expected,
            } => write!(f, "`{field}` of volume `{volume}` must be {expected}"),
            Self::StorageNotAnObject { storage } => {
                write!(f, "configuration of storage `{storage}` must be an object")
            }
            Self::StorageField {
                storage,
                field,
                expected,
            } => write!(f, "`{field}` of storage `{storage}` must be {expected}"),
            Self::InvalidKeyExpr { storage, key_expr } => write!(
                f,
                "key_expr='{key_expr}' of storage `{storage}` is not a valid key-expression"
            ),
            Self::InvalidComplete { storage, value } => write!(
                f,
                "complete='{value}' of storage `{storage}` is not a valid value; only \
                 booleans or the strings 'true' and 'false' are accepted"
            ),
            Self::StripPrefixNotAPrefix {
                storage,
                strip_prefix,
                key_expr,
            } => write!(
                f,
                "the specified \"strip_prefix={strip_prefix}\" of storage `{storage}` is not \
                 a prefix of \"key_expr={key_expr}\""
            ),
            Self::InvalidStripPrefix {
                storage,
                strip_prefix,
            } => write!(
                f,
                "strip_prefix='{strip_prefix}' of storage `{storage}` is not a valid \
                 key-expression"
            ),
            Self::WildStripPrefix {
                storage,
                strip_prefix,
            } => write!(
                f,
                "the specified \"strip_prefix={strip_prefix}\" of storage `{storage}` \
                 contains wildcard characters (it shouldn't)"
            ),
            // The sentence upstream's own test pins, kept word for word so the
            // vector ports unchanged.
            Self::PropagationDelayTooHigh { storage, delay_ms } => write!(
                f,
                "invalid value for field `propagation_delay` of storage `{storage}`: its \
                 value is too high compared to the `interval`, consider increasing the \
                 `interval` to at least twice its value (i.e. {})",
                *delay_ms as f64 * 2.0 / 1000.0
            ),
        }
    }
}

impl core::error::Error for PluginConfigError {}

impl StoragePluginConfig {
    /// An empty document for `name`: no volumes, no storages. What a node
    /// whose config never mentioned the plugin diffs its first document
    /// against.
    pub fn empty(name: &str) -> Self {
        Self {
            name: String::from(name),
            required: true,
            backend_search_dirs: None,
            volumes: Vec::new(),
            storages: Vec::new(),
            rest: Vec::new(),
        }
    }

    /// Read the plugin `name`'s document the way upstream's `PluginConfig`
    /// reader does — see the module doc for what "the way" includes.
    pub fn from_json5(name: &str, value: &Json5Value) -> Result<Self, PluginConfigError> {
        let plugin = || String::from(name);
        let map =
            object_map(value).ok_or_else(|| PluginConfigError::NotAnObject { plugin: plugin() })?;
        let plugin_field = |field, expected| PluginConfigError::PluginField {
            plugin: plugin(),
            field,
            expected,
        };
        let required = match map.get("__required__") {
            None => true,
            Some(Json5Value::Bool(b)) => *b,
            Some(_) => return Err(plugin_field("__required__", "a boolean")),
        };
        let backend_search_dirs = match map.get("backend_search_dirs") {
            None => None,
            Some(Json5Value::String(path)) => Some(alloc::vec![path.clone()]),
            Some(Json5Value::Array(paths)) => Some(
                paths
                    .iter()
                    .map(|p| match p {
                        Json5Value::String(p) => Ok(p.clone()),
                        _ => Err(plugin_field(
                            "backend_search_dirs",
                            "a string or array of strings",
                        )),
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Some(_) => {
                return Err(plugin_field(
                    "backend_search_dirs",
                    "a string or array of strings",
                ))
            }
        };
        let volumes = match map.get("volumes") {
            None => Vec::new(),
            Some(configs) => {
                let configs =
                    object_map(configs).ok_or_else(|| plugin_field("volumes", "an object"))?;
                configs
                    .into_iter()
                    .map(|(volume, config)| read_volume(volume, config))
                    .collect::<Result<_, _>>()?
            }
        };
        let storages = match map.get("storages") {
            None => Vec::new(),
            Some(configs @ Json5Value::Object(_)) => {
                let configs = object_map(configs).expect("matched as an object");
                configs
                    .into_iter()
                    .map(|(storage, config)| read_storage(storage, config))
                    .collect::<Result<_, _>>()?
            }
            Some(_) => return Err(plugin_field("storages", "an object")),
        };
        let rest = map
            .into_iter()
            .filter(|(key, _)| {
                !["__required__", "backend_search_dirs", "volumes", "storages"].contains(key)
            })
            .map(|(key, value)| (String::from(key), value.clone()))
            .collect();
        Ok(Self {
            name: String::from(name),
            required,
            backend_search_dirs,
            volumes,
            storages,
            rest,
        })
    }
}

/// One volume, as `plugins/zenoh-backend-traits/src/config.rs` @ `fn try_from<V: AsObject>(plugin_name: &str, configs: &V) -> ZResult<Vec<Self>> {`
/// reads each entry of `volumes`.
fn read_volume(name: &str, config: &Json5Value) -> Result<VolumeDecl, PluginConfigError> {
    let map = object_map(config).ok_or_else(|| PluginConfigError::VolumeNotAnObject {
        volume: String::from(name),
    })?;
    let field = |field, expected| PluginConfigError::VolumeField {
        volume: String::from(name),
        field,
        expected,
    };
    let backend = match map.get("backend") {
        None => None,
        Some(Json5Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(field("backend", "a string")),
    };
    let paths = match map.get("__path__") {
        None => None,
        Some(Json5Value::String(s)) => Some(alloc::vec![s.clone()]),
        Some(Json5Value::Array(a)) => Some(
            a.iter()
                .map(|p| match p {
                    Json5Value::String(p) => Ok(p.clone()),
                    _ => Err(field("__path__", "a string or array of strings")),
                })
                .collect::<Result<_, _>>()?,
        ),
        Some(_) => return Err(field("__path__", "a string or array of strings")),
    };
    let required = match map.get("__required__") {
        None => true,
        Some(Json5Value::Bool(b)) => *b,
        Some(_) => return Err(field("__required__", "a boolean")),
    };
    let rest = map
        .into_iter()
        .filter(|(key, _)| !["__path__", "__required__"].contains(key))
        .map(|(key, value)| (String::from(key), value.clone()))
        .collect();
    Ok(VolumeDecl {
        name: String::from(name),
        backend,
        paths,
        required,
        rest,
    })
}

/// One storage, as `plugins/zenoh-backend-traits/src/config.rs` @ `fn try_from<V: AsObject>(plugin_name: &str, storage_name: &str, config: &V) -> ZResult<Self> {`
/// reads it — field by field, in that function's order.
fn read_storage(name: &str, config: &Json5Value) -> Result<StorageDecl, PluginConfigError> {
    let storage = || String::from(name);
    let map = object_map(config)
        .ok_or_else(|| PluginConfigError::StorageNotAnObject { storage: storage() })?;
    let field = |field, expected| PluginConfigError::StorageField {
        storage: storage(),
        field,
        expected,
    };

    // A non-string `key_expr` reads as a missing one upstream (`as_str()`).
    let key_expr = match map.get("key_expr") {
        Some(Json5Value::String(s)) => s.clone(),
        _ => return Err(field("key_expr", "a string-typed key expression")),
    };
    if !is_canon_keyexpr(&key_expr) {
        return Err(PluginConfigError::InvalidKeyExpr {
            storage: storage(),
            key_expr,
        });
    }

    let complete = match map.get("complete") {
        None => false,
        Some(Json5Value::Bool(b)) => *b,
        Some(Json5Value::String(s)) if s == "true" => true,
        Some(Json5Value::String(s)) if s == "false" => false,
        Some(Json5Value::String(s)) => {
            return Err(PluginConfigError::InvalidComplete {
                storage: storage(),
                value: s.clone(),
            })
        }
        Some(_) => {
            return Err(field(
                "complete",
                "a boolean or the string 'true' or 'false'",
            ))
        }
    };

    // Upstream's order: the TEXT prefix test (`str::starts_with`, not a chunk
    // test — `demo/ab` prefixes `demo/abc/**` there and so here), then the key
    // expression, then the wildcard.
    let strip_prefix = match map.get("strip_prefix") {
        None => None,
        Some(Json5Value::String(s)) => {
            if !key_expr.starts_with(s.as_str()) {
                return Err(PluginConfigError::StripPrefixNotAPrefix {
                    storage: storage(),
                    strip_prefix: s.clone(),
                    key_expr,
                });
            }
            if !is_canon_keyexpr(s) {
                return Err(PluginConfigError::InvalidStripPrefix {
                    storage: storage(),
                    strip_prefix: s.clone(),
                });
            }
            // Upstream's `is_wild`: the text holds a `*`, `$*` included.
            if s.contains('*') {
                return Err(PluginConfigError::WildStripPrefix {
                    storage: storage(),
                    strip_prefix: s.clone(),
                });
            }
            Some(s.clone())
        }
        Some(_) => return Err(field("strip_prefix", "a string")),
    };

    let (volume_id, volume_cfg) = match map.get("volume") {
        Some(Json5Value::String(id)) => (id.clone(), None),
        Some(volume @ Json5Value::Object(_)) => {
            let volume = object_map(volume).expect("matched as an object");
            // A non-string `id` is dropped rather than kept as payload, and
            // then reads as a missing one — upstream's `("id", _) => {}`.
            let id = match volume.get("id") {
                Some(Json5Value::String(id)) => id.clone(),
                _ => return Err(field("volume", "a string, or an object with a string `id`")),
            };
            let cfg = volume
                .into_iter()
                .filter(|(key, _)| *key != "id")
                .map(|(key, value)| (String::from(key), value.clone()))
                .collect();
            (id, Some(cfg))
        }
        _ => return Err(field("volume", "a string, or an object with a string `id`")),
    };

    // A non-object value has no fields to read, so it yields the defaults —
    // upstream calls `get` on whatever `garbage_collection` holds.
    let mut garbage_collection = GarbageCollectionConfig::default();
    if let Some(gc) = map.get("garbage_collection") {
        if let Some(period) = gc.get("period") {
            garbage_collection.period = Duration::from_secs(
                json_u64(period).ok_or_else(|| field("garbage_collection/period", "an integer"))?,
            );
        }
        if let Some(lifespan) = gc.get("lifespan") {
            garbage_collection.lifespan = Duration::from_secs(
                json_u64(lifespan)
                    .ok_or_else(|| field("garbage_collection/lifespan", "an integer"))?,
            );
        }
    }

    // Present at all — `null` included — enables replication, upstream's
    // `Some(s) =>` arm.
    let replication = match map.get("replication") {
        None => None,
        Some(r) => {
            let mut replication = ReplicaConfig::default();
            if let Some(p) = r.get("interval") {
                let secs = json_f64(p).ok_or_else(|| field("replication/interval", "a number"))?;
                replication.interval = Duration::try_from_secs_f64(secs)
                    .map_err(|_| field("replication/interval", "a non-negative number"))?;
            }
            if let Some(p) = r.get("sub_intervals") {
                replication.sub_intervals = json_u64(p)
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or_else(|| field("replication/sub_intervals", "an integer"))?;
            }
            if let Some(p) = r.get("hot") {
                replication.hot =
                    json_u64(p).ok_or_else(|| field("replication/hot", "an integer"))?;
            }
            if let Some(p) = r.get("warm") {
                replication.warm =
                    json_u64(p).ok_or_else(|| field("replication/warm", "an integer"))?;
            }
            if let Some(p) = r.get("propagation_delay") {
                let delay_ms = json_u64(p)
                    .ok_or_else(|| field("replication/propagation_delay", "an integer"))?;
                let delay = Duration::from_millis(delay_ms);
                // `None` is the case upstream's subtraction panics on.
                let too_high = match replication.interval.checked_sub(delay) {
                    None => true,
                    Some(left) => left < delay,
                };
                if too_high {
                    return Err(PluginConfigError::PropagationDelayTooHigh {
                        storage: storage(),
                        delay_ms,
                    });
                }
                replication.propagation_delay = delay;
            }
            Some(replication)
        }
    };

    Ok(StorageDecl {
        name: storage(),
        key_expr,
        complete,
        strip_prefix,
        volume_id,
        volume_cfg,
        garbage_collection,
        replication,
    })
}

/// An object's entries as upstream's `Map` holds them: sorted by key, the
/// LAST of a repeated key kept. `None` for anything that is not an object.
fn object_map(value: &Json5Value) -> Option<BTreeMap<&str, &Json5Value>> {
    let Json5Value::Object(entries) = value else {
        return None;
    };
    // Inserting in source order makes the later of two equal keys win.
    Some(entries.iter().map(|(k, v)| (k.as_str(), v)).collect())
}

/// Upstream's `keyexpr::new`: the text must already BE canon, not merely
/// canonicalise (`commons/zenoh-keyexpr/src/key_expr/borrowed.rs` @ `impl<'a> TryFrom<&'a str> for &'a keyexpr {`
/// refuses `**/*`, `**/**` and a lone `$*` rather than rewriting them). Canon
/// is a fixed point, so "canonicalises to itself" is exactly that test. Upstream
/// core is zenoh-c's lineage, hence that dialect.
fn is_canon_keyexpr(text: &str) -> bool {
    crate::keyexpr_canon::canonize_keyexpr_in(text, crate::keyexpr_canon::KeyexprDialect::ZenohC)
        .is_ok_and(|canon| canon.as_str() == text)
}

/// A JSON number, as the value upstream's JSON5 reader hands `serde_json`:
/// an integer when the literal has no fraction or exponent, else a float.
#[derive(Debug, Clone, Copy, PartialEq)]
enum JsonNumber {
    Int(i128),
    Float(f64),
}

fn json_number(text: &str) -> Option<JsonNumber> {
    let (negative, body) = match text.strip_prefix('-') {
        Some(body) => (true, body),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let signed = |magnitude: i128| if negative { -magnitude } else { magnitude };
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        return i128::from_str_radix(hex, 16)
            .ok()
            .map(|m| JsonNumber::Int(signed(m)));
    }
    if !body.contains(['.', 'e', 'E']) {
        if let Ok(m) = body.parse::<i128>() {
            return Some(JsonNumber::Int(signed(m)));
        }
    }
    text.parse::<f64>()
        .ok()
        .filter(|f| f.is_finite())
        .map(JsonNumber::Float)
}

/// Upstream's `value.to_string().parse::<u64>()`: a JSON integer in `u64`'s
/// range, and nothing else — not a float of an integral value, and not a
/// string of digits (its `to_string()` keeps the quotes).
fn json_u64(value: &Json5Value) -> Option<u64> {
    match value {
        Json5Value::Number(text) => match json_number(text)? {
            JsonNumber::Int(i) => u64::try_from(i).ok(),
            JsonNumber::Float(_) => None,
        },
        _ => None,
    }
}

/// Upstream's `value.to_string().parse::<f64>()`: any JSON number.
fn json_f64(value: &Json5Value) -> Option<f64> {
    match value {
        Json5Value::Number(text) => match json_number(text)? {
            JsonNumber::Int(i) => Some(i as f64),
            JsonNumber::Float(f) => Some(f),
        },
        _ => None,
    }
}

/// Two name-ordered pair lists, equal as `serde_json` maps are.
fn pairs_eq(a: &[(String, Json5Value)], b: &[(String, Json5Value)]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|((ka, va), (kb, vb))| ka == kb && json_eq(va, vb))
}

/// Two values, equal as `serde_json::Value`s are: objects as maps (order not
/// semantic, last of a repeated key kept), numbers by kind and value.
fn json_eq(a: &Json5Value, b: &Json5Value) -> bool {
    match (a, b) {
        (Json5Value::Null, Json5Value::Null) => true,
        (Json5Value::Bool(x), Json5Value::Bool(y)) => x == y,
        (Json5Value::String(x), Json5Value::String(y)) => x == y,
        (Json5Value::Number(x), Json5Value::Number(y)) => match (json_number(x), json_number(y)) {
            (Some(x), Some(y)) => x == y,
            _ => x == y,
        },
        (Json5Value::Array(x), Json5Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| json_eq(x, y))
        }
        (Json5Value::Object(_), Json5Value::Object(_)) => {
            let (x, y) = (
                object_map(a).expect("object"),
                object_map(b).expect("object"),
            );
            x.len() == y.len()
                && x.iter()
                    .zip(&y)
                    .all(|((kx, vx), (ky, vy))| kx == ky && json_eq(vx, vy))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json5::parse;
    use alloc::vec;

    fn read(doc: &str) -> Result<StoragePluginConfig, PluginConfigError> {
        StoragePluginConfig::from_json5(STORAGE_MANAGER_PLUGIN, &parse(doc).expect("json5"))
    }

    fn storage(doc: &str) -> Result<StorageDecl, PluginConfigError> {
        read(&alloc::format!("{{ storages: {{ s: {doc} }} }}")).map(|c| c.storages[0].clone())
    }

    fn names(c: &StoragePluginConfig) -> (Vec<&str>, Vec<&str>) {
        (
            c.volumes.iter().map(|v| v.name.as_str()).collect(),
            c.storages.iter().map(|s| s.name.as_str()).collect(),
        )
    }

    /// Upstream's storage-manager plugin ships this document as its own
    /// example config. It is read as upstream reads it — including the ORDER:
    /// the file writes `memory` before `example`, and the storages come back in
    /// name order, because upstream's `Map` is a `BTreeMap`.
    #[test]
    fn the_plugins_own_example_document_reads_as_upstream_reads_it() {
        let c = read(
            r#"{
              "volumes": {
                "example": {
                  "__path__": ["target/debug/libzenoh_backend_example.so","target/debug/libzenoh_backend_example.dylib"]
                }
              },
              "storages": {
                "memory": { "volume": "memory", "key_expr": "demo/memory/**" },
                "example": { "volume": "example", "key_expr": "demo/example/**" }
              }
            }"#,
        )
        .expect("upstream's own example");
        assert_eq!(names(&c), (vec!["example"], vec!["example", "memory"]));
        let volume = &c.volumes[0];
        assert_eq!(volume.backend(), "example", "no `backend` names its own");
        assert_eq!(volume.paths.as_ref().map(Vec::len), Some(2));
        assert!(volume.required, "`__required__` defaults to true");
        assert!(volume.rest.is_empty(), "`__path__` is not rest");
        let memory = &c.storages[1];
        assert_eq!(memory.key_expr, "demo/memory/**");
        assert_eq!(memory.volume_id, "memory");
        assert_eq!(
            memory.volume_cfg, None,
            "the string form carries no payload"
        );
        assert!(!memory.complete);
        assert_eq!(memory.replication, None);
        assert!(c.required && c.backend_search_dirs.is_none() && c.rest.is_empty());
    }

    /// Upstream's own test, ported vector for vector:
    /// `plugins/zenoh-backend-traits/src/config.test.rs` @ `fn test_replica_config() {`.
    #[test]
    fn upstreams_replica_vectors_hold_here() {
        let empty =
            storage(r#"{ key_expr: "test/**", volume: "memory", replication: {} }"#).unwrap();
        assert_eq!(empty.replication, Some(ReplicaConfig::default()));

        let err = storage(
            r#"{ key_expr: "test/**", volume: "memory",
                 replication: { interval: 1, propagation_delay: 750 } }"#,
        )
        .unwrap_err();
        let expected = "consider increasing the `interval` to at least twice its value (i.e. 1.5)";
        assert!(
            alloc::format!("{err}").contains(expected),
            "wants {expected:?}, got {err}"
        );

        let full = storage(
            r#"{ key_expr: "test/**", volume: "memory",
                 replication: { interval: 10, sub_intervals: 4, hot: 6, warm: 60,
                                propagation_delay: 250 } }"#,
        )
        .unwrap();
        assert_eq!(
            full.replication,
            Some(ReplicaConfig {
                interval: Duration::from_secs(10),
                sub_intervals: 4,
                hot: 6,
                warm: 60,
                propagation_delay: Duration::from_millis(250),
            })
        );
    }

    /// The two upstream PANICS, refused here: a delay beyond the interval and a
    /// negative interval.
    #[test]
    fn what_panics_upstream_is_refused_here() {
        let beyond = storage(
            r#"{ key_expr: "k", volume: "memory",
                 replication: { interval: 1, propagation_delay: 1500 } }"#,
        );
        assert!(
            matches!(
                beyond,
                Err(PluginConfigError::PropagationDelayTooHigh { delay_ms: 1500, .. })
            ),
            "{beyond:?}"
        );
        let negative =
            storage(r#"{ key_expr: "k", volume: "memory", replication: { interval: -1 } }"#);
        assert!(
            matches!(
                negative,
                Err(PluginConfigError::StorageField {
                    field: "replication/interval",
                    ..
                })
            ),
            "{negative:?}"
        );
    }

    /// `null` is not an absence upstream, and each field's own arm decides
    /// what it means.
    #[test]
    fn a_present_null_means_what_each_upstream_arm_says() {
        let r = storage(r#"{ key_expr: "k", volume: "memory", replication: null }"#).unwrap();
        assert_eq!(
            r.replication,
            Some(ReplicaConfig::default()),
            "enables replication"
        );
        let g =
            storage(r#"{ key_expr: "k", volume: "memory", garbage_collection: null }"#).unwrap();
        assert_eq!(g.garbage_collection, GarbageCollectionConfig::default());
        for field in ["strip_prefix", "complete", "volume", "key_expr"] {
            let doc = alloc::format!(r#"{{ key_expr: "k", volume: "memory", {field}: null }}"#);
            assert!(storage(&doc).is_err(), "`{field}: null` is refused");
        }
    }

    /// Upstream reads the fields in a fixed order, so a document with two
    /// defects is refused for the one that code reaches first — here
    /// `complete`, whatever order the document wrote them in.
    #[test]
    fn the_first_refusal_is_upstreams_first_refusal() {
        let err = storage(
            r#"{ strip_prefix: "zzz", complete: "yes", volume: "memory", key_expr: "k/**" }"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, PluginConfigError::InvalidComplete { .. }),
            "{err:?}"
        );
    }

    /// `keyexpr::new` takes canon form only; it does not rewrite.
    #[test]
    fn key_expr_must_already_be_canon() {
        for ok in ["demo/**", "a/*/b", "a/b$*", "*/**", "a/**/b"] {
            assert!(
                storage(&alloc::format!(r#"{{ key_expr: "{ok}", volume: "m" }}"#)).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "", "a/", "/a", "a//b", "**/*", "a/**/**", "a/$*", "a/$*$*b", "a/*b", "a/#", "a?b",
        ] {
            let got = storage(&alloc::format!(r#"{{ key_expr: "{bad}", volume: "m" }}"#));
            assert!(
                matches!(got, Err(PluginConfigError::InvalidKeyExpr { .. })),
                "{bad:?} -> {got:?}"
            );
        }
        let not_text = storage(r#"{ key_expr: 5, volume: "m" }"#);
        assert!(matches!(
            not_text,
            Err(PluginConfigError::StorageField {
                field: "key_expr",
                ..
            })
        ));
    }

    /// Upstream's prefix test is on TEXT, then canon, then wildness.
    #[test]
    fn strip_prefix_is_upstreams_three_tests_in_upstreams_order() {
        let text_prefix =
            storage(r#"{ key_expr: "demo/abc/**", strip_prefix: "demo/ab", volume: "m" }"#);
        assert_eq!(
            text_prefix.unwrap().strip_prefix.as_deref(),
            Some("demo/ab")
        );
        assert!(matches!(
            storage(r#"{ key_expr: "demo/**", strip_prefix: "other", volume: "m" }"#),
            Err(PluginConfigError::StripPrefixNotAPrefix { .. })
        ));
        assert!(matches!(
            storage(r#"{ key_expr: "demo/x/**", strip_prefix: "demo/", volume: "m" }"#),
            Err(PluginConfigError::InvalidStripPrefix { .. })
        ));
        assert!(matches!(
            storage(r#"{ key_expr: "demo/*/x", strip_prefix: "demo/*", volume: "m" }"#),
            Err(PluginConfigError::WildStripPrefix { .. })
        ));
        assert!(matches!(
            storage(r#"{ key_expr: "demo/a$*/x", strip_prefix: "demo/a$*", volume: "m" }"#),
            Err(PluginConfigError::WildStripPrefix { .. })
        ));
    }

    #[test]
    fn complete_takes_a_boolean_or_its_two_spellings() {
        for (text, want) in [
            ("true", true),
            ("false", false),
            (r#""true""#, true),
            (r#""false""#, false),
        ] {
            let doc = alloc::format!(r#"{{ key_expr: "k", volume: "m", complete: {text} }}"#);
            assert_eq!(storage(&doc).unwrap().complete, want, "{text}");
        }
        assert!(matches!(
            storage(r#"{ key_expr: "k", volume: "m", complete: 1 }"#),
            Err(PluginConfigError::StorageField {
                field: "complete",
                ..
            })
        ));
    }

    #[test]
    fn volume_is_a_string_or_an_object_with_a_string_id() {
        let object =
            storage(r#"{ key_expr: "k", volume: { dir: "d", id: "fs", size: 3 } }"#).unwrap();
        assert_eq!(object.volume_id, "fs");
        assert_eq!(
            object.volume_cfg,
            Some(vec![
                (String::from("dir"), Json5Value::String("d".into())),
                (String::from("size"), Json5Value::Number("3".into())),
            ])
        );
        // An `id` that is not a string is DROPPED, and then there is none.
        for bad in [r#"{ dir: "d" }"#, r#"{ id: 7 }"#, "7", "[]"] {
            let doc = alloc::format!(r#"{{ key_expr: "k", volume: {bad} }}"#);
            assert!(
                matches!(
                    storage(&doc),
                    Err(PluginConfigError::StorageField {
                        field: "volume",
                        ..
                    })
                ),
                "{bad}"
            );
        }
        let missing = storage(r#"{ key_expr: "k" }"#);
        assert!(matches!(
            missing,
            Err(PluginConfigError::StorageField {
                field: "volume",
                ..
            })
        ));
    }

    /// `to_string().parse::<u64>()` upstream: an integer literal only.
    #[test]
    fn a_duration_field_takes_a_json_integer_and_nothing_else() {
        for (text, secs) in [("30", 30), ("+30", 30), ("0x1e", 30), ("0", 0)] {
            let doc = alloc::format!(
                r#"{{ key_expr: "k", volume: "m", garbage_collection: {{ period: {text} }} }}"#
            );
            assert_eq!(
                storage(&doc).unwrap().garbage_collection.period,
                Duration::from_secs(secs),
                "{text}"
            );
        }
        for text in ["30.0", "3e1", "-5", r#""30""#, "true", "[30]"] {
            let doc = alloc::format!(
                r#"{{ key_expr: "k", volume: "m", garbage_collection: {{ period: {text} }} }}"#
            );
            assert!(
                matches!(
                    storage(&doc),
                    Err(PluginConfigError::StorageField {
                        field: "garbage_collection/period",
                        ..
                    })
                ),
                "{text}"
            );
        }
        // A non-object block has no fields, so it yields the defaults.
        let scalar = storage(r#"{ key_expr: "k", volume: "m", garbage_collection: 5 }"#).unwrap();
        assert_eq!(
            scalar.garbage_collection,
            GarbageCollectionConfig::default()
        );
    }

    #[test]
    fn plugin_level_fields_are_typed_as_upstream_types_them() {
        let c = read(
            r#"{ __required__: false, backend_search_dirs: "/lib", __path__: "x.so", extra: 1 }"#,
        )
        .unwrap();
        assert!(!c.required);
        assert_eq!(c.backend_search_dirs, Some(vec![String::from("/lib")]));
        let rest: Vec<&str> = c.rest.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(rest, vec!["__path__", "extra"], "the rest, in name order");
        for (doc, field) in [
            ("{ __required__: 1 }", "__required__"),
            ("{ backend_search_dirs: [1] }", "backend_search_dirs"),
            ("{ backend_search_dirs: null }", "backend_search_dirs"),
            ("{ volumes: [] }", "volumes"),
            ("{ storages: null }", "storages"),
        ] {
            let got = read(doc);
            assert!(
                matches!(&got, Err(PluginConfigError::PluginField { field: f, .. }) if *f == field),
                "{doc} -> {got:?}"
            );
        }
        assert!(matches!(
            read("[]"),
            Err(PluginConfigError::NotAnObject { .. })
        ));
        assert!(matches!(
            read("{ volumes: { v: { backend: 1 } } }"),
            Err(PluginConfigError::VolumeField {
                field: "backend",
                ..
            })
        ));
        assert!(matches!(
            read("{ volumes: { v: 1 } }"),
            Err(PluginConfigError::VolumeNotAnObject { .. })
        ));
        assert!(matches!(
            read("{ storages: { s: 1 } }"),
            Err(PluginConfigError::StorageNotAnObject { .. })
        ));
    }

    /// Upstream's diff order, and a CHANGED storage as its delete and its add.
    #[test]
    fn the_diff_is_upstreams_four_groups_in_upstreams_order() {
        let old = read(
            r#"{ volumes: { gone: {}, kept: {} },
                 storages: { changed: { key_expr: "a/**", volume: "kept" },
                             dropped: { key_expr: "b/**", volume: "gone" },
                             same: { key_expr: "c/**", volume: "kept" } } }"#,
        )
        .unwrap();
        let new = read(
            r#"{ volumes: { kept: {}, fresh: {} },
                 storages: { same: { key_expr: "c/**", volume: "kept" },
                             changed: { key_expr: "a/x/**", volume: "kept" },
                             born: { key_expr: "d/**", volume: "fresh" } } }"#,
        )
        .unwrap();
        let diff = diffs(&old, &new);
        let steps: Vec<(&str, &str)> = diff
            .iter()
            .map(|d| match d {
                ConfigDiff::DeleteStorage(s) => ("DeleteStorage", s.name.as_str()),
                ConfigDiff::DeleteVolume(v) => ("DeleteVolume", v.name.as_str()),
                ConfigDiff::AddVolume(v) => ("AddVolume", v.name.as_str()),
                ConfigDiff::AddStorage(s) => ("AddStorage", s.name.as_str()),
            })
            .collect();
        assert_eq!(
            steps,
            vec![
                ("DeleteStorage", "changed"),
                ("DeleteStorage", "dropped"),
                ("DeleteVolume", "gone"),
                ("AddVolume", "fresh"),
                ("AddStorage", "born"),
                ("AddStorage", "changed"),
            ]
        );
        assert!(
            diffs(&new, &new).is_empty(),
            "a document does not differ from itself"
        );
        let from_nothing = diffs(&StoragePluginConfig::empty(STORAGE_MANAGER_PLUGIN), &new);
        assert_eq!(
            from_nothing.len(),
            5,
            "startup is the diff from the empty document"
        );
    }

    /// Equality is upstream's, and it decides whether a storage restarts. A
    /// payload rewritten in another key order, or with a key repeated, is the
    /// SAME storage; an integer and the float of its value are not.
    #[test]
    fn a_storage_restarts_exactly_when_upstream_would_restart_it() {
        let base = r#"{ key_expr: "k", volume: { id: "v", a: 1, b: { x: 1, y: 2 } } }"#;
        let same = [
            r#"{ volume: { b: { y: 2, x: 1 }, a: 1, id: "v" }, key_expr: "k" }"#,
            r#"{ key_expr: "k", volume: { id: "v", a: 9, a: 1, b: { x: 1, y: 2 } } }"#,
            r#"{ key_expr: "k", volume: { id: "v", a: 0x1, b: { x: 1, y: 2 } } }"#,
        ];
        let differs = [
            r#"{ key_expr: "k", volume: { id: "v", a: 1.0, b: { x: 1, y: 2 } } }"#,
            r#"{ key_expr: "k", volume: { id: "v", a: 1, b: { x: 1, y: 3 } } }"#,
            r#"{ key_expr: "k", volume: { id: "v", a: 1, b: { x: 1, y: 2 } }, replication: {} }"#,
            r#"{ key_expr: "k", volume: { id: "v", a: 1, b: { x: 1, y: 2 } }, complete: true }"#,
        ];
        let base = storage(base).unwrap();
        for doc in same {
            assert_eq!(storage(doc).unwrap(), base, "{doc}");
        }
        for doc in differs {
            assert_ne!(storage(doc).unwrap(), base, "{doc}");
        }
        // The string form and an object carrying only the id stay apart.
        assert_ne!(
            storage(r#"{ key_expr: "k", volume: "v" }"#).unwrap(),
            storage(r#"{ key_expr: "k", volume: { id: "v" } }"#).unwrap()
        );
    }

    /// A volume compares name, paths and rest — so `__required__` alone is no
    /// change, and `backend` is one because it stays in rest.
    #[test]
    fn a_volume_is_equal_on_upstreams_three_fields() {
        let v = |doc: &str| {
            read(&alloc::format!("{{ volumes: {{ v: {doc} }} }}"))
                .unwrap()
                .volumes[0]
                .clone()
        };
        assert_eq!(
            v("{ backend: \"fs\" }"),
            v("{ backend: \"fs\", __required__: false }")
        );
        assert_ne!(v("{ backend: \"fs\" }"), v("{ backend: \"mem\" }"));
        assert_ne!(v("{ __path__: \"a.so\" }"), v("{ __path__: \"b.so\" }"));
        assert_ne!(v("{ root: \"/a\" }"), v("{ root: \"/b\" }"));
    }

    #[test]
    fn a_declaration_becomes_the_storage_config_wz_drives() {
        let s = storage(
            r#"{ key_expr: "demo/x/**", strip_prefix: "demo/x", complete: true,
                 volume: { id: "fs", dir: "sub", size: 3 },
                 garbage_collection: { period: 5, lifespan: 60 } }"#,
        )
        .unwrap();
        let c = s.to_storage_config();
        assert_eq!(
            (c.name.as_str(), c.key_expr.as_str(), c.volume_id.as_str()),
            ("s", "demo/x/**", "fs")
        );
        assert!(c.complete);
        assert_eq!(c.strip_prefix.as_deref(), Some("demo/x"));
        assert_eq!(c.garbage_collection.period, Duration::from_secs(5));
        assert_eq!(c.garbage_collection.lifespan, Duration::from_secs(60));
        assert_eq!(
            c.volume_cfg,
            vec![
                (String::from("dir"), String::from("sub")),
                (String::from("size"), String::from("3"))
            ]
        );
    }
}
