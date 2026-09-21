// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2786 (§5.23 `adminspace-config-hotreload`) — the `plugins` section of a
//! node's config, and the two ways a RUNNING node's copy of it may change.
//!
//! ## Why this exists
//!
//! Upstream keeps `plugins` as ONE JSON object whose members are the plugins'
//! own documents (`commons/zenoh-config/src/lib.rs` @ `pub struct PluginsConfig {`),
//! and a config write below `plugins/` edits that object rather than a typed
//! field. Every write goes through a VALIDATOR first — the running plugin is
//! handed its old and its new document and may refuse — and every change that
//! lands is then announced to the NOTIFICATION plane, which starts and stops
//! whole plugins. That is how upstream hot-reloads a storage manager: its
//! validator diffs the two documents and applies the difference, and a refusal
//! leaves both the node and its config as they were.
//!
//! wz's config is a struct of typed fields, and `plugins` had no place in it,
//! so a write below `plugins/` could only be refused. This module is the place:
//! [`PluginsConfig`](crate::plugins_config::PluginsConfig) holds the section,
//! and its two write operations are
//! upstream's, step for step. What runs a plugin is not here — it is the
//! [`PluginsSink`](crate::plugins_config::PluginsSink) a host supplies, which
//! is the validator AND the notification
//! plane, because both are questions only the host that runs plugins can
//! answer.
//!
//! ## Upstream's semantics, read at the pin
//!
//! * INSERT (`commons/zenoh-config/src/lib.rs` @ `let new_value = value.clone().merge(key, new_value)?;`):
//!   the first key segment names the plugin; the rest is a path MERGED into
//!   that plugin's document by `commons/zenoh-config/src/lib.rs` @ `impl PartialMerge for serde_json::Value {`
//!   — an empty segment is skipped, a `null` on the path becomes an object
//!   (or an array, for `0` and `+`), `+` appends to an array, a number indexes
//!   one, and a scalar in the way is "not found". The merged document must be
//!   an object ("Attempt to provide non-object value as configuration for
//!   plugin"), and it is handed to the validator with the current one.
//! * REMOVE (`commons/zenoh-config/src/lib.rs` @ `pub fn remove(&mut self, key: &str) -> ZResult<()> {`):
//!   a key naming a WHOLE plugin removes it with no validator at all
//!   (`commons/zenoh-config/src/lib.rs` @ `self.values.as_object_mut().unwrap().remove(plugin);`),
//!   which is what lets the notification plane stop it. A deeper key walks the
//!   path WITHOUT skipping empty segments, refuses a step that names nothing,
//!   removes the last one, and asks the validator — below a plugin the section
//!   does not have, it is refused
//!   (`commons/zenoh-config/src/lib.rs` @ `None => bail!("No plugin {} to edit", plugin),`).
//!   The whole section cannot be deleted: upstream's remove takes only keys
//!   below `plugins/`
//!   (`commons/zenoh-config/src/lib.rs` @ `Removal of values from Config is only supported for keys starting with`).
//! * ORDER. Upstream's `Map` is a `BTreeMap` (its `serde_json` has no
//!   `preserve_order`), so every object here is held sorted with a repeated key
//!   keeping its last value — the shape
//!   [`PluginsConfig::from_section`](crate::plugins_config::PluginsConfig::from_section) and
//!   every write normalise to.
//!
//! ## Where wz departs, and why
//!
//! * A write that fails leaves NOTHING behind. Upstream inserts an empty entry
//!   for the plugin before the merge can fail and does not take it back, and a
//!   later `load_requests` then panics on that entry ("Plugin configurations
//!   must be objects"). Here the new section is computed first and stored only
//!   once everything has accepted it.
//! * A write of the WHOLE section asks the validator about every plugin whose
//!   document it changes. Upstream replaces the section by deserialising a new
//!   one, which skips the validator and also drops the validator hook for every
//!   later write; a running storage manager would then go on serving the
//!   storages the section no longer names.
//! * The validator is told the path BELOW the plugin. Upstream's remove slices
//!   its key at an offset that counts the `plugins/` prefix twice, so the path
//!   it passes is a suffix of the right one — or a panic, for a key shorter
//!   than that offset.

use std::collections::BTreeMap;

use wz_session_core::json5::Json5Value;

/// The host side of the `plugins` section: the validator a write must pass and
/// the notification plane a landed change is announced to.
///
/// One trait for both because upstream's two halves are held by the same
/// runtime (the running plugins), and a host that can answer one can answer the
/// other. Methods take `&self`, as every sink in `config.rs` does; a host whose
/// plugins are mutable state holds them behind interior mutability.
pub trait PluginsSink {
    /// Upstream's `ConfigValidator::check_config`: may `plugin`'s document
    /// change from `current` to `new`? `path` is the part of the write key
    /// below the plugin (`""` for the whole document).
    ///
    /// `Ok(None)` accepts `new` as it is, `Ok(Some(doc))` accepts it replaced
    /// by `doc`, and `Err(reason)` refuses the write — the section and every
    /// plugin stay as they were. A plugin this host is not running has nothing
    /// to check, and upstream accepts any document for it.
    fn check_config(
        &self,
        plugin: &str,
        path: &str,
        current: &Json5Value,
        new: &Json5Value,
    ) -> Result<Option<Json5Value>, String>;

    /// Upstream's notification plane: the section changed and now reads
    /// `plugins`. Called once per landed write, never for a refused one.
    fn plugins_changed(&self, plugins: &PluginsConfig);
}

/// Why a write to the `plugins` section was refused.
#[derive(Debug, Clone, PartialEq)]
pub enum PluginsConfigError {
    /// A step of the key names nothing: a scalar in the way, an array index
    /// that is not a number or is past the end, or — on a remove — an object
    /// with no such member.
    PathNotFound {
        /// The key below `plugins/`, as written.
        path: String,
    },
    /// The plugin's document would not be an object.
    NotAnObject {
        /// The plugin.
        plugin: String,
    },
    /// A remove below a plugin the section does not configure.
    NoSuchPlugin {
        /// The plugin.
        plugin: String,
    },
    /// The section as a whole is not an object whose members are objects.
    NotASection,
    /// The whole section was asked to be deleted.
    SectionNotRemovable,
    /// The plugin's validator refused the change, in its own words.
    Refused {
        /// The plugin.
        plugin: String,
        /// What it said.
        reason: String,
    },
}

/// The `plugins` section: each plugin's document, by plugin name.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PluginsConfig {
    plugins: BTreeMap<String, Json5Value>,
}

impl PluginsConfig {
    /// An empty section — a node whose config names no plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// The section a config document states: an object whose members are
    /// objects, which is what upstream's loader demands of it.
    pub fn from_section(section: &Json5Value) -> Result<Self, PluginsConfigError> {
        let Json5Value::Object(entries) = section else {
            return Err(PluginsConfigError::NotASection);
        };
        let mut plugins = BTreeMap::new();
        for (name, doc) in entries {
            if !matches!(doc, Json5Value::Object(_)) {
                return Err(PluginsConfigError::NotASection);
            }
            plugins.insert(name.clone(), normalise(doc.clone()));
        }
        Ok(Self { plugins })
    }

    /// The section as one object, plugins in name order.
    pub fn section(&self) -> Json5Value {
        Json5Value::Object(
            self.plugins
                .iter()
                .map(|(name, doc)| (name.clone(), doc.clone()))
                .collect(),
        )
    }

    /// `plugin`'s document, when the section configures it.
    pub fn plugin(&self, plugin: &str) -> Option<&Json5Value> {
        self.plugins.get(plugin)
    }

    /// The plugins the section configures, in name order.
    pub fn plugin_names(&self) -> impl Iterator<Item = &str> {
        self.plugins.keys().map(String::as_str)
    }

    /// Write `value` at `key` (the part below `plugins/`), as upstream's
    /// insert does — see the module doc.
    pub fn insert(
        &mut self,
        key: &str,
        value: Json5Value,
        validator: &dyn PluginsSink,
    ) -> Result<(), PluginsConfigError> {
        let (plugin, path) = key.split_once('/').unwrap_or((key, ""));
        if plugin.is_empty() {
            return Err(PluginsConfigError::PathNotFound {
                path: String::from(key),
            });
        }
        let current = self
            .plugins
            .get(plugin)
            .cloned()
            .unwrap_or(Json5Value::Null);
        let merged = merge(current.clone(), path, normalise(value)).ok_or_else(|| {
            PluginsConfigError::PathNotFound {
                path: String::from(key),
            }
        })?;
        let accepted = self.validate(plugin, path, current, merged, validator)?;
        self.plugins.insert(String::from(plugin), accepted);
        Ok(())
    }

    /// Remove `key` (the part below `plugins/`), as upstream's remove does —
    /// see the module doc.
    pub fn remove(
        &mut self,
        key: &str,
        validator: &dyn PluginsSink,
    ) -> Result<(), PluginsConfigError> {
        let mut steps = key.split('/');
        let plugin = steps.next().unwrap_or_default();
        let Some(first) = steps.next() else {
            // A whole plugin: no validator, and an absent one is no error.
            self.plugins.remove(plugin);
            return Ok(());
        };
        let Some(current) = self.plugins.get(plugin).cloned() else {
            return Err(PluginsConfigError::NoSuchPlugin {
                plugin: String::from(plugin),
            });
        };
        let mut updated = current.clone();
        remove_at(&mut updated, first, steps).ok_or_else(|| PluginsConfigError::PathNotFound {
            path: String::from(key),
        })?;
        let path = &key[plugin.len() + 1..];
        let accepted = self.validate(plugin, path, current, updated, validator)?;
        self.plugins.insert(String::from(plugin), accepted);
        Ok(())
    }

    /// Replace the whole section with `section`, asking the validator about
    /// every plugin whose document changes — see the module doc for why this
    /// is stricter than upstream. A plugin the new section drops is removed as
    /// a whole-plugin remove is: without a validator.
    pub fn replace(
        &mut self,
        section: &Json5Value,
        validator: &dyn PluginsSink,
    ) -> Result<(), PluginsConfigError> {
        let proposed = Self::from_section(section)?;
        let mut accepted = BTreeMap::new();
        for (plugin, new) in proposed.plugins {
            let current = self
                .plugins
                .get(&plugin)
                .cloned()
                .unwrap_or(Json5Value::Null);
            let doc = if current == new {
                new
            } else {
                self.validate(&plugin, "", current, new, validator)?
            };
            accepted.insert(plugin, doc);
        }
        self.plugins = accepted;
        Ok(())
    }

    /// Hand `plugin`'s change to the validator and return the document that
    /// is to be stored.
    fn validate(
        &self,
        plugin: &str,
        path: &str,
        current: Json5Value,
        new: Json5Value,
        validator: &dyn PluginsSink,
    ) -> Result<Json5Value, PluginsConfigError> {
        let not_an_object = || PluginsConfigError::NotAnObject {
            plugin: String::from(plugin),
        };
        if !matches!(new, Json5Value::Object(_)) {
            return Err(not_an_object());
        }
        // A plugin the section did not configure is checked against an empty
        // document, upstream's `unwrap_or(&empty_config)`.
        let current = match current {
            doc @ Json5Value::Object(_) => doc,
            _ => Json5Value::Object(Vec::new()),
        };
        match validator.check_config(plugin, path, &current, &new) {
            Ok(None) => Ok(new),
            Ok(Some(doc @ Json5Value::Object(_))) => Ok(normalise(doc)),
            Ok(Some(_)) => Err(not_an_object()),
            Err(reason) => Err(PluginsConfigError::Refused {
                plugin: String::from(plugin),
                reason,
            }),
        }
    }
}

/// `value` with every object sorted by key and a repeated key keeping its last
/// value — upstream's `BTreeMap`, applied all the way down.
fn normalise(value: Json5Value) -> Json5Value {
    match value {
        Json5Value::Object(entries) => {
            let map: BTreeMap<String, Json5Value> = entries.into_iter().collect();
            Json5Value::Object(map.into_iter().map(|(k, v)| (k, normalise(v))).collect())
        }
        Json5Value::Array(items) => Json5Value::Array(items.into_iter().map(normalise).collect()),
        other => other,
    }
}

/// Upstream's `PartialMerge::merge`: `new` placed at `path` in `root`, or
/// `None` when a step of the path names nothing. `root` and `new` are already
/// normalised, and every object created or entered here stays sorted.
fn merge(mut root: Json5Value, path: &str, new: Json5Value) -> Option<Json5Value> {
    let mut slot = &mut root;
    let mut key = path;
    while !key.is_empty() {
        let (current, rest) = key.split_once('/').unwrap_or((key, ""));
        key = rest;
        if current.is_empty() {
            continue;
        }
        slot = match slot {
            Json5Value::Bool(_) | Json5Value::Number(_) | Json5Value::String(_) => return None,
            Json5Value::Null => {
                if current == "0" || current == "+" {
                    *slot = Json5Value::Array(vec![Json5Value::Null]);
                    match slot {
                        Json5Value::Array(items) => &mut items[0],
                        _ => unreachable!("just made an array"),
                    }
                } else {
                    *slot = Json5Value::Object(vec![(String::from(current), Json5Value::Null)]);
                    match slot {
                        Json5Value::Object(entries) => &mut entries[0].1,
                        _ => unreachable!("just made an object"),
                    }
                }
            }
            Json5Value::Array(items) => match current {
                "+" => {
                    items.push(Json5Value::Null);
                    items.last_mut()?
                }
                "0" if items.is_empty() => {
                    items.push(Json5Value::Null);
                    items.last_mut()?
                }
                _ => items.get_mut(current.parse::<usize>().ok()?)?,
            },
            Json5Value::Object(entries) => {
                let at = match entries.binary_search_by(|(k, _)| k.as_str().cmp(current)) {
                    Ok(at) => at,
                    Err(at) => {
                        entries.insert(at, (String::from(current), Json5Value::Null));
                        at
                    }
                };
                &mut entries[at].1
            }
        };
    }
    *slot = new;
    Some(root)
}

/// Upstream's remove walk: every step must name something, empty ones
/// included, and the last is removed. `None` when a step names nothing.
fn remove_at<'k>(
    root: &mut Json5Value,
    first: &'k str,
    rest: impl Iterator<Item = &'k str>,
) -> Option<()> {
    let mut current = first;
    let mut slot = root;
    for next in rest {
        slot = match slot {
            Json5Value::Object(entries) => {
                let at = entries.iter().position(|(k, _)| k == current)?;
                &mut entries[at].1
            }
            Json5Value::Array(items) => items.get_mut(current.parse::<usize>().ok()?)?,
            _ => return None,
        };
        current = next;
    }
    match slot {
        Json5Value::Object(entries) => {
            let at = entries.iter().position(|(k, _)| k == current)?;
            entries.remove(at);
        }
        Json5Value::Array(items) => {
            let at = current.parse::<usize>().ok()?;
            if at >= items.len() {
                return None;
            }
            items.remove(at);
        }
        _ => return None,
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use wz_session_core::json5::parse;

    /// A validator that records what it was asked and answers from a script.
    #[derive(Default)]
    struct Recorder {
        asked: RefCell<Vec<(String, String, String, String)>>,
        answer: RefCell<Option<Result<Option<Json5Value>, String>>>,
        notified: RefCell<usize>,
    }

    impl PluginsSink for Recorder {
        fn check_config(
            &self,
            plugin: &str,
            path: &str,
            current: &Json5Value,
            new: &Json5Value,
        ) -> Result<Option<Json5Value>, String> {
            self.asked.borrow_mut().push((
                plugin.into(),
                path.into(),
                current.to_json5_text(),
                new.to_json5_text(),
            ));
            self.answer.borrow().clone().unwrap_or(Ok(None))
        }

        fn plugins_changed(&self, _: &PluginsConfig) {
            *self.notified.borrow_mut() += 1;
        }
    }

    fn doc(text: &str) -> Json5Value {
        parse(text).expect("json5")
    }

    fn text(plugins: &PluginsConfig) -> String {
        plugins.section().to_json5_text()
    }

    #[test]
    fn an_insert_builds_its_path_and_hands_both_documents_to_the_validator() {
        let v = Recorder::default();
        let mut p = PluginsConfig::new();
        p.insert(
            "storage_manager/storages/demo",
            doc(r#"{ key_expr: "d/**", volume: "memory" }"#),
            &v,
        )
        .unwrap();
        assert_eq!(
            p.plugin("storage_manager").map(Json5Value::to_json5_text),
            Some(
                doc(r#"{ storages: { demo: { key_expr: "d/**", volume: "memory" } } }"#)
                    .to_json5_text()
            )
        );
        let asked = v.asked.borrow();
        assert_eq!(asked.len(), 1);
        assert_eq!(
            (asked[0].0.as_str(), asked[0].1.as_str()),
            ("storage_manager", "storages/demo")
        );
        assert_eq!(
            asked[0].2, "{}",
            "a plugin the section lacked is checked against an empty document"
        );
    }

    #[test]
    fn a_refusal_leaves_the_section_exactly_as_it_was() {
        let v = Recorder::default();
        let mut p =
            PluginsConfig::from_section(&doc("{ storage_manager: { storages: {} } }")).unwrap();
        let before = p.clone();
        *v.answer.borrow_mut() = Some(Err(String::from("no such volume")));
        let err = p
            .insert("storage_manager/storages/demo", doc("{}"), &v)
            .unwrap_err();
        assert_eq!(
            err,
            PluginsConfigError::Refused {
                plugin: String::from("storage_manager"),
                reason: String::from("no such volume"),
            }
        );
        assert_eq!(p, before);
        // A refused write to a plugin the section did NOT have leaves no stray
        // entry either — the one upstream leaves behind.
        let err = p.insert("rest/http_port", doc("8000"), &v).unwrap_err();
        assert!(matches!(err, PluginsConfigError::Refused { .. }));
        assert_eq!(p, before);
    }

    #[test]
    fn the_validator_may_replace_what_is_stored() {
        let v = Recorder::default();
        *v.answer.borrow_mut() = Some(Ok(Some(doc("{ b: 2, a: 1 }"))));
        let mut p = PluginsConfig::new();
        p.insert("x/k", doc("1"), &v).unwrap();
        assert_eq!(
            p.plugin("x").map(Json5Value::to_json5_text),
            Some(doc("{ a: 1, b: 2 }").to_json5_text())
        );
    }

    /// Upstream's merge through arrays and scalars.
    #[test]
    fn the_merge_walks_arrays_and_refuses_a_scalar_in_the_way() {
        let v = Recorder::default();
        let mut p =
            PluginsConfig::from_section(&doc(r#"{ x: { list: [1, 2], s: "text" } }"#)).unwrap();
        p.insert("x/list/+", doc("3"), &v).unwrap();
        p.insert("x/list/0", doc("9"), &v).unwrap();
        p.insert("x/fresh/0", doc("7"), &v).unwrap();
        p.insert("x//nested//deep", doc("true"), &v).unwrap();
        assert_eq!(
            p.plugin("x").map(Json5Value::to_json5_text),
            Some(
                doc(r#"{ fresh: [7], list: [9, 2, 3], nested: { deep: true }, s: "text" }"#)
                    .to_json5_text()
            )
        );
        for bad in ["x/list/5", "x/list/k", "x/s/inner"] {
            assert_eq!(
                p.insert(bad, doc("0"), &v),
                Err(PluginsConfigError::PathNotFound {
                    path: String::from(bad)
                }),
                "{bad}"
            );
        }
        assert_eq!(
            p.insert("x", doc("5"), &v),
            Err(PluginsConfigError::NotAnObject {
                plugin: String::from("x")
            })
        );
    }

    #[test]
    fn removing_a_whole_plugin_asks_no_validator_and_an_absent_one_is_no_error() {
        let v = Recorder::default();
        let mut p = PluginsConfig::from_section(&doc("{ a: {}, b: {} }")).unwrap();
        p.remove("a", &v).unwrap();
        p.remove("never", &v).unwrap();
        assert_eq!(p.plugin_names().collect::<Vec<_>>(), vec!["b"]);
        assert!(v.asked.borrow().is_empty());
    }

    #[test]
    fn removing_below_a_plugin_walks_every_step_and_asks_the_validator() {
        let v = Recorder::default();
        let mut p = PluginsConfig::from_section(&doc(
            "{ sm: { storages: { a: {}, b: {} }, list: [1, 2, 3] } }",
        ))
        .unwrap();
        p.remove("sm/storages/a", &v).unwrap();
        p.remove("sm/list/1", &v).unwrap();
        assert_eq!(
            text(&p),
            doc("{ sm: { list: [1, 3], storages: { b: {} } } }").to_json5_text()
        );
        let asked = v.asked.borrow();
        assert_eq!(asked[0].1, "storages/a", "the path BELOW the plugin");
        assert_eq!(asked[1].1, "list/1");
        drop(asked);
        for bad in ["sm/storages/zz", "sm/list/9", "sm//storages"] {
            assert_eq!(
                p.remove(bad, &v),
                Err(PluginsConfigError::PathNotFound {
                    path: String::from(bad)
                }),
                "{bad}"
            );
        }
        assert_eq!(
            p.remove("nope/x", &v),
            Err(PluginsConfigError::NoSuchPlugin {
                plugin: String::from("nope")
            })
        );
    }

    #[test]
    fn replacing_the_section_asks_about_every_changed_plugin_and_no_other() {
        let v = Recorder::default();
        let mut p =
            PluginsConfig::from_section(&doc("{ same: { k: 1 }, changed: { k: 1 }, dropped: {} }"))
                .unwrap();
        p.replace(&doc("{ same: { k: 1 }, changed: { k: 2 }, fresh: {} }"), &v)
            .unwrap();
        let asked: Vec<String> = v.asked.borrow().iter().map(|a| a.0.clone()).collect();
        assert_eq!(asked, vec!["changed", "fresh"]);
        assert_eq!(
            p.plugin_names().collect::<Vec<_>>(),
            vec!["changed", "fresh", "same"]
        );
        let before = p.clone();
        *v.answer.borrow_mut() = Some(Err(String::from("no")));
        assert!(p.replace(&doc("{ same: { k: 3 } }"), &v).is_err());
        assert_eq!(p, before, "one refusal refuses the whole section");
        assert_eq!(
            p.replace(&doc("{ a: 1 }"), &v),
            Err(PluginsConfigError::NotASection)
        );
        assert_eq!(
            p.replace(&doc("[]"), &v),
            Err(PluginsConfigError::NotASection)
        );
    }

    /// The stored section is upstream's shape: sorted, the last of a repeated
    /// key kept, all the way down.
    #[test]
    fn the_section_is_held_as_upstreams_map_holds_it() {
        let p =
            PluginsConfig::from_section(&doc("{ z: { b: 1, a: { d: 1, c: 2, d: 3 } }, y: {} }"))
                .unwrap();
        assert_eq!(
            text(&p),
            doc("{ y: {}, z: { a: { c: 2, d: 3 }, b: 1 } }").to_json5_text()
        );
    }
}
