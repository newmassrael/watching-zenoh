// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2820 (§5.23 `adminspace-config-hotreload`) — the NOTIFICATION PLANE for
//! the plugins this node loads from a library: a change to the `plugins`
//! section starts, stops and restarts them.
//!
//! ## What upstream does, read at the pin
//!
//! Upstream subscribes to its own config and, on every change below
//! `plugins`, compares the plugins the section now asks for with the ones it
//! is running (`zenoh/src/net/runtime/adminspace.rs` @ `let cfg_rx = admin.context.runtime.state.config.subscribe();`):
//!
//! * a running plugin the section no longer names is DELETED — stopped, not
//!   unloaded;
//! * a requested plugin that is running is left alone when the request names
//!   no path or names the one it runs from, and is otherwise deleted and
//!   started again;
//! * every other request is STARTED: declared by its paths (the first that
//!   loads) or by name, loaded, and started, each step reusing what an
//!   earlier start left behind (`zenoh/src/net/runtime/adminspace.rs` @ `fn start_plugin(`).
//!
//! A failed start is logged, or is fatal when the plugin is `__required__`.
//! Its VALIDATOR half is the other rule this module carries: a write below a
//! plugin that is running reaches that plugin's `config_checker`, whose
//! default refuses (`zenoh/src/api/plugins.rs` @ `bail!("Runtime configuration change not supported");`)
//! — so a running plugin is reconfigured by removing it and adding it back,
//! not by editing it in place.
//!
//! ## Where wz departs, and why
//!
//! * The plugins it STARTS are recorded as running. Upstream builds its
//!   running set once, from the plugins started before the plane began, and
//!   never adds the ones the plane itself starts — so a plugin started by a
//!   config write is never stopped by the next one, and is started again by
//!   every change that still names it. Here a start the plane made is a
//!   plugin the plane runs.
//! * A request with no `__path__` is upstream's by-name lookup, which
//!   `plugins_loading/enabled` switches ([`PluginsLoading`]). Switched off, the
//!   plugin is left unloaded with upstream's warning and fails nothing, as
//!   upstream's empty loader leaves it. Switched on, it is searched for in
//!   `plugins_loading/search_dirs` ([`crate::plugin_search_dirs`]), as a zenohd
//!   searches for it, under wz's plugin prefix rather than upstream's.
//! * A `__required__` plugin that fails to start is REPORTED as required
//!   rather than panicking inside the plane; the host decides. Upstream's
//!   panic lands in the task that runs its plane.
//! * The ABI carries no `config_checker`, so every running library plugin
//!   answers the one way upstream's default answers: it refuses.
//! * A changed `__path__` cannot swap a loaded library in process — nothing
//!   is ever unloaded (see [`crate::plugin`]'s module doc). The restart is
//!   the library already loaded, as upstream's "already loaded" reuse is, and
//!   the report says the new path was not loaded.
//!
//! Plugins a host composes at build time (the storage manager) are not this
//! plane's: they have their own sink, and a request naming one is skipped.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use wz_admin::adminspace::{AdminPlugin, AdminPluginState};
use wz_session_core::json5::Json5Value;
use wz_storage::storage_plugin_config::STORAGE_MANAGER_PLUGIN;

use crate::plugin::PluginRegistry;
use crate::plugin_search_dirs::LibSearchDirs;
use crate::plugins_config::{PluginLoadRequest, PluginsConfig, PluginsSink};

/// Something a change made happen, or failed to, that refused no write:
/// upstream logs these and runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginPlaneReport {
    /// The plugin, by its key in the section.
    pub plugin: String,
    /// `__required__`: upstream treats this report's failure as fatal.
    pub required: bool,
    /// What happened, in words a log line can carry.
    pub message: String,
}

/// One step of a change, upstream's `PluginDiff`.
#[derive(Debug)]
enum PluginDiff {
    Delete(String),
    Start(PluginLoadRequest),
}

/// Whether a plugin the section asks for by NAME (no `__path__`) is looked up:
/// upstream's `plugins_loading/enabled`.
///
/// Upstream's plugin manager is built over the config's library loader, which
/// is EMPTY when the key is off (`commons/zenoh-config/src/lib.rs` @ `LibLoader::empty()`);
/// a by-name lookup on an empty loader finds nothing and the plugin is left
/// unloaded with a warning, never a failure
/// (`plugins/zenoh-plugin-trait/src/manager/dynamic_plugin.rs` @ `will not be loaded as plugin loading is disabled",`).
/// A plugin named by path loads either way.
///
/// The two defaults differ, and which one a host takes is the host's: a
/// library session's config leaves the key off (`Config::default()`), while
/// zenohd turns it on over whatever its file says
/// (`zenohd/src/main.rs` @ `config.plugins_loading.set_enabled(true).unwrap();`).
/// [`Self::from_config`] is the library's reading, which is what a host the
/// file configures takes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PluginsLoading {
    /// The key off: a by-name request is left unloaded with upstream's warning.
    #[default]
    Disabled,
    /// The key on: a by-name request is searched for in `plugins_loading/search_dirs`.
    Enabled,
}

impl PluginsLoading {
    /// The library's reading of `plugins_loading/enabled`: on only when the
    /// file states `true`.
    pub fn from_config(stated: Option<bool>) -> Self {
        if stated == Some(true) {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }
}

/// The library plugins a node runs, and the plane that keeps them matching
/// its `plugins` section.
#[derive(Debug)]
pub struct DynamicPluginPlane {
    registry: PluginRegistry,
    /// Upstream's `active_plugins`: every plugin this plane runs, by its key
    /// in the section, with the path it runs from.
    active: BTreeMap<String, PathBuf>,
    /// Keys a build-time subsystem owns; never started here.
    composed: BTreeSet<String>,
    /// Whether a by-name request is looked up.
    loading: PluginsLoading,
    /// Where a by-name request is searched for.
    search_dirs: LibSearchDirs,
}

impl DynamicPluginPlane {
    /// A plane running nothing, looking plugins up by name as `loading` says, in upstream's
    /// default directories until [`Self::set_search_dirs`] names others.
    ///
    /// It leaves the storage manager to the subsystem composed into this
    /// build: the feature that compiles this module also compiles the storage
    /// manager's own sink, and a library by that name would be upstream's
    /// plugin, which no wz ABI can load.
    pub fn new(loading: PluginsLoading) -> Self {
        Self {
            registry: PluginRegistry::new(),
            active: BTreeMap::new(),
            composed: BTreeSet::from([String::from(STORAGE_MANAGER_PLUGIN)]),
            loading,
            search_dirs: LibSearchDirs::default(),
        }
    }

    /// Search `dirs` for a request that names no `__path__`: the node's
    /// `plugins_loading/search_dirs`. Every later start searches them.
    pub fn set_search_dirs(&mut self, dirs: LibSearchDirs) {
        self.search_dirs = dirs;
    }

    /// The directories a request naming no `__path__` is searched for in.
    pub fn search_dirs(&self) -> &LibSearchDirs {
        &self.search_dirs
    }

    /// The registry, for plugins a host loads OUTSIDE the section (a
    /// command-line path): they share the admin records and the library
    /// lifetime, and no section change stops them.
    pub fn registry_mut(&mut self) -> &mut PluginRegistry {
        &mut self.registry
    }

    /// Every plugin's admin record, section-run or not.
    pub fn admin_records(&self) -> Vec<AdminPlugin> {
        self.registry.admin_records()
    }

    /// Upstream's `Running plugins` log: the plugins the section has this
    /// plane running, in key order.
    pub fn running(&self) -> impl Iterator<Item = &str> {
        self.active.keys().map(String::as_str)
    }

    /// The validator half; see the module doc. A plugin a composed subsystem
    /// owns is not this plane's to judge.
    pub fn check_config(
        &self,
        plugin: &str,
        new: &Json5Value,
    ) -> Result<Option<Json5Value>, String> {
        if self.composed.contains(plugin) {
            return Ok(None);
        }
        PluginLoadRequest::from_document(plugin, new)?;
        if self.registry.state(plugin) == Some(AdminPluginState::Started) {
            return Err(String::from("Runtime configuration change not supported"));
        }
        Ok(None)
    }

    /// The notification half: bring the running plugins to what `plugins`
    /// asks for, in upstream's order — every delete, then every start.
    pub fn apply(&mut self, plugins: &PluginsConfig) -> Vec<PluginPlaneReport> {
        let mut reports = Vec::new();
        let mut requests = Vec::new();
        for id in plugins.plugin_names() {
            if self.composed.contains(id) {
                continue;
            }
            let Some(document) = plugins.plugin(id) else {
                continue;
            };
            match PluginLoadRequest::from_document(id, document) {
                Ok(request) => requests.push(request),
                // Only a section that never met a validator carries one of
                // these (a startup document); it starts nothing.
                Err(message) => reports.push(PluginPlaneReport {
                    plugin: String::from(id),
                    required: false,
                    message,
                }),
            }
        }

        let mut diffs = Vec::new();
        for running in self.active.keys() {
            if !requests.iter().any(|r| &r.id == running) {
                diffs.push(PluginDiff::Delete(running.clone()));
            }
        }
        for request in requests {
            if let Some(path) = self.active.get(&request.id) {
                let unchanged = match request.paths.as_ref() {
                    None => true,
                    Some(paths) => paths.iter().any(|p| std::path::Path::new(p) == path),
                };
                if unchanged {
                    continue;
                }
                diffs.push(PluginDiff::Delete(request.id.clone()));
            }
            diffs.push(PluginDiff::Start(request));
        }

        for diff in diffs {
            match diff {
                PluginDiff::Delete(id) => {
                    self.active.remove(&id);
                    if let Err(e) = self.registry.stop(&id) {
                        reports.push(PluginPlaneReport {
                            plugin: id,
                            required: false,
                            message: e.to_string(),
                        });
                    }
                }
                PluginDiff::Start(request) => {
                    let document = plugins.plugin(&request.id).cloned();
                    if let Err(message) = self.start(&request, document.as_ref(), &mut reports) {
                        reports.push(PluginPlaneReport {
                            plugin: request.id.clone(),
                            required: request.required,
                            message: format!("Failed to load plugin `{}`: {message}", request.id),
                        });
                    }
                }
            }
        }
        reports
    }

    /// Upstream's `start_plugin`: declare, load and start, reusing each step
    /// an earlier start left behind. On success the plugin is running.
    fn start(
        &mut self,
        request: &PluginLoadRequest,
        document: Option<&Json5Value>,
        reports: &mut Vec<PluginPlaneReport>,
    ) -> Result<(), String> {
        let paths: Vec<PathBuf> = match (request.paths.as_ref(), self.loading) {
            (Some(paths), _) => paths.iter().map(PathBuf::from).collect(),
            // Upstream's empty loader: the lookup finds nothing, the plugin is
            // not started, and nothing fails, `__required__` or not.
            (None, PluginsLoading::Disabled) => {
                reports.push(PluginPlaneReport {
                    plugin: request.id.clone(),
                    required: false,
                    message: format!(
                        "Plugin `{}` will not be loaded as plugin loading is disabled",
                        request.name
                    ),
                });
                return Ok(());
            }
            // Upstream declares a plugin by name before it looks for it, so one
            // that is not found stays declared.
            (None, PluginsLoading::Enabled) => match self.search_dirs.find_plugin(&request.name) {
                Ok(path) => vec![path],
                Err(why) => {
                    self.registry.declare_unfound(&request.id, why.clone());
                    return Err(why);
                }
            },
        };
        let was_live = matches!(
            self.registry.state(&request.id),
            Some(AdminPluginState::Loaded | AdminPluginState::Started)
        );
        self.registry
            .load_first(&request.id, &paths)
            .map_err(|e| e.to_string())?;
        let path = self
            .registry
            .path(&request.id)
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        if was_live && !paths.contains(&path) {
            reports.push(PluginPlaneReport {
                plugin: request.id.clone(),
                required: false,
                message: format!(
                    "`__path__` now names {paths:?}, but a loaded library is never \
                     replaced in process; restarting the one loaded from {}",
                    path.display()
                ),
            });
        }
        if self.registry.state(&request.id) != Some(AdminPluginState::Started) {
            let config = document.map(Json5Value::to_json_text);
            self.registry
                .start(&request.id, config.as_deref())
                .map_err(|e| e.to_string())?;
        }
        self.active.insert(request.id.clone(), path);
        Ok(())
    }
}

impl Default for DynamicPluginPlane {
    /// The library's plane: by-name lookup off, as a config that states nothing leaves it.
    fn default() -> Self {
        Self::new(PluginsLoading::default())
    }
}

/// The plane as a [`PluginsSink`], borrowed for the one write it serves.
///
/// What a start could not do refuses nothing, so it is kept for the host to
/// log or act on ([`Self::take_reports`]).
pub struct DynamicPluginSink<'a> {
    plane: core::cell::RefCell<&'a mut DynamicPluginPlane>,
    reports: core::cell::RefCell<Vec<PluginPlaneReport>>,
}

impl<'a> DynamicPluginSink<'a> {
    /// A sink over `plane`.
    pub fn new(plane: &'a mut DynamicPluginPlane) -> Self {
        Self {
            plane: core::cell::RefCell::new(plane),
            reports: core::cell::RefCell::new(Vec::new()),
        }
    }

    /// The reports the notification produced.
    pub fn take_reports(&self) -> Vec<PluginPlaneReport> {
        core::mem::take(&mut *self.reports.borrow_mut())
    }
}

impl PluginsSink for DynamicPluginSink<'_> {
    fn check_config(
        &self,
        plugin: &str,
        _path: &str,
        _current: &Json5Value,
        new: &Json5Value,
    ) -> Result<Option<Json5Value>, String> {
        self.plane.borrow().check_config(plugin, new)
    }

    fn plugins_changed(&self, plugins: &PluginsConfig) {
        let reports = self.plane.borrow_mut().apply(plugins);
        self.reports.borrow_mut().extend(reports);
    }
}

/// Several sinks as one: each plugin belongs to at most one of them, and a
/// sink answers `Ok(None)` for a plugin that is not its own.
///
/// So the validator asks each in turn and the first that refuses or replaces
/// the document decides; the notification reaches all of them.
pub struct PluginsSinks<'a>(pub &'a [&'a dyn PluginsSink]);

impl PluginsSink for PluginsSinks<'_> {
    fn check_config(
        &self,
        plugin: &str,
        path: &str,
        current: &Json5Value,
        new: &Json5Value,
    ) -> Result<Option<Json5Value>, String> {
        for sink in self.0 {
            if let Some(doc) = sink.check_config(plugin, path, current, new)? {
                return Ok(Some(doc));
            }
        }
        Ok(None)
    }

    fn plugins_changed(&self, plugins: &PluginsConfig) {
        for sink in self.0 {
            sink.plugins_changed(plugins);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::json5::parse;

    /// The example plugin's library, built by Layer C1bp before these run. Its
    /// absence is a skip where nobody owes it and a failure under that lane's
    /// `WZ_EXAMPLE_CDYLIB_REQUIRE` (open-debt item 776).
    fn example_so() -> Option<PathBuf> {
        crate::built_fixture::built_or_skip(
            crate::built_fixture::cdylib("wz_plugin_example"),
            "run `cargo build -p wz-plugin-example` (Layer C1bp does)",
        )
    }

    fn section(text: &str) -> PluginsConfig {
        PluginsConfig::from_section(&parse(text).expect("json5")).expect("a section")
    }

    fn state(plane: &DynamicPluginPlane, id: &str) -> Option<AdminPluginState> {
        plane.registry.state(id)
    }

    /// The whole life of a section-run plugin: appearing starts it, a change
    /// that keeps its path leaves it running, and going stops it. The second
    /// apply is the CONTROL for "left alone": it must not restart a plugin the
    /// section still names unchanged. The `{}` apply is also the module doc's
    /// first departure: the plugin it stops is one the PLANE started, which
    /// upstream never records and would leave running.
    #[test]
    fn the_section_starts_keeps_and_stops_a_library_plugin() {
        let Some(so) = example_so() else {
            return;
        };
        let so = so.display().to_string();
        let mut plane = DynamicPluginPlane::default();

        let reports = plane.apply(&section(&format!(
            r#"{{ ex: {{ __path__: "{so}" }}, storage_manager: {{ storages: {{}} }} }}"#
        )));
        assert_eq!(reports, Vec::new());
        assert_eq!(state(&plane, "ex"), Some(AdminPluginState::Started));
        assert_eq!(
            plane.running().collect::<Vec<_>>(),
            vec!["ex"],
            "a composed subsystem is never this plane's"
        );

        let reports = plane.apply(&section(&format!(
            r#"{{ ex: {{ __path__: ["/nonexistent/other.so", "{so}"] }} }}"#
        )));
        assert_eq!(
            reports,
            Vec::new(),
            "a path list that still names the running path leaves it running"
        );
        assert_eq!(state(&plane, "ex"), Some(AdminPluginState::Started));

        let reports = plane.apply(&section("{}"));
        assert_eq!(reports, Vec::new());
        assert_eq!(
            state(&plane, "ex"),
            Some(AdminPluginState::Loaded),
            "stopped, not unloaded"
        );
        assert_eq!(plane.running().count(), 0);

        plane.apply(&section(&format!(r#"{{ ex: {{ __path__: "{so}" }} }}"#)));
        assert_eq!(
            state(&plane, "ex"),
            Some(AdminPluginState::Started),
            "added back, the loaded library starts again"
        );
    }

    /// Upstream's validator: a write below a RUNNING library plugin is
    /// refused with its default checker's words; one below a plugin that is
    /// not running, and one below a composed subsystem, are not this plane's
    /// to refuse. A malformed reserved member is refused before it can land.
    #[test]
    fn a_running_library_plugin_refuses_to_be_edited_in_place() {
        let Some(so) = example_so() else {
            return;
        };
        let so = so.display().to_string();
        let mut plane = DynamicPluginPlane::default();
        let new = parse(r#"{ key: 1 }"#).unwrap();
        assert_eq!(
            plane.check_config("ex", &new),
            Ok(None),
            "CONTROL: not running yet, so any document is accepted"
        );
        plane.apply(&section(&format!(r#"{{ ex: {{ __path__: "{so}" }} }}"#)));
        assert_eq!(
            plane.check_config("ex", &new),
            Err(String::from("Runtime configuration change not supported"))
        );
        assert_eq!(plane.check_config("storage_manager", &new), Ok(None));
        assert!(plane
            .check_config("other", &parse(r#"{ __required__: 1 }"#).unwrap())
            .unwrap_err()
            .contains("__required__"));
    }

    /// A start that cannot happen is REPORTED with its `__required__`, and
    /// the section's other plugins still start — upstream logs and runs on.
    /// No example library is needed: the failures are the subject. By-name
    /// lookup is ON here over no directory, so the unnamed plugin is searched
    /// for and not found.
    #[test]
    fn a_plugin_that_cannot_start_is_reported_and_the_rest_run_on() {
        let mut plane = DynamicPluginPlane::new(PluginsLoading::Enabled);
        plane.set_search_dirs(LibSearchDirs::new(Vec::new()));
        let reports = plane.apply(&section(
            r#"{ missing: { __path__: "/nonexistent/wz-no-such.so", __required__: true },
                 unnamed: {} }"#,
        ));
        assert_eq!(reports.len(), 2, "{reports:?}");
        let missing = reports.iter().find(|r| r.plugin == "missing").unwrap();
        assert!(missing.required);
        assert!(
            missing.message.contains("/nonexistent/wz-no-such.so"),
            "{missing:?}"
        );
        let unnamed = reports.iter().find(|r| r.plugin == "unnamed").unwrap();
        assert!(!unnamed.required);
        assert!(
            unnamed
                .message
                .contains(&crate::plugin_search_dirs::plugin_library_file_name(
                    "unnamed"
                )),
            "{unnamed:?}"
        );
        assert!(unnamed.message.contains("search_dirs"), "{unnamed:?}");
        assert_eq!(
            state(&plane, "missing"),
            Some(AdminPluginState::Declared),
            "a failed load stays visible as Declared"
        );
        assert_eq!(
            state(&plane, "unnamed"),
            Some(AdminPluginState::Declared),
            "a plugin searched for and not found stays declared, as upstream declares it first"
        );
        assert_eq!(plane.running().count(), 0);
    }

    /// `plugins_loading/search_dirs`: a plugin named without a `__path__` is
    /// found by its library name in the first directory holding it, and an
    /// earlier directory that does not hold it is passed over. The CONTROL is
    /// the same section over directories that do not hold it, which starts
    /// nothing; without the search the first apply would be that control.
    #[test]
    fn a_plugin_named_without_a_path_is_found_in_the_search_dirs() {
        let Some(so) = example_so() else {
            return;
        };
        let dir = so
            .parent()
            .expect("a built library has a directory")
            .to_path_buf();
        let empty = tempfile::tempdir().unwrap();
        let named = r#"{ ex: { __plugin__: "example" } }"#;

        let mut control = DynamicPluginPlane::new(PluginsLoading::Enabled);
        control.set_search_dirs(LibSearchDirs::new(vec![
            crate::plugin_search_dirs::LibSearchDir::Path(empty.path().display().to_string()),
        ]));
        let reports = control.apply(&section(named));
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(control.running().count(), 0);

        let mut plane = DynamicPluginPlane::new(PluginsLoading::Enabled);
        plane.set_search_dirs(LibSearchDirs::new(vec![
            crate::plugin_search_dirs::LibSearchDir::Path(empty.path().display().to_string()),
            crate::plugin_search_dirs::LibSearchDir::Path(dir.display().to_string()),
        ]));
        let reports = plane.apply(&section(named));
        assert_eq!(reports, Vec::new());
        assert_eq!(state(&plane, "ex"), Some(AdminPluginState::Started));
        assert_eq!(
            plane.registry.path("ex"),
            Some(so.as_path()),
            "the name `example` is the built `wz-plugin-example` library"
        );
    }

    /// `plugins_loading/enabled` off, the library's default: a plugin the
    /// section names with no `__path__` is left unloaded with upstream's
    /// warning, which fails nothing even when `__required__`, while one named
    /// by path is still loaded. On, the same request is searched for in
    /// `plugins_loading/search_dirs`, and one not found there is a failure that
    /// keeps its `__required__`. No example library is needed: the path arm's
    /// subject is that the attempt is made at all.
    #[test]
    fn by_name_loading_off_leaves_an_unnamed_plugin_unloaded_and_fails_nothing() {
        assert_eq!(PluginsLoading::from_config(None), PluginsLoading::Disabled);
        assert_eq!(
            PluginsLoading::from_config(Some(false)),
            PluginsLoading::Disabled
        );
        assert_eq!(
            PluginsLoading::from_config(Some(true)),
            PluginsLoading::Enabled
        );

        let doc = r#"{ unnamed: { __required__: true },
                       pathed: { __path__: "/nonexistent/wz-no-such.so" } }"#;
        let mut off = DynamicPluginPlane::new(PluginsLoading::Disabled);
        let reports = off.apply(&section(doc));
        let unnamed = reports.iter().find(|r| r.plugin == "unnamed").unwrap();
        assert!(
            !unnamed.required,
            "upstream fails nothing here: {unnamed:?}"
        );
        assert!(
            unnamed
                .message
                .contains("will not be loaded as plugin loading is disabled"),
            "{unnamed:?}"
        );
        let pathed = reports.iter().find(|r| r.plugin == "pathed").unwrap();
        assert!(
            pathed.message.contains("/nonexistent/wz-no-such.so"),
            "a path is tried whatever the switch says: {pathed:?}"
        );
        assert_eq!(off.running().count(), 0);

        let mut on = DynamicPluginPlane::new(PluginsLoading::Enabled);
        on.set_search_dirs(LibSearchDirs::new(Vec::new()));
        let reports = on.apply(&section(doc));
        let unnamed = reports.iter().find(|r| r.plugin == "unnamed").unwrap();
        assert!(unnamed.required, "{unnamed:?}");
        assert!(unnamed.message.contains("search_dirs"), "{unnamed:?}");
    }

    /// The combinator asks each sink and the first that refuses decides; the
    /// notification reaches every one.
    #[test]
    fn several_sinks_answer_as_one() {
        struct Fixed(Result<Option<Json5Value>, String>, core::cell::Cell<usize>);
        impl PluginsSink for Fixed {
            fn check_config(
                &self,
                _: &str,
                _: &str,
                _: &Json5Value,
                _: &Json5Value,
            ) -> Result<Option<Json5Value>, String> {
                self.0.clone()
            }
            fn plugins_changed(&self, _: &PluginsConfig) {
                self.1.set(self.1.get() + 1);
            }
        }
        let accept = Fixed(Ok(None), Default::default());
        let refuse = Fixed(Err(String::from("no")), Default::default());
        let doc = Json5Value::Object(Vec::new());
        let both = PluginsSinks(&[&accept, &refuse]);
        assert_eq!(
            both.check_config("p", "", &doc, &doc),
            Err(String::from("no"))
        );
        assert_eq!(
            PluginsSinks(&[&accept, &accept]).check_config("p", "", &doc, &doc),
            Ok(None)
        );
        both.plugins_changed(&PluginsConfig::new());
        assert_eq!((accept.1.get(), refuse.1.get()), (1, 1));
    }
}
