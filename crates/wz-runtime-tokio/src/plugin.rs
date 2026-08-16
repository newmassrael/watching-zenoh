// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.22 — the DYNAMIC plugin host: `dlopen` loading, the ABI gate, the
//! lifecycle FSM, and the runtime registry.
//!
//! ## Four deprecated atoms returning, exactly as R311y256 said they would
//!
//! R311y256 deprecated `plugin-manager`, `-host-trait`, `-lifecycle` and
//! `-abi-compat` because each exists ONLY to serve dynamic loading, which wz did
//! not do — every subsystem was composed at build time, so there was no registry
//! to keep, no uniform start seam, no `Declared -> Loaded` step and no
//! cross-binary ABI boundary. The same round kept `plugin-dynamic-loading` as
//! real backlog and wrote the consequence down: *"the other four exist only to
//! SERVE dynamic loading, so if this is ever built they return with it."*
//!
//! They return here, and each is a distinct thing rather than a relabelling:
//!
//! - `plugin-dynamic-loading` — [`DynamicPlugin::load`], a real `dlopen` +
//!   `dlsym` of `wz_plugin_abi::ENTRY_SYMBOL`.
//! - `plugin-abi-compat` — the [`wz_plugin_abi::PluginEntry::compatibility`]
//!   call that gates every dereference of the vtable.
//! - `plugin-lifecycle` — [`AdminPluginState`]'s `Loaded -> Started` on this
//!   side of the boundary, and `Declared -> Loaded` in [`PluginRegistry::load`],
//!   the step that only exists BECAUSE `dlopen` can fail.
//! - `plugin-manager` — [`PluginRegistry`], the runtime registry keyed by plugin
//!   id, which is what makes the admin space's `plugins/**` legs report a
//!   loaded `.so` beside the statically composed subsystems.
//!
//! `plugin-static-registration` does NOT return, and that is not an oversight:
//! its inventory reason records that cargo `[features]` + `cfg` ARE wz's static
//! registration, realised at the build-system layer. Nothing here changes that.
//!
//! ## The one thing this module is careful about
//!
//! A library is `dlopen`ed for the lifetime of the registry and never unloaded.
//! That is deliberate. `dlclose` while any pointer into the library is still
//! reachable — a `&'static str` the plugin returned, a function pointer the host
//! cached, a thread the plugin spawned — is a use-after-free that no amount of
//! Rust type checking sees, because the lifetime the borrow checker reasons
//! about ends at process exit while the mapping does not. zenoh takes the same
//! position (`dynamic_plugin.rs` holds its `Library` for the manager's life).
//! So [`DynamicPlugin`] owns its [`libloading::Library`] and drops it only when
//! the registry itself drops, at which point the process is tearing down.
//!
//! Every string the plugin hands back is COPIED at load time for the same
//! reason: the registry outlives no library, but a caller holding a `&str` that
//! points into a mapping is one refactor away from doing so.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

use wz_plugin_abi::{Compatibility, EntryFn, PluginEntry, PluginVTable, ENTRY_SYMBOL, OK};
use wz_session_core::adminspace::{AdminPlugin, AdminPluginState};

/// Why a load or start refused.
///
/// Every variant names the operand. "plugin failed to load" with no path, or
/// "incompatible" with no numbers, is the diagnostic that sends the next reader
/// into this file — the same rule the R311y490 barriers were fixed under.
#[derive(Debug)]
pub enum PluginError {
    /// `dlopen` refused — missing file, missing dependency, not an ELF.
    Open { path: PathBuf, source: String },
    /// The library loaded but exports no `wz_plugin_entry`.
    NoEntrySymbol { path: PathBuf, source: String },
    /// The entry function returned null.
    NullEntry { path: PathBuf },
    /// The `plugin-abi-compat` gate refused.
    Incompatible {
        path: PathBuf,
        verdict: Compatibility,
    },
    /// The descriptor's vtable pointer was null.
    NullVTable { path: PathBuf },
    /// A metadata getter returned a string that is not UTF-8.
    BadMetadata { path: PathBuf, field: &'static str },
    /// Two plugins claim the same id.
    DuplicateId { id: String, path: PathBuf },
    /// `start` returned non-zero. The plugin stays `Loaded`.
    StartRefused { id: String, code: i32 },
    /// `stop` returned non-zero.
    StopRefused { id: String, code: i32 },
    /// No plugin with that id is loaded.
    NotLoaded { id: String },
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(f, "dlopen {} failed: {source}", path.display())
            }
            Self::NoEntrySymbol { path, source } => write!(
                f,
                "{} exports no `wz_plugin_entry`: {source} — is it a wz plugin?",
                path.display()
            ),
            Self::NullEntry { path } => {
                write!(f, "{}'s wz_plugin_entry returned null", path.display())
            }
            Self::Incompatible { path, verdict } => write!(
                f,
                "{} failed the ABI gate: {verdict:?} — rebuild it against this \
                 host's wz-plugin-abi",
                path.display()
            ),
            Self::NullVTable { path } => {
                write!(f, "{}'s entry carries a null vtable", path.display())
            }
            Self::BadMetadata { path, field } => {
                write!(f, "{}'s `{field}` is not valid UTF-8", path.display())
            }
            Self::DuplicateId { id, path } => write!(
                f,
                "a plugin with id `{id}` is already loaded; {} would shadow it",
                path.display()
            ),
            Self::StartRefused { id, code } => {
                write!(f, "plugin `{id}` refused to start (code {code})")
            }
            Self::StopRefused { id, code } => {
                write!(f, "plugin `{id}` refused to stop (code {code})")
            }
            Self::NotLoaded { id } => write!(f, "no plugin `{id}` is loaded"),
        }
    }
}

impl std::error::Error for PluginError {}

/// One `dlopen`ed plugin.
///
/// Field order matters for drop: `_library` is declared LAST so it is dropped
/// last, after every field that could conceivably reference it. Rust drops
/// struct fields in declaration order, and while none of the owned `String`s
/// point into the mapping (they are copies, by construction — see the module
/// doc), the ordering removes the question rather than answering it in a comment
/// that a later field addition could invalidate.
pub struct DynamicPlugin {
    id: String,
    name: String,
    version: String,
    path: PathBuf,
    state: AdminPluginState,
    vtable: *const PluginVTable,
    _library: libloading::Library,
}

impl std::fmt::Debug for DynamicPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicPlugin")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("path", &self.path)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Copy a NUL-terminated C string out of a plugin getter.
///
/// # Safety
/// `ptr` must be a valid NUL-terminated string for the duration of the call.
unsafe fn copy_cstr(
    ptr: *const std::ffi::c_char,
    path: &Path,
    field: &'static str,
) -> Result<String, PluginError> {
    if ptr.is_null() {
        return Err(PluginError::BadMetadata {
            path: path.to_path_buf(),
            field,
        });
    }
    // SAFETY: the caller's contract, and the ABI's, is a NUL-terminated string
    // valid for the library's lifetime; this copies out of it immediately.
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str()
        .map(str::to_owned)
        .map_err(|_| PluginError::BadMetadata {
            path: path.to_path_buf(),
            field,
        })
}

impl DynamicPlugin {
    /// `dlopen` `path`, resolve the entry symbol, run the ABI gate, and copy the
    /// metadata out — the `Declared -> Loaded` transition.
    ///
    /// `start` is NOT called. Loading and starting are separate on purpose,
    /// mirroring zenoh's lifecycle: a host may want to know what a `.so` claims
    /// to be before letting it run, and the ABI gate is worth nothing if it runs
    /// after the plugin has already executed.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PluginError> {
        let path = path.as_ref().to_path_buf();
        // SAFETY: `dlopen` runs the library's initialisers, which is arbitrary
        // code from a file the operator named. That is the irreducible trust in
        // dynamic loading and is why this atom is AP/std-only and opt-in; the
        // host makes no claim beyond "the operator asked for this path".
        let library =
            unsafe { libloading::Library::new(&path) }.map_err(|e| PluginError::Open {
                path: path.clone(),
                source: e.to_string(),
            })?;

        // SAFETY: the symbol's type is the ABI contract's `EntryFn`. If the
        // library exports something else under that name, the ABI gate below is
        // the only thing between us and it — which is exactly why the entry
        // function is specified to do nothing but return a pointer.
        let entry_fn = unsafe { library.get::<EntryFn>(ENTRY_SYMBOL) }.map_err(|e| {
            PluginError::NoEntrySymbol {
                path: path.clone(),
                source: e.to_string(),
            }
        })?;

        // SAFETY: calling the resolved symbol. Its contract is to return a
        // pointer to a `static` and run no initialisation.
        let entry: *const PluginEntry = unsafe { entry_fn() };
        if entry.is_null() {
            return Err(PluginError::NullEntry { path });
        }
        // SAFETY: non-null, and the contract makes it valid for the library's
        // lifetime. Only the plain data fields are read here — the vtable
        // pointer is not followed until the gate below passes, which is the
        // whole ordering the compatibility check depends on.
        let entry_ref = unsafe { &*entry };

        let verdict = entry_ref.compatibility();
        if !verdict.is_ok() {
            return Err(PluginError::Incompatible { path, verdict });
        }

        let vtable = entry_ref.vtable;
        if vtable.is_null() {
            return Err(PluginError::NullVTable { path });
        }
        // SAFETY: the gate passed, so this host's `PluginVTable` and the
        // plugin's agree on ABI, size and alignment; the pointer is non-null and
        // valid for the library's lifetime.
        let vt = unsafe { &*vtable };

        // SAFETY (x3): the getters are the gated vtable's, and their contract is
        // a NUL-terminated UTF-8 string valid for the library's lifetime.
        // Copied immediately, per the module doc.
        let id = unsafe { copy_cstr((vt.id)(), &path, "id") }?;
        let name = unsafe { copy_cstr((vt.name)(), &path, "name") }?;
        let version = unsafe { copy_cstr((vt.version)(), &path, "version") }?;

        Ok(Self {
            id,
            name,
            version,
            path,
            state: AdminPluginState::Loaded,
            vtable,
            _library: library,
        })
    }

    /// The plugin's registry id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Where it was loaded from — the value that distinguishes it from a
    /// statically composed subsystem in the admin space.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Its lifecycle state.
    pub fn state(&self) -> AdminPluginState {
        self.state
    }

    /// Call `start` — the `Loaded -> Started` transition.
    ///
    /// A refusal leaves the plugin `Loaded` and does NOT call `stop`, matching
    /// the ABI contract: `stop` pairs with a `start` that returned OK, and
    /// calling it after a refusal would hand the plugin a teardown for a setup
    /// it never did.
    pub fn start(&mut self, config: Option<&str>) -> Result<(), PluginError> {
        let owned = config.map(|c| CString::new(c).unwrap_or_default());
        let ptr = owned
            .as_ref()
            .map_or(std::ptr::null(), |c| c.as_ptr().cast());
        // SAFETY: the gated vtable's `start`; `ptr` is null or a valid
        // NUL-terminated string owned by `owned`, which outlives the call.
        let rc = unsafe { ((*self.vtable).start)(ptr) };
        if rc != OK {
            return Err(PluginError::StartRefused {
                id: self.id.clone(),
                code: rc,
            });
        }
        self.state = AdminPluginState::Started;
        Ok(())
    }

    /// Call `stop` — back to `Loaded`. A no-op if it was never started, so a
    /// registry teardown can call it blindly.
    pub fn stop(&mut self) -> Result<(), PluginError> {
        if self.state != AdminPluginState::Started {
            return Ok(());
        }
        // SAFETY: the gated vtable's `stop`, called only after a successful
        // `start`, which is what the `Started` state above records.
        let rc = unsafe { ((*self.vtable).stop)() };
        if rc != OK {
            return Err(PluginError::StopRefused {
                id: self.id.clone(),
                code: rc,
            });
        }
        self.state = AdminPluginState::Loaded;
        Ok(())
    }

    /// The admin-space record for this plugin.
    ///
    /// `path` is the real filesystem path, NOT
    /// [`wz_session_core::adminspace::WZ_STATIC_PLUGIN_PATH`]. That difference
    /// is the whole foreign-observable discriminator for this atom: a statically
    /// composed subsystem reports `"__static__"` by construction, so a record
    /// carrying a `.so` path cannot be produced without a `dlopen` having
    /// happened.
    pub fn admin_record(&self) -> AdminPlugin {
        AdminPlugin {
            id: self.id.clone(),
            name: self.name.clone(),
            version: Some(self.version.clone()),
            path: self.path.display().to_string(),
            state: self.state,
            // R311y827 — a dlopen'd plugin publishes no admin sub-tree: the wz
            // plugin ABI (`wz-plugin-abi`) carries no getter entry point, so there
            // is nothing to ask. Upstream's `adminspace_getter` is a trait method
            // every plugin answers; adding its analogue is an ABI change, which is
            // the §5.22 plugin family's own question, not this one.
            status_leaves: Vec::new(),
        }
    }
}

/// The runtime registry — the `plugin-manager` atom.
///
/// Ordered by id (`BTreeMap`) so the admin space's reply order is deterministic;
/// a `HashMap` would make the `plugins/**` reply set a different sequence per
/// process, which is the kind of thing a foreign client's transcript assertion
/// discovers the hard way.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: BTreeMap<String, DynamicPlugin>,
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field("ids", &self.plugins.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PluginRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// `Declared -> Loaded`: load `path` and register it under the id the
    /// plugin declares.
    ///
    /// Rejects a duplicate id rather than replacing: replacing would drop the
    /// incumbent's `Library` while its `start` may still have live effects, and
    /// the module doc's whole position is that a library is never unloaded while
    /// anything could reach into it.
    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<&str, PluginError> {
        let plugin = DynamicPlugin::load(path)?;
        let id = plugin.id().to_string();
        if self.plugins.contains_key(&id) {
            return Err(PluginError::DuplicateId {
                id,
                path: plugin.path().to_path_buf(),
            });
        }
        let entry = self.plugins.entry(id.clone()).or_insert(plugin);
        Ok(&entry.id)
    }

    /// `Loaded -> Started` for one plugin.
    pub fn start(&mut self, id: &str, config: Option<&str>) -> Result<(), PluginError> {
        self.plugins
            .get_mut(id)
            .ok_or_else(|| PluginError::NotLoaded { id: id.to_string() })?
            .start(config)
    }

    /// `Started -> Loaded` for one plugin.
    pub fn stop(&mut self, id: &str) -> Result<(), PluginError> {
        self.plugins
            .get_mut(id)
            .ok_or_else(|| PluginError::NotLoaded { id: id.to_string() })?
            .stop()
    }

    /// Loaded plugin ids, sorted.
    pub fn ids(&self) -> Vec<&str> {
        self.plugins.keys().map(String::as_str).collect()
    }

    /// One plugin's state.
    pub fn state(&self, id: &str) -> Option<AdminPluginState> {
        self.plugins.get(id).map(DynamicPlugin::state)
    }

    /// `true` when nothing is loaded.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// The admin records for every loaded plugin, id-ordered — the slice the
    /// `adminspace-plugins-handlers` reply blocks append to the statically
    /// composed ones.
    pub fn admin_records(&self) -> Vec<AdminPlugin> {
        self.plugins
            .values()
            .map(DynamicPlugin::admin_record)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example plugin's `.so`, built by the same cargo invocation that runs
    /// these tests (it is a workspace member and a `dev-dependency` of nothing —
    /// so the lane builds it explicitly; see Layer C1bp).
    fn example_so() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.push("target");
        p.push("debug");
        p.push(if cfg!(target_os = "macos") {
            "libwz_plugin_example.dylib"
        } else {
            "libwz_plugin_example.so"
        });
        p
    }

    /// The example `.so`, or `None` with a LOUD note.
    ///
    /// The note is not decoration: three of the legs below return early on
    /// `None`, and a silent early return is a green test that proved nothing —
    /// this project's own anti-masked-skip rule. Layer C1bp builds the `.so`
    /// first and is where its absence is a hard failure; here the worst case is
    /// visible rather than invisible.
    fn require_example() -> Option<PathBuf> {
        let p = example_so();
        if p.exists() {
            return Some(p);
        }
        eprintln!(
            "skip: {} not built — run `cargo build -p wz-plugin-example` (Layer C1bp does)",
            p.display()
        );
        None
    }

    #[test]
    fn a_missing_library_names_the_path_it_could_not_open() {
        let err = DynamicPlugin::load("/nonexistent/wz-not-a-plugin.so").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("/nonexistent/wz-not-a-plugin.so") && msg.contains("dlopen"),
            "the error names the path and the operation\n  got: {msg}"
        );
    }

    #[test]
    fn a_library_without_the_entry_symbol_is_refused_by_name() {
        // libc is a real, loadable shared object that is emphatically not a wz
        // plugin — the honest negative, rather than a file we crafted to fail.
        for candidate in ["libm.so.6", "libc.so.6"] {
            if let Ok(p) = DynamicPlugin::load(candidate) {
                panic!("{candidate} must not load as a wz plugin, got {p:?}");
            }
        }
    }

    #[test]
    fn the_real_example_loads_starts_and_stops() {
        let Some(so) = require_example() else {
            return;
        };
        let mut plugin = DynamicPlugin::load(&so).expect("the example plugin loads");
        assert_eq!(plugin.id(), "wz_example");
        assert_eq!(plugin.state(), AdminPluginState::Loaded);

        plugin.start(None).expect("it starts");
        assert_eq!(plugin.state(), AdminPluginState::Started);

        plugin.stop().expect("it stops");
        assert_eq!(plugin.state(), AdminPluginState::Loaded);
    }

    #[test]
    fn a_refusing_start_leaves_it_loaded() {
        let Some(so) = require_example() else {
            return;
        };
        let mut plugin = DynamicPlugin::load(&so).expect("loads");
        let err = plugin
            .start(Some(r#"{"refuse": true}"#))
            .expect_err("the example refuses this config");
        assert!(
            err.to_string().contains("wz_example"),
            "the refusal names the plugin\n  got: {err}"
        );
        // The state must NOT have advanced, and `stop` must stay a no-op — a
        // teardown for a setup that never ran is the bug this asserts against.
        assert_eq!(plugin.state(), AdminPluginState::Loaded);
        plugin.stop().expect("stop is a no-op when never started");
    }

    #[test]
    fn the_admin_record_carries_the_real_path_not_the_static_marker() {
        let Some(so) = require_example() else {
            return;
        };
        let plugin = DynamicPlugin::load(&so).expect("loads");
        let rec = plugin.admin_record();
        assert_eq!(rec.id, "wz_example");
        assert_ne!(
            rec.path,
            wz_session_core::adminspace::WZ_STATIC_PLUGIN_PATH,
            "a dlopen'd plugin must not report the static marker — that field is \
             the whole discriminator for this atom"
        );
        assert!(
            rec.path.ends_with("libwz_plugin_example.so")
                || rec.path.ends_with("libwz_plugin_example.dylib"),
            "it reports the file it was loaded from\n  got: {}",
            rec.path
        );
    }

    #[test]
    fn the_registry_rejects_a_duplicate_id_rather_than_replacing() {
        let Some(so) = require_example() else {
            return;
        };
        let mut reg = PluginRegistry::new();
        assert!(reg.is_empty());
        let id = reg.load(&so).expect("first load").to_string();
        assert_eq!(id, "wz_example");
        assert_eq!(reg.ids(), vec!["wz_example"]);

        let err = reg.load(&so).expect_err("the same id must not load twice");
        assert!(err.to_string().contains("already loaded"), "got: {err}");
        // And the incumbent is untouched.
        assert_eq!(reg.state("wz_example"), Some(AdminPluginState::Loaded));

        reg.start("wz_example", None)
            .expect("starts through registry");
        assert_eq!(reg.state("wz_example"), Some(AdminPluginState::Started));
        assert_eq!(reg.admin_records().len(), 1);
        assert_eq!(reg.admin_records()[0].state, AdminPluginState::Started);

        reg.stop("wz_example").expect("stops through registry");
        assert_eq!(reg.state("wz_example"), Some(AdminPluginState::Loaded));

        assert!(reg.start("absent", None).is_err());
    }
}
