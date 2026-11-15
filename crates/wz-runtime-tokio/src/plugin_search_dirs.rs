// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `plugins_loading/search_dirs`: where a plugin the `plugins` section names
//! without a `__path__` is looked for, and the file name it is looked for by.
//!
//! The rules are upstream's, read at the pin:
//!
//! * a plugin is searched for BY NAME only when its document names no
//!   `__path__` (`zenoh/src/api/loader.rs` @ `plugin_mgr.declare_dynamic_plugin_by_name(id, name, required)?`);
//!   the name is `__plugin__`, else the plugin's key in the section;
//! * the file is the platform's library prefix, the plugin prefix, the name and
//!   the platform's library suffix
//!   (`plugins/zenoh-plugin-trait/src/manager.rs` @ `let libplugin_name = format!("{}{}", self.default_lib_prefix, plugin_name);`);
//! * the directories are tried in the order the list gives them, and the first
//!   one holding an entry of that name wins
//!   (`commons/zenoh-util/src/lib_loader.rs` @ `if entry.file_name() == filename_ostr {`);
//!   a directory that cannot be read is passed over, and none holding the file
//!   is a refusal naming the file
//!   (`commons/zenoh-util/src/lib_loader.rs` @ `Err(zerror!("Library file '{}' not found", filename).into())`);
//! * an entry is a path, in which `~` and environment variables are expanded
//!   (`commons/zenoh-util/src/lib_search_dirs.rs` @ `shellexpand::full(value).map_err(|err| error_from_source(&self, err))?;`),
//!   or `{ kind: "current_exe_parent" }`, the canonical directory of the running
//!   executable (`commons/zenoh-util/src/lib_search_dirs.rs` @ `let canonicalized = current_exe_parent`);
//!   an entry that does not resolve is dropped from the search and the rest
//!   still apply (`commons/zenoh-util/src/lib_loader.rs` @ `Err(err) => tracing::error!("{err}"),`);
//! * a document that names no list searches upstream's default one
//!   (`commons/zenoh-util/src/lib_search_dirs.rs` @ `LibSearchDir::Path("~/.zenoh/lib".to_string()),`).
//!
//! One departure, and it is the plugin prefix: upstream's is `zenoh_plugin_`, the
//! prefix of libraries built against ITS plugin ABI, which no wz host can load.
//! wz's is [`PLUGIN_LIBRARY_PREFIX`](crate::plugin_search_dirs::PLUGIN_LIBRARY_PREFIX), so a
//! name finds the library a wz plugin
//! crate builds (`wz-plugin-example` builds `libwz_plugin_example.so`, found as
//! `example`) and never an upstream one that would only fail the ABI gate.

use std::path::{Path, PathBuf};

use wz_session_core::json5::Json5Value;

/// The prefix of a wz plugin library's name, after the platform's own `lib`.
pub const PLUGIN_LIBRARY_PREFIX: &str = "wz_plugin_";

/// The file a plugin named `name` is looked for as: `libwz_plugin_<name>.so` on Linux.
pub fn plugin_library_file_name(name: &str) -> String {
    format!(
        "{}{PLUGIN_LIBRARY_PREFIX}{name}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    )
}

/// One entry of the search list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibSearchDir {
    /// A path, `~` and `$VAR` expanded when it is resolved. The bare-string spelling and
    /// `{ kind: "path", value: ... }` both read as this.
    Path(String),
    /// `{ kind: "path" }` with no `value`: upstream reads it and refuses it when the list
    /// is resolved, so it is kept to be refused there too.
    PathWithoutValue,
    /// `{ kind: "current_exe_parent" }`: the directory of the running executable.
    CurrentExeParent,
}

impl LibSearchDir {
    /// The directory this entry names, or why it names none.
    pub fn resolve(&self) -> Result<PathBuf, String> {
        match self {
            LibSearchDir::Path(text) => expand_path(text).map(PathBuf::from),
            LibSearchDir::PathWithoutValue => {
                Err(String::from("`path` specs should have a `value` field"))
            }
            LibSearchDir::CurrentExeParent => {
                let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                let parent = exe.parent().ok_or_else(|| {
                    String::from("current executable's path has no parent directory")
                })?;
                parent.canonicalize().map_err(|e| e.to_string())
            }
        }
    }
}

/// The ordered list of directories a plugin is searched for in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibSearchDirs(Vec<LibSearchDir>);

impl Default for LibSearchDirs {
    /// Upstream's list, in upstream's order.
    fn default() -> Self {
        LibSearchDirs(vec![
            LibSearchDir::CurrentExeParent,
            LibSearchDir::Path(String::from(".")),
            LibSearchDir::Path(String::from("~/.zenoh/lib")),
            LibSearchDir::Path(String::from("/opt/homebrew/lib")),
            LibSearchDir::Path(String::from("/usr/local/lib")),
            LibSearchDir::Path(String::from("/usr/lib")),
        ])
    }
}

/// The shape a search list is read in, for a refusal to name.
pub const LIB_SEARCH_DIRS_SHAPE: &str = "a list of paths or { kind: \"path\" | \
                                         \"current_exe_parent\", value?: \"<path>\" }";

impl LibSearchDirs {
    /// A list of exactly `dirs`, in that order.
    pub fn new(dirs: Vec<LibSearchDir>) -> Self {
        LibSearchDirs(dirs)
    }

    /// The entries, in search order.
    pub fn dirs(&self) -> &[LibSearchDir] {
        &self.0
    }

    /// Read a list as a document spells it: each member a path string or an object with a
    /// `kind` and, for `path`, a `value`. Upstream reads the object without refusing a field it
    /// does not know, and so does this; a member of another type, a `kind` it does not know
    /// and a `value` that is not a string are refused, as upstream's parser refuses them.
    pub fn from_json5(value: &Json5Value) -> Result<Self, String> {
        let Json5Value::Array(items) = value else {
            return Err(String::from(LIB_SEARCH_DIRS_SHAPE));
        };
        let mut dirs = Vec::with_capacity(items.len());
        for item in items {
            dirs.push(match item {
                Json5Value::String(path) => LibSearchDir::Path(path.clone()),
                Json5Value::Object(_) => {
                    let value = match item.get("value") {
                        None | Some(Json5Value::Null) => None,
                        Some(Json5Value::String(text)) => Some(text.clone()),
                        Some(_) => return Err(String::from(LIB_SEARCH_DIRS_SHAPE)),
                    };
                    match item.get("kind") {
                        Some(Json5Value::String(kind)) if kind == "current_exe_parent" => {
                            LibSearchDir::CurrentExeParent
                        }
                        Some(Json5Value::String(kind)) if kind == "path" => match value {
                            Some(path) => LibSearchDir::Path(path),
                            None => LibSearchDir::PathWithoutValue,
                        },
                        _ => return Err(String::from(LIB_SEARCH_DIRS_SHAPE)),
                    }
                }
                _ => return Err(String::from(LIB_SEARCH_DIRS_SHAPE)),
            });
        }
        Ok(LibSearchDirs(dirs))
    }

    /// The list as JSON5 text [`Self::from_json5`] reads back to the same list.
    pub fn to_json5_text(&self) -> String {
        let items: Vec<Json5Value> = self
            .0
            .iter()
            .map(|dir| match dir {
                LibSearchDir::Path(path) => Json5Value::String(path.clone()),
                LibSearchDir::PathWithoutValue => Json5Value::Object(vec![(
                    String::from("kind"),
                    Json5Value::String(String::from("path")),
                )]),
                LibSearchDir::CurrentExeParent => Json5Value::Object(vec![
                    (
                        String::from("kind"),
                        Json5Value::String(String::from("current_exe_parent")),
                    ),
                    (String::from("value"), Json5Value::Null),
                ]),
            })
            .collect();
        Json5Value::Array(items).to_json5_text()
    }

    /// Every entry resolved, in order: the directories, and a refusal per entry that names
    /// none, which leaves that entry out of the search.
    pub fn resolve(&self) -> (Vec<PathBuf>, Vec<String>) {
        let mut dirs = Vec::with_capacity(self.0.len());
        let mut refusals = Vec::new();
        for dir in &self.0 {
            match dir.resolve() {
                Ok(path) => dirs.push(path),
                Err(why) => {
                    refusals.push(format!("invalid library search directory {dir:?}: {why}"))
                }
            }
        }
        (dirs, refusals)
    }

    /// The library of the plugin named `name`: the first resolved directory holding an entry
    /// named [`plugin_library_file_name`]. A refusal names the file, the directories searched
    /// and the entries that resolved to none.
    pub fn find_plugin(&self, name: &str) -> Result<PathBuf, String> {
        let file_name = plugin_library_file_name(name);
        let (dirs, refusals) = self.resolve();
        if let Some(path) = find_in(&dirs, &file_name) {
            return Ok(path);
        }
        let mut why =
            format!("Library file '{file_name}' not found in plugins_loading/search_dirs {dirs:?}");
        for refusal in refusals {
            why.push_str("; ");
            why.push_str(&refusal);
        }
        Err(why)
    }
}

/// The first of `dirs` holding an entry named `file_name`, read as upstream reads it: by
/// listing the directory, so one that cannot be listed is passed over.
fn find_in(dirs: &[PathBuf], file_name: &str) -> Option<PathBuf> {
    let wanted = std::ffi::OsStr::new(file_name);
    dirs.iter().find_map(|dir| {
        std::fs::read_dir(dir)
            .ok()?
            .flatten()
            .find(|entry| entry.file_name() == wanted)
            .map(|entry| entry.path())
    })
}

/// `~` and environment variables expanded as a shell expands them in a word: a leading `~`
/// alone or before `/` is the home directory (left as written when there is none), `$NAME`
/// and `${NAME}` are the variable, `${NAME:-default}` falls back to `default` when it is
/// unset or empty, and an unset variable with no fallback is a refusal naming it.
pub fn expand_path(text: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    if let Some(after) = rest.strip_prefix('~') {
        if after.is_empty() || after.starts_with('/') {
            match std::env::var_os("HOME") {
                Some(home) => out.push_str(&Path::new(&home).to_string_lossy()),
                None => out.push('~'),
            }
            rest = after;
        }
    }
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        if let Some(braced) = after.strip_prefix('{') {
            let Some(close) = braced.find('}') else {
                return Err(format!("unterminated `${{` in {text:?}"));
            };
            let inner = &braced[..close];
            let (name, fallback) = match inner.split_once(":-") {
                Some((name, fallback)) => (name, Some(fallback)),
                None => (inner, None),
            };
            let value = std::env::var(name).ok();
            match fallback {
                Some(fallback) => out.push_str(
                    value
                        .as_deref()
                        .filter(|v| !v.is_empty())
                        .unwrap_or(fallback),
                ),
                None => match value {
                    Some(value) => out.push_str(&value),
                    None => {
                        return Err(format!(
                            "environment variable {name:?} is not set ({text:?})"
                        ))
                    }
                },
            }
            rest = &braced[close + 1..];
            continue;
        }
        let name_len = after.find(|c: char| !is_name(c)).unwrap_or(after.len());
        if name_len == 0 {
            out.push('$');
            rest = after;
            continue;
        }
        let name = &after[..name_len];
        match std::env::var(name) {
            Ok(value) => out.push_str(&value),
            Err(_) => {
                return Err(format!(
                    "environment variable {name:?} is not set ({text:?})"
                ))
            }
        }
        rest = &after[name_len..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::json5::parse;

    fn read(text: &str) -> Result<LibSearchDirs, String> {
        LibSearchDirs::from_json5(&parse(text).expect("json5"))
    }

    #[test]
    fn a_library_is_named_by_the_wz_plugin_prefix() {
        let name = plugin_library_file_name("example");
        assert_eq!(
            name,
            format!(
                "{}wz_plugin_example{}",
                std::env::consts::DLL_PREFIX,
                std::env::consts::DLL_SUFFIX
            )
        );
        assert!(!name.contains("zenoh_plugin_"), "{name}");
    }

    #[test]
    fn the_default_list_is_upstreams_in_upstreams_order() {
        let dirs = LibSearchDirs::default();
        assert_eq!(dirs.dirs()[0], LibSearchDir::CurrentExeParent);
        let paths: Vec<&str> = dirs.dirs()[1..]
            .iter()
            .map(|d| match d {
                LibSearchDir::Path(p) => p.as_str(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            paths,
            [
                ".",
                "~/.zenoh/lib",
                "/opt/homebrew/lib",
                "/usr/local/lib",
                "/usr/lib"
            ]
        );
    }

    #[test]
    fn both_spellings_of_an_entry_read_and_survive_the_emitter() {
        let dirs = read(
            r#"[ "/a", { kind: "path", value: "/b" }, { kind: "current_exe_parent" },
                 { kind: "path" }, { kind: "path", value: "/c", note: 1 } ]"#,
        )
        .expect("a list of both spellings");
        assert_eq!(
            dirs.dirs(),
            [
                LibSearchDir::Path(String::from("/a")),
                LibSearchDir::Path(String::from("/b")),
                LibSearchDir::CurrentExeParent,
                LibSearchDir::PathWithoutValue,
                LibSearchDir::Path(String::from("/c")),
            ]
        );
        assert_eq!(read(&dirs.to_json5_text()), Ok(dirs.clone()));
        assert_eq!(
            read(&LibSearchDirs::default().to_json5_text()),
            Ok(LibSearchDirs::default())
        );
    }

    #[test]
    fn a_member_upstreams_parser_refuses_is_refused() {
        for bad in [
            r#""/a""#,
            "[5]",
            r#"[{ kind: "sideways" }]"#,
            r#"[{ value: "/a" }]"#,
            r#"[{ kind: "path", value: 5 }]"#,
            "[[]]",
        ] {
            assert!(read(bad).is_err(), "{bad} was read");
        }
        assert_eq!(read("[]"), Ok(LibSearchDirs::new(Vec::new())));
    }

    #[test]
    fn a_path_expands_home_and_variables_and_refuses_an_unset_one() {
        let home = std::env::var("HOME").expect("the test environment has a HOME");
        assert_eq!(expand_path("~/lib").unwrap(), format!("{home}/lib"));
        assert_eq!(expand_path("~").unwrap(), home);
        assert_eq!(
            expand_path("/x/~/y").unwrap(),
            "/x/~/y",
            "only a leading tilde is the home directory"
        );
        assert_eq!(expand_path("$HOME/a").unwrap(), format!("{home}/a"));
        assert_eq!(expand_path("${HOME}b").unwrap(), format!("{home}b"));
        let unset = "WZ_PLUGIN_SEARCH_DIRS_TEST_UNSET_VARIABLE";
        assert_eq!(
            expand_path(&format!("${{{unset}:-/fallback}}/x")).unwrap(),
            "/fallback/x"
        );
        let refused = expand_path(&format!("/a/${unset}")).unwrap_err();
        assert!(refused.contains(unset), "{refused}");
        assert_eq!(
            expand_path("/a$/b").unwrap(),
            "/a$/b",
            "a bare `$` is a `$`"
        );
    }

    #[test]
    fn the_first_directory_holding_the_library_wins_and_a_bad_entry_is_passed_over() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let file = plugin_library_file_name("probe");
        std::fs::write(second.path().join(&file), b"").unwrap();
        let dirs = LibSearchDirs::new(vec![
            LibSearchDir::PathWithoutValue,
            LibSearchDir::Path(String::from("/nonexistent/wz-plugin-search")),
            LibSearchDir::Path(first.path().display().to_string()),
            LibSearchDir::Path(second.path().display().to_string()),
        ]);
        assert_eq!(dirs.find_plugin("probe"), Ok(second.path().join(&file)));

        std::fs::write(first.path().join(&file), b"").unwrap();
        assert_eq!(
            dirs.find_plugin("probe"),
            Ok(first.path().join(&file)),
            "the earlier directory now holds it too, so it is the one found"
        );

        let missing = dirs.find_plugin("absent").unwrap_err();
        assert!(
            missing.contains(&plugin_library_file_name("absent")),
            "{missing}"
        );
        assert!(
            missing.contains("value"),
            "the bad entry is named: {missing}"
        );
    }
}
