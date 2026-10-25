// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-util`, the library loader, its search directories and the ffi helpers (the second slice of
//! the crate): upstream's crate (`up_util`) and wz's (`wz_util`) given the same inputs, results equal
//! as text.
//!
//! * SEARCH DIRECTORIES: every JSON spec a directory may be written as (a path, a path with a shell
//!   variable, the map forms with and without a value, a kind that does not exist, things that are
//!   not a directory at all), what each parses to and the path or the error it comes to; the
//!   defaults, `from_paths`, equality and hashing, and the serde forms of a list.
//! * THE LOADER over a tree of fixtures that both crates read (so the paths in an error are the
//!   same): a real shared library (the C library of this test binary, found in `/proc/self/maps` and
//!   linked into the tree), a file that is not one, a directory with the name of one, a name that is
//!   not UTF-8, a second directory with the same library. `load_file` on each, `search_and_load` over
//!   several searches, `load_all_with_prefix` for several prefixes (the libraries and their order
//!   compared sorted, since the order of a directory is the system's), `plugin_name`.
//! * THE FFI HELPERS: the string readers over buffers that are valid, invalid and wide, and the two
//!   JSON wrappers (every kind of value, equality that ignores the order of keys, the serde forms,
//!   the schema).
//!
//! Upstream slices a file name for the name of a library without asking whether the prefix and the
//! suffix overlap, which is a panic on a name a directory holds. It is a class, built by hand,
//! counted and held on both sides:
//!
//! * `load_all_with_prefix(Some("."))` over a directory with a file `lib.so`: the file starts with
//!   the prefix `lib.` and ends with the suffix `.so` by the same dot, upstream slices `[4..3]` and
//!   panics, wz skips the file as a name that has no library name in it.

#![cfg(target_os = "linux")]

use std::{
    cell::Cell,
    ffi::OsString,
    fs,
    os::unix::ffi::OsStringExt,
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, Once, OnceLock},
};

static LOCK: Mutex<()> = Mutex::new(());

/// The tests share one fixture tree and the environment, and a library loaded twice is the same
/// handle, so the tests of the binary take one lock.
fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f`, and says `None` if it panicked, without the report of the panic.
fn guarded<T>(f: impl FnOnce() -> T) -> Option<T> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = take_hook();
        set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                previous(info)
            }
        }));
    });
    QUIET.with(|q| q.set(true));
    let out = catch_unwind(AssertUnwindSafe(f)).ok();
    QUIET.with(|q| q.set(false));
    out
}

const PANIC: &str = "PANIC";

/// An error as text without the place of the crate that made it.
fn plain(e: &impl std::fmt::Display) -> String {
    let s = e.to_string();
    s.split(" at ").next().unwrap_or("").to_string()
}

/// The path of a shared library this process has mapped: the C library.
fn a_real_library() -> PathBuf {
    let maps = fs::read_to_string("/proc/self/maps").unwrap();
    for line in maps.lines() {
        if let Some(path) = line.split_whitespace().last() {
            let name = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if path.starts_with('/') && name.starts_with("libc.so") && Path::new(path).is_file() {
                return PathBuf::from(path);
            }
        }
    }
    panic!("no C library in the maps of this process:\n{maps}");
}

/// The tree of fixtures, built once.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

fn tree() -> &'static Tree {
    static TREE: OnceLock<Tree> = OnceLock::new();
    TREE.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("wz_util_loader_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let lib = a_real_library();
        let mk = |dir: &str| {
            let d = root.join(dir);
            fs::create_dir_all(&d).unwrap();
            d
        };
        let link =
            |dir: &Path, name: &str| std::os::unix::fs::symlink(&lib, dir.join(name)).unwrap();
        let good = mk("good");
        link(&good, "libwzfixture.so");
        link(&good, "libwzother.so");
        link(&good, "libwzfoo.so");
        // Contains the prefix without starting with it: no search takes it.
        link(&good, "xlibwzmid.so");
        fs::write(good.join("notalib.txt"), b"text").unwrap();
        fs::write(good.join("libwzbad.so"), b"this is not an ELF file").unwrap();
        fs::create_dir_all(good.join("libwzdir.so")).unwrap();
        mk("empty");
        let dup = mk("dup");
        link(&dup, "libwzfixture.so");
        link(&dup, "libwzdup.so");
        let weird = mk("weird");
        link(&weird, "lib.so");
        link(&weird, "libx.so");
        fs::write(
            weird.join(OsString::from_vec(b"libwz\xffnonutf8.so".to_vec())),
            b"x",
        )
        .unwrap();
        Tree { root }
    })
}

macro_rules! loader_cases {
    ($m:ident, $u:ident) => {
        mod $m {
            use std::path::{Path, PathBuf};

            use $u::{
                ffi::{pstr_to_string, pwstr_to_string, JsonKeyValueMap, JsonValue},
                lib_search_dirs::LibSearchDir,
                LibLoader, LibSearchDirs, LIB_PREFIX, LIB_SUFFIX,
            };

            use super::{guarded, plain, tree, PANIC};

            /// What a list of JSON specs parses to, and each directory it comes to.
            pub fn spec_text(specs: &[&str]) -> String {
                match LibSearchDirs::from_specs(specs) {
                    Err(e) => format!("err {e}"),
                    Ok(dirs) => {
                        let mut out = format!("ok {dirs:?}");
                        for d in dirs.into_iter() {
                            match d {
                                Ok(p) => out.push_str(&format!(" | path {p:?}")),
                                Err(e) => out.push_str(&format!(" | invalid {e}")),
                            }
                        }
                        out
                    }
                }
            }

            /// What a JSON document is as a list of directories.
            pub fn dirs_from_json(doc: &str) -> String {
                match serde_json::from_str::<LibSearchDirs>(doc) {
                    Err(e) => format!("err {e}"),
                    Ok(d) => format!(
                        "ok {d:?} -> {}",
                        serde_json::to_string(&d).unwrap_or_else(|e| format!("ser err {e}"))
                    ),
                }
            }

            pub fn dir_from_json(doc: &str) -> String {
                match serde_json::from_str::<LibSearchDir>(doc) {
                    Err(e) => format!("err {e}"),
                    Ok(d) => format!(
                        "ok {d:?} -> {}",
                        serde_json::to_string(&d).unwrap_or_else(|e| format!("ser err {e}"))
                    ),
                }
            }

            pub fn defaults() -> Vec<String> {
                let d = LibSearchDirs::default();
                let mut out = vec![format!("{d:?}")];
                for p in d.clone() {
                    out.push(format!("{p:?}"));
                }
                out.push(serde_json::to_string(&d).unwrap());
                let paths = LibSearchDirs::from_paths(&["a", "~/b", "$HOME/c"]);
                out.push(format!("{paths:?}"));
                for p in paths.clone() {
                    out.push(format!("{p:?}"));
                }
                out.push(format!(
                    "eq {} {} {}",
                    LibSearchDirs::from_paths(&["a"]) == LibSearchDirs::from_specs(&["\"a\""]).unwrap(),
                    LibSearchDirs::from_paths(&["a"]) == LibSearchDirs::from_paths(&["b"]),
                    LibSearchDirs::from_paths::<&str>(&[]) == LibSearchDirs::from_specs::<&str>(&[]).unwrap(),
                ));
                let hash = |d: &LibSearchDirs| {
                    use std::hash::{Hash, Hasher};
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    d.hash(&mut h);
                    h.finish() == 0
                };
                out.push(format!("hash0 {}", hash(&paths)));
                out
            }

            fn loader_over(dirs: &[PathBuf]) -> LibLoader {
                let strs: Vec<String> = dirs.iter().map(|p| p.to_str().unwrap().to_string()).collect();
                LibLoader::new(LibSearchDirs::from_paths(&strs))
            }

            fn dirs(names: &[&str]) -> Vec<PathBuf> {
                names.iter().map(|n| tree().dir(n)).collect()
            }

            pub fn basics() -> Vec<String> {
                let mut out = vec![
                    format!("prefix {:?} suffix {:?}", *LIB_PREFIX, *LIB_SUFFIX),
                    format!("empty {:?}", LibLoader::empty()),
                    format!("empty paths {:?}", LibLoader::empty().search_paths()),
                    format!("default {:?}", LibLoader::default()),
                    format!("default paths {:?}", LibLoader::default().search_paths()),
                ];
                let l = loader_over(&dirs(&["good", "empty"]));
                out.push(format!("{l:?} {:?}", l.clone().search_paths()));
                // A set of directories where some cannot be a path: they are logged and dropped.
                let l = LibLoader::new(
                    LibSearchDirs::from_specs(&[
                        "\"/a\"",
                        "{\"kind\":\"path\"}",
                        "\"$WZ_NO_SUCH_VARIABLE/x\"",
                        "{\"kind\":\"current_exe_parent\"}",
                    ])
                    .unwrap(),
                );
                out.push(format!("{:?}", l.search_paths()));
                out
            }

            /// `load_file` of each path: the canonical path or the error.
            pub fn load_file(path: &str) -> String {
                // SAFETY: the libraries are the C library of the process, which is valid.
                match unsafe { LibLoader::load_file(path) } {
                    Ok((_lib, p)) => format!("ok {p:?}"),
                    Err(e) => format!("err {}", plain(&e)),
                }
            }

            pub fn root() -> String {
                tree().root.to_str().unwrap().to_string()
            }

            /// `search_and_load` of a name over the directories of the tree.
            pub fn search(names: &[&str], name: &str) -> String {
                let l = loader_over(&dirs(names));
                // SAFETY: as above.
                match unsafe { l.search_and_load(name) } {
                    Ok(Some((_lib, p))) => format!("ok {p:?}"),
                    Ok(None) => "none".to_string(),
                    Err(e) => format!("err {}", plain(&e)),
                }
            }

            pub fn search_empty(name: &str) -> String {
                // SAFETY: as above.
                match unsafe { LibLoader::empty().search_and_load(name) } {
                    Ok(Some((_lib, p))) => format!("ok {p:?}"),
                    Ok(None) => "none".to_string(),
                    Err(e) => format!("err {}", plain(&e)),
                }
            }

            /// `load_all_with_prefix` over the directories: the libraries found, sorted, or the
            /// panic.
            pub fn load_all(names: &[&str], prefix: Option<&str>) -> String {
                let l = loader_over(&dirs(names));
                // SAFETY: as above.
                match guarded(|| unsafe { l.load_all_with_prefix(prefix) }) {
                    None => PANIC.to_string(),
                    Some(None) => "none".to_string(),
                    Some(Some(libs)) => {
                        let mut rows: Vec<String> = libs
                            .into_iter()
                            .map(|(_lib, p, n)| format!("{p:?} {n:?}"))
                            .collect();
                        rows.sort();
                        format!("{} {rows:?}", rows.len())
                    }
                }
            }

            pub fn load_all_empty(prefix: Option<&str>) -> String {
                // SAFETY: as above.
                match unsafe { LibLoader::empty().load_all_with_prefix(prefix) } {
                    None => "none".to_string(),
                    Some(v) => format!("some {}", v.len()),
                }
            }

            pub fn plugin_name(path: &Path) -> String {
                format!("{:?} {:?}", LibLoader::_plugin_name(path), LibLoader::plugin_name(&path))
            }

            pub fn strings() -> Vec<String> {
                let mut out = Vec::new();
                for bytes in [
                    &b"hello\0"[..],
                    b"\0",
                    "héllo wörld 日本\0".as_bytes(),
                    b"bad\xff\xfeutf8\0",
                    b"a\0b\0",
                    b"\xf0\x9f\x92\x96\0",
                    b"\xed\xa0\x80lone surrogate\0",
                ] {
                    let mut buf: Vec<i8> = bytes.iter().map(|b| *b as i8).collect();
                    // SAFETY: the buffer is terminated.
                    out.push(unsafe { pstr_to_string(buf.as_mut_ptr()) });
                }
                for units in [
                    &[104u16, 105, 0][..],
                    &[0],
                    &[0xD83D, 0xDC96, 0],
                    &[0xD800, 0x61, 0],
                    &[0xDC00, 0],
                    &[0x65E5, 0x672C, 0, 0x61, 0],
                ] {
                    let mut buf = units.to_vec();
                    // SAFETY: the buffer is terminated.
                    out.push(unsafe { pwstr_to_string(buf.as_mut_ptr()) });
                }
                out
            }

            pub fn json() -> Vec<String> {
                let values = [
                    "null",
                    "true",
                    "false",
                    "0",
                    "-0",
                    "-0.0",
                    "1.5",
                    "1e300",
                    "18446744073709551615",
                    "-9223372036854775808",
                    "\"\"",
                    "\"a\\u0000b\"",
                    "\"日本\"",
                    "[]",
                    "[1,[2,[3]],{\"a\":null}]",
                    "{}",
                    "{\"b\":1,\"a\":2}",
                    "{\"a\":{\"b\":{\"c\":[true,null]}}}",
                ];
                let mut out = Vec::new();
                for v in values {
                    let value: serde_json::Value = serde_json::from_str(v).unwrap();
                    let j = JsonValue::from(&value);
                    let owned = JsonValue::from(value.clone());
                    let back: serde_json::Value = (&j).into();
                    let back_owned: serde_json::Value = owned.clone().into();
                    out.push(format!(
                        "{v}: {j:?} {owned:?} eq {} back {back} {back_owned} into {} ser {} de {:?}",
                        j == owned,
                        j.into_serde_value(),
                        serde_json::to_string(&j).unwrap(),
                        serde_json::from_str::<JsonValue>(v).map(|x| x == j)
                    ));
                }
                // Equality ignores the order of the keys of a map and nothing else.
                let a: JsonValue = serde_json::from_str::<serde_json::Value>("{\"a\":1,\"b\":2}").unwrap().into();
                let b: JsonValue = serde_json::from_str::<serde_json::Value>("{\"b\":2,\"a\":1}").unwrap().into();
                let c: JsonValue = serde_json::from_str::<serde_json::Value>("{\"a\":1,\"b\":3}").unwrap().into();
                out.push(format!("order {} {} {:?}", a == b, a == c, JsonValue::default()));
                out.push(format!(
                    "schema {}",
                    serde_json::to_string(&schemars::schema_for!(JsonValue)).unwrap()
                ));
                for v in ["{}", "{\"a\":1}", "{\"z\":[1,2],\"a\":{\"b\":null}}"] {
                    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(v).unwrap();
                    let m = JsonKeyValueMap::from(&map);
                    let owned = JsonKeyValueMap::from(map.clone());
                    let back: serde_json::Map<String, serde_json::Value> = (&m).into();
                    let back_owned: serde_json::Map<String, serde_json::Value> = owned.clone().into();
                    out.push(format!(
                        "{v}: {m:?} {owned:?} eq {} back {back:?} {back_owned:?} into {:?}",
                        m == owned,
                        m.into_serde_map()
                    ));
                }
                let x = JsonKeyValueMap::from(
                    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>("{\"a\":1,\"b\":2}").unwrap(),
                );
                let y = JsonKeyValueMap::from(
                    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>("{\"b\":2,\"a\":1}").unwrap(),
                );
                let z = JsonKeyValueMap::from(
                    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>("{\"a\":1,\"b\":3}").unwrap(),
                );
                out.push(format!(
                    "map order {} {} default {:?}",
                    x == y,
                    x == z,
                    JsonKeyValueMap::default()
                ));
                out
            }
        }
    };
}

loader_cases!(up, up_util);
loader_cases!(wz, wz_util);

const SPECS: [&str; 24] = [
    "\"/tmp\"",
    "\"~/x\"",
    "\"$HOME/x\"",
    "\"${HOME}/x\"",
    "\"$WZ_NO_SUCH_VARIABLE/x\"",
    "{\"kind\":\"path\",\"value\":\"/a\"}",
    "{\"kind\":\"path\"}",
    "{\"kind\":\"path\",\"value\":null}",
    "{\"kind\":\"path\",\"value\":\"$WZ_NO_SUCH_VARIABLE\"}",
    "{\"kind\":\"current_exe_parent\"}",
    "{\"kind\":\"current_exe_parent\",\"value\":\"ignored\"}",
    "{\"kind\":\"other\"}",
    "{}",
    "{\"value\":\"x\"}",
    "1",
    "null",
    "[]",
    "true",
    "\"\"",
    "{\"kind\":\"path\",\"value\":\"/a\",\"extra\":1}",
    " \"/a\" ",
    "\"/a\" trailing",
    "",
    "\"unterminated",
];

#[test]
fn both_crates_parse_every_search_directory_spec_alike() {
    let _g = serial();
    let mut ok = 0;
    for s in SPECS {
        let (a, b) = (up::spec_text(&[s]), wz::spec_text(&[s]));
        assert_eq!(a, b, "{s:?}");
        ok += a.starts_with("ok") as usize;
    }
    // Lists of more than one, and none.
    for pair in SPECS.windows(2) {
        let (a, b) = (up::spec_text(pair), wz::spec_text(pair));
        assert_eq!(a, b, "{pair:?}");
    }
    assert_eq!(up::spec_text(&[]), wz::spec_text(&[]));
    // Some of them are a directory, and some are an error somewhere on the way.
    assert!(ok > 8 && ok < SPECS.len(), "{ok}");
    assert!(up::spec_text(&["\"/tmp\""]).contains("path \"/tmp\""));
    assert!(up::spec_text(&["{\"kind\":\"path\"}"])
        .contains("`path` specs should have a `value` field"));
    assert!(up::spec_text(&["\"$WZ_NO_SUCH_VARIABLE/x\""]).contains("invalid"));
}

#[test]
fn both_crates_hold_the_defaults_the_equality_and_the_serde_forms_alike() {
    let _g = serial();
    assert_eq!(up::defaults(), wz::defaults());
    assert!(up::defaults().len() > 8);
    for doc in SPECS.iter().copied().chain([
        "[]",
        "[\"a\"]",
        "[\"a\",{\"kind\":\"path\",\"value\":\"b\"}]",
        "[{\"kind\":\"current_exe_parent\"}]",
        "{}",
        "[1]",
        "[null]",
        "[[]]",
        "{\"0\":\"a\"}",
    ]) {
        let (a, b) = (up::dirs_from_json(doc), wz::dirs_from_json(doc));
        assert_eq!(a, b, "{doc:?}");
        let (a, b) = (up::dir_from_json(doc), wz::dir_from_json(doc));
        assert_eq!(a, b, "{doc:?}");
    }
    // A list written and read again is the list, for both.
    let written = up::dirs_from_json("[\"a\",{\"kind\":\"path\",\"value\":\"b\"}]");
    assert!(
        written.contains("-> [\"a\",{\"kind\":\"path\",\"value\":\"b\"}]"),
        "{written}"
    );
}

#[test]
fn both_crates_build_a_loader_alike() {
    let _g = serial();
    assert_eq!(up::basics(), wz::basics());
    let b = up::basics();
    assert!(
        b[0].contains("\"lib\"") && b[0].contains("\".so\""),
        "{b:?}"
    );
}

#[test]
fn both_crates_load_a_file_alike() {
    let _g = serial();
    let root = up::root();
    assert_eq!(root, wz::root());
    let missing = format!("{root}/good/nothing.so");
    let relative = format!("{root}/good/../good/libwzfixture.so");
    let via_link_dir = format!("{root}/dup/libwzfixture.so");
    let cases = [
        format!("{root}/good/libwzfixture.so"),
        relative,
        via_link_dir,
        format!("{root}/good/libwzbad.so"),
        format!("{root}/good/notalib.txt"),
        format!("{root}/good/libwzdir.so"),
        format!("{root}/good"),
        missing,
        format!("{root}/empty"),
        "".to_string(),
        "/".to_string(),
        "$WZ_NO_SUCH_VARIABLE/x".to_string(),
        "~/no/such/file".to_string(),
        "\0".to_string(),
    ];
    let (mut ok, mut err) = (0, 0);
    for c in &cases {
        let (a, b) = (up::load_file(c), wz::load_file(c));
        assert_eq!(a, b, "{c:?}");
        if a.starts_with("ok") {
            ok += 1
        } else {
            err += 1
        }
    }
    assert!(ok >= 3 && err >= 8, "{ok} {err}");
    // The canonical path is the path of the library behind a link.
    assert!(
        up::load_file(&cases[0]).contains("libc.so"),
        "{}",
        up::load_file(&cases[0])
    );
}

#[test]
fn both_crates_search_and_load_alike() {
    let _g = serial();
    let cases: [(&[&str], &str); 12] = [
        (&["good"], "wzfixture"),
        (&["empty", "good"], "wzfixture"),
        (&["dup", "good"], "wzfixture"),
        (&["good", "dup"], "wzdup"),
        (&["empty"], "wzfixture"),
        (&["good"], "wzmissing"),
        (&["good"], "wzbad"),
        (&["good"], "wzdir"),
        (&["good"], ""),
        (&["weird"], ""),
        (&["nosuchdir", "good"], "wzother"),
        (&[], "wzfixture"),
    ];
    let (mut found, mut failed) = (0, 0);
    for (names, name) in cases {
        let (a, b) = (up::search(names, name), wz::search(names, name));
        assert_eq!(a, b, "{names:?} {name:?}");
        if a.starts_with("ok") {
            found += 1
        } else {
            failed += 1
        }
    }
    assert!(found >= 5 && failed >= 5, "{found} {failed}");
    // A loader with no search paths at all says none, and one with paths and no library errs.
    assert_eq!(up::search_empty("wzfixture"), wz::search_empty("wzfixture"));
    assert_eq!(up::search_empty("wzfixture"), "none");
    assert!(up::search(&["good"], "wzmissing").contains("not found"));
}

#[test]
fn both_crates_load_all_with_a_prefix_alike() {
    let _g = serial();
    let mut rows = Vec::new();
    for names in [
        &["good"][..],
        &["good", "dup"],
        &["dup", "good"],
        &["empty"],
        &["good", "empty", "nosuchdir"],
        &["weird"],
        &[],
    ] {
        for prefix in [
            None,
            Some(""),
            Some("wz"),
            Some("wzf"),
            Some("wzfixture"),
            Some("wzd"),
            Some("nomatch"),
            Some("x"),
            Some("wzbad"),
        ] {
            let (a, b) = (up::load_all(names, prefix), wz::load_all(names, prefix));
            assert_eq!(a, b, "{names:?} {prefix:?}");
            rows.push(a);
        }
    }
    // A loader of directories finds libraries, deduplicated by name across the directories, and
    // skips the file that is not a library and the directory with the name of one.
    let all_good = up::load_all(&["good", "dup"], Some("wz"));
    assert!(all_good.starts_with("4 "), "{all_good}");
    assert!(
        all_good.contains("libwzfixture.so") && all_good.contains("libwzdup.so"),
        "{all_good}"
    );
    assert!(
        !all_good.contains("libwzbad") && !all_good.contains("libwzdir"),
        "{all_good}"
    );
    assert!(rows.iter().any(|r| r.starts_with("0 ")));
    // A loader with no search paths has nothing to search.
    assert_eq!(up::load_all_empty(None), wz::load_all_empty(None));
    assert_eq!(up::load_all_empty(Some("wz")), "none");
}

#[test]
fn both_crates_read_the_name_of_a_plugin_alike() {
    let _g = serial();
    let mut some = 0;
    for p in [
        "libfoo.so",
        "foo.so",
        "libfoo",
        "foo",
        "lib.so",
        "libso",
        "lib",
        ".so",
        "",
        "/a/b/libx.so",
        "/a/b/x",
        "libx.so/",
        "a/libx.so/..",
        "liblibfoo.so.so",
        "libfoo.so.1",
        "日本libx.so",
        "libé.so",
    ] {
        let path = PathBuf::from(p);
        let (a, b) = (up::plugin_name(&path), wz::plugin_name(&path));
        assert_eq!(a, b, "{p:?}");
        some += !a.starts_with("None") as usize;
    }
    assert!(some >= 12, "{some}");
    // A name that is not UTF-8 has no plugin name.
    let odd = PathBuf::from(OsString::from_vec(b"libwz\xff.so".to_vec()));
    assert_eq!(up::plugin_name(&odd), wz::plugin_name(&odd));
    assert!(up::plugin_name(&odd).starts_with("None"));
    assert_eq!(
        up::plugin_name(Path::new("libfoo.so")),
        "Some(\"foo\") Some(\"foo\")"
    );
}

#[test]
fn a_file_name_that_is_the_prefix_and_the_suffix_panics_upstream_and_is_skipped_by_wz() {
    let _g = serial();
    // `lib.so` for the prefix `lib.` and the suffix `.so`.
    let (a, b) = (
        up::load_all(&["weird"], Some(".")),
        wz::load_all(&["weird"], Some(".")),
    );
    assert_eq!(a, PANIC, "{a}");
    assert_ne!(b, PANIC, "{b}");
    assert!(b.starts_with("0 "), "{b}");
    // The same directory read for a prefix that does not overlap is read alike and loads its
    // libraries, so the class is the overlap and not the directory.
    for prefix in [None, Some("x"), Some("")] {
        let (a, b) = (
            up::load_all(&["weird"], prefix),
            wz::load_all(&["weird"], prefix),
        );
        assert_eq!(a, b, "{prefix:?}");
        assert_ne!(a, PANIC, "{prefix:?}");
    }
    // `lib.so` is a library of the name that is empty, found by the prefix `` and the suffix.
    let all = up::load_all(&["weird"], None);
    assert!(
        all.starts_with("2 ") && all.contains("weird/lib.so") && all.contains("weird/libx.so"),
        "{all}"
    );
    // And every other directory is read alike with the prefix `.`: it holds no such file.
    for names in [&["good"][..], &["dup"], &["empty"], &["good", "dup"]] {
        assert_eq!(
            up::load_all(names, Some(".")),
            wz::load_all(names, Some("."))
        );
    }
}

#[test]
fn both_crates_read_strings_through_pointers_alike() {
    let _g = serial();
    let (u, w) = (up::strings(), wz::strings());
    assert_eq!(u, w);
    assert_eq!(u.len(), 13);
    assert_eq!(u[0], "hello");
    assert!(u[3].contains('\u{FFFD}'), "{u:?}");
    assert_eq!(u[4], "a");
    assert_eq!(u[7], "hi");
    assert_eq!(u[9], "💖");
    assert!(
        u[10].contains('\u{FFFD}') && u[11].contains('\u{FFFD}'),
        "{u:?}"
    );
}

#[test]
fn both_crates_wrap_json_alike() {
    let _g = serial();
    let (u, w) = (up::json(), wz::json());
    assert_eq!(u, w);
    assert!(u.len() > 20);
    assert!(u.iter().any(|r| r.starts_with("order true false")), "{u:?}");
    assert!(
        u.iter().any(|r| r.starts_with("map order true false")),
        "{u:?}"
    );
}

/// The control: the comparison is on text, so an input that differs gives a row that differs.
#[test]
fn the_comparison_sees_a_loader_that_differs() {
    let _g = serial();
    assert_ne!(
        wz::search(&["good"], "wzfixture"),
        wz::search(&["good"], "wzother")
    );
    assert_ne!(
        wz::load_all(&["good"], Some("wzf")),
        wz::load_all(&["good"], Some("wz"))
    );
    assert_ne!(wz::spec_text(&["\"/a\""]), wz::spec_text(&["\"/b\""]));
    assert_ne!(
        wz::plugin_name(Path::new("libfoo.so")),
        wz::plugin_name(Path::new("libbar.so"))
    );
}
