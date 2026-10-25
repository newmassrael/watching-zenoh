// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-config`, the files (the first slice of the crate): upstream's crate (`up_config`) and wz's
//! (`wz_config`) given the same files to read, results equal as text.
//!
//! * `Config::from_file` over a directory of files of every kind a user may hand it: JSON, JSON5,
//!   YAML and TOML that are good, an extension that is not supported or is spelled in capitals, no
//!   extension, an empty file, a file that does not parse, a file that parses and is not a valid
//!   configuration (a key that does not exist, a user without a password), a directory, a file that
//!   is not there.
//! * The files a plugin section includes (`__config__`): a file, a file that includes a file, a
//!   loop, a path that is not there, a value that is not a string, an included file that is not an
//!   object, one that names the property at its top level, YAML and a type that is not supported.
//!
//! Upstream reads the extension of the path with `to_str().unwrap()`, so a path whose extension is
//! not UTF-8 panics in `Config::from_file` where the user meant an error (the included files are
//! named by a JSON string, which is always UTF-8, so there the unwrap cannot fail). That is a
//! class, built by hand, counted and held on both sides: wz refuses the file as one of a type that
//! is not supported.

use std::{
    cell::Cell,
    fs,
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::Once,
};

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f`, and says `None` if it panicked, without the report of the panic: a reader that panics
/// is a result of this comparison, and the report would be noise.
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

/// A directory of files that both crates read. Its path is part of some error texts, so one
/// directory serves both and the texts that carry it are made relative.
struct Files {
    dir: PathBuf,
}

impl Files {
    fn new(tag: &str) -> Files {
        let dir = std::env::temp_dir().join(format!("wz-config-file-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Files { dir }
    }
    fn write(&self, name: &str, content: &str) -> PathBuf {
        let p = self.dir.join(name);
        fs::write(&p, content).unwrap();
        p
    }
    fn rel(&self, text: &str) -> String {
        text.replace(self.dir.to_str().unwrap(), "<dir>")
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The files of the first group, as (name, content).
fn plain_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("ok.json5", r#"{ mode: "router", id: "abc", listen: { endpoints: ["tcp/127.0.0.1:7447"] } }"#),
        ("ok.json", r#"{ "mode": "client", "connect": { "endpoints": ["tcp/localhost:7447"] } }"#),
        ("ok.yaml", "mode: peer\nid: a1b2\nscouting:\n  multicast:\n    enabled: false\n"),
        ("ok.yml", "mode: router\nlisten:\n  endpoints:\n    - tcp/0.0.0.0:7447\n"),
        ("ok.toml", "mode = \"router\"\nid = \"abc\"\n\n[listen]\nendpoints = [\"tcp/localhost:7448\"]\n"),
        ("commented.json5", "// a comment\n{ /* inline */ mode: 'peer', metadata: { a: [1, 2, 3], }, }\n"),
        ("modes.json5", r#"{ connect: { timeout_ms: { router: -1, peer: 5000, client: 0 }, exit_on_failure: { client: true } } }"#),
        ("empty.json5", ""),
        ("blank.json5", "   \n"),
        ("noext", r#"{ mode: "router" }"#),
        ("bad.txt", r#"{ mode: "router" }"#),
        ("caps.JSON5", r#"{ mode: "router" }"#),
        ("dotted.name.json5", r#"{ mode: "client" }"#),
        ("broken.json5", "{ mode: "),
        ("broken.json", "{ \"mode\": \"router\", }}"),
        ("broken.yaml", "mode: [router\n"),
        ("broken.toml", "mode = \n"),
        ("unknown_key.json5", r#"{ nonsense: 1 }"#),
        ("unknown_section.json5", r#"{ transport: { link: { nonsense: true } } }"#),
        ("bad_mode.json5", r#"{ mode: "emperor" }"#),
        ("bad_type.json5", r#"{ listen: { endpoints: "tcp/127.0.0.1:7447" } }"#),
        ("user_no_password.json5", r#"{ transport: { auth: { usrpwd: { user: "a" } } } }"#),
        ("queue_zero.json5", r#"{ transport: { link: { tx: { queue: { size: { data: 0 } } } } } }"#),
        ("queue_ok.json5", r#"{ transport: { link: { tx: { queue: { size: { data: 16 } } } } } }"#),
        ("resolution_ok.json5", r#"{ transport: { link: { tx: { sequence_number_resolution: "16bit" } } } }"#),
        ("resolution_bad.json5", r#"{ transport: { link: { tx: { sequence_number_resolution: "7bit" } } } }"#),
        ("plugins_ok.json5", r#"{ plugins: { rest: { http_port: 8000 }, storage_manager: { __required__: true } } }"#),
        ("plugins_array.json5", r#"{ plugins: [1, 2] }"#),
        ("qos.json5", r#"{ qos: { publication: [ { key_exprs: ["a/**"], config: { priority: "data_high", express: true } } ] } }"#),
        ("namespace.json5", r#"{ namespace: "ns/one" }"#),
        ("namespace_wild.json5", r#"{ namespace: "ns/*" }"#),
        ("deprecated.json5", r#"{ routing: { router: { peers_failover_brokering: true }, peer: { mode: "x" } } }"#),
        ("wide_id.json5", r#"{ id: "0123456789abcdef0123456789abcdef00" }"#),
        ("utf8_bom.json5", "\u{feff}{ mode: \"peer\" }"),
    ]
}

/// The files of the second group: a plugin section that includes files. A config file names its
/// includes by absolute path, since upstream resolves the first level against the directory the
/// process runs in and not the one of the file.
fn include_files(dir: &Path) -> Vec<(String, String)> {
    let d = dir.to_str().unwrap();
    let cfg = |inner: &str| format!("{{ plugins: {{ p: {inner} }} }}");
    vec![
        ("inc_a.json5".into(), r#"{ x: 1, y: { z: 2 } }"#.into()),
        ("inc_b.yaml".into(), "x: 1\nlist:\n  - a\n  - b\n".into()),
        ("inc_chain.json5".into(), format!(r#"{{ child: {{ __config__: "inc_a.json5" }}, k: 1 }}"#)),
        ("inc_self.json5".into(), format!(r#"{{ more: {{ __config__: "inc_self.json5" }} }}"#)),
        ("inc_top.json5".into(), r#"{ __config__: "inc_a.json5", a: 1 }"#.into()),
        ("inc_array.json5".into(), r#"[1, 2, 3]"#.into()),
        ("inc_text.txt".into(), r#"{ a: 1 }"#.into()),
        ("inc_bad.json5".into(), "{ a: ".into()),
        ("inc_override.json5".into(), r#"{ x: 99, own: 3 }"#.into()),
        ("inc_sub.json5".into(), r#"{ sub: { z: 1 } }"#.into()),
        ("cfg_one.json5".into(), cfg(&format!(r#"{{ __config__: "{d}/inc_a.json5" }}"#))),
        ("cfg_yaml.json5".into(), cfg(&format!(r#"{{ __config__: "{d}/inc_b.yaml" }}"#))),
        ("cfg_chain.json5".into(), cfg(&format!(r#"{{ __config__: "{d}/inc_chain.json5" }}"#))),
        ("cfg_loop.json5".into(), cfg(&format!(r#"{{ __config__: "{d}/inc_self.json5" }}"#))),
        ("cfg_top.json5".into(), cfg(&format!(r#"{{ __config__: "{d}/inc_top.json5" }}"#))),
        ("cfg_array.json5".into(), cfg(&format!(r#"{{ __config__: "{d}/inc_array.json5" }}"#))),
        ("cfg_text.json5".into(), cfg(&format!(r#"{{ __config__: "{d}/inc_text.txt" }}"#))),
        ("cfg_bad.json5".into(), cfg(&format!(r#"{{ __config__: "{d}/inc_bad.json5" }}"#))),
        ("cfg_missing.json5".into(), cfg(&format!(r#"{{ __config__: "{d}/nowhere.json5" }}"#))),
        ("cfg_number.json5".into(), cfg(r#"{ __config__: 7 }"#)),
        ("cfg_override.json5".into(), cfg(&format!(r#"{{ x: 1, keep: 2, __config__: "{d}/inc_override.json5" }}"#))),
        // the section the included file replaces holds an include of its own that cannot be read:
        // upstream drops the replaced section without looking at it, so the file reads
        ("cfg_shadow.json5".into(), cfg(&format!(r#"{{ sub: {{ __config__: "{d}/nowhere.json5" }}, __config__: "{d}/inc_sub.json5" }}"#))),
        ("cfg_nested.json5".into(), cfg(&format!(r#"{{ deep: {{ deeper: {{ __config__: "{d}/inc_a.json5" }} }} }}"#))),
        ("cfg_two.json5".into(), format!(r#"{{ plugins: {{ p: {{ __config__: "{d}/inc_a.json5" }}, q: {{ __config__: "{d}/inc_b.yaml" }} }} }}"#)),
        ("cfg_plugin_not_object.json5".into(), r#"{ plugins: { p: 5 } }"#.into()),
        ("cfg_directory.json5".into(), cfg(&format!(r#"{{ __config__: "{d}" }}"#))),
    ]
}

macro_rules! file_cases {
    ($name:ident, $cfg:ident) => {
        mod $name {
            use super::*;

            fn one(files: &Files, name: &str) -> String {
                let path = files.dir.join(name);
                match guarded(|| $cfg::Config::from_file(&path)) {
                    None => PANIC.to_string(),
                    Some(Ok(c)) => format!("ok {}", files.rel(&c.to_string())),
                    Some(Err(e)) => format!("err {}", files.rel(&plain(&e))),
                }
            }

            /// Every file of the first group, one line each.
            pub fn plain_group(files: &Files) -> Vec<String> {
                let mut out: Vec<String> = plain_files()
                    .iter()
                    .map(|(name, _)| format!("{name}: {}", one(files, name)))
                    .collect();
                out.push(format!("directory: {}", {
                    let p = files.dir.join("a-directory.json5");
                    fs::create_dir_all(&p).unwrap();
                    one(files, "a-directory.json5")
                }));
                out.push(format!("missing: {}", one(files, "not-there.json5")));
                out
            }

            /// Every file of the second group, one line each.
            pub fn include_group(files: &Files) -> Vec<String> {
                include_files(&files.dir)
                    .iter()
                    .filter(|(name, _)| name.starts_with("cfg_"))
                    .map(|(name, _)| format!("{name}: {}", one(files, name)))
                    .collect()
            }

            /// A path whose extension is not UTF-8, which only a Unix file name can have.
            #[cfg(unix)]
            pub fn odd_extension(files: &Files) -> String {
                use std::{ffi::OsString, os::unix::ffi::OsStringExt};
                let mut name = b"odd.".to_vec();
                name.push(0xff);
                let path = files.dir.join(OsString::from_vec(name));
                fs::write(&path, r#"{ mode: "router" }"#).unwrap();
                match guarded(|| $cfg::Config::from_file(&path)) {
                    None => PANIC.to_string(),
                    Some(Ok(c)) => format!("ok {}", c),
                    Some(Err(e)) => format!("err {}", files.rel(&plain(&e))),
                }
            }
        }
    };
}

file_cases!(up, up_config);
file_cases!(wz, wz_config);

/// A directory with every file of both groups written.
fn populated(tag: &str) -> Files {
    let files = Files::new(tag);
    for (name, content) in plain_files() {
        files.write(name, content);
    }
    for (name, content) in include_files(&files.dir) {
        files.write(&name, &content);
    }
    files
}

/// Prints a transcript when `WZ_CONFIG_TRANSCRIPT` is set, so what a group holds can be read.
fn show(group: &str, lines: &[String]) {
    if std::env::var_os("WZ_CONFIG_TRANSCRIPT").is_some() {
        for line in lines {
            println!("{group}: {line}");
        }
    }
}

fn first_difference(a: &[String], b: &[String]) -> Option<String> {
    assert_eq!(a.len(), b.len(), "the groups differ in length");
    a.iter()
        .zip(b)
        .find(|(x, y)| x != y)
        .map(|(x, y)| format!("upstream: {x}\nwz:       {y}"))
}

#[test]
fn files_read_alike() {
    let files = populated("plain");
    let up = up::plain_group(&files);
    let wz = wz::plain_group(&files);
    show("files", &up);
    assert!(up.len() > 30, "{}", up.len());
    if let Some(d) = first_difference(&up, &wz) {
        panic!("{d}");
    }
    // The group is not vacuous: some files are read and some are refused.
    assert!(up.iter().any(|l| l.contains(": ok ")), "{up:#?}");
    assert!(up.iter().any(|l| l.contains(": err ")), "{up:#?}");
}

#[test]
fn includes_read_alike() {
    let files = populated("include");
    let up = up::include_group(&files);
    let wz = wz::include_group(&files);
    show("includes", &up);
    assert!(up.len() >= 16, "{}", up.len());
    // the replaced section is dropped without its own include being read
    assert!(
        up.iter().any(|l| l.starts_with("cfg_shadow.json5: ok ")),
        "{up:#?}"
    );
    if let Some(d) = first_difference(&up, &wz) {
        panic!("{d}");
    }
    assert!(up.iter().any(|l| l.contains(": ok ")), "{up:#?}");
    assert!(up.iter().any(|l| l.contains(": err ")), "{up:#?}");
}

#[test]
fn the_comparison_sees_a_file_that_differs() {
    let files = populated("control-a");
    let other = populated("control-b");
    other.write("ok.json5", r#"{ mode: "client", id: "abc" }"#);
    let up = up::plain_group(&files);
    let wz = wz::plain_group(&other);
    assert!(first_difference(&up, &wz).is_some());
    // and an included file that differs: each directory's configurations name their own
    // included file
    other.write("inc_a.json5", r#"{ x: 2, y: { z: 2 } }"#);
    let up = up::include_group(&files);
    let wz = wz::include_group(&other);
    assert!(first_difference(&up, &wz).is_some());
}

/// The class: a path whose extension is not UTF-8. Upstream panics, wz refuses the file as one of
/// a type that is not supported. Held on both sides, so a change on either is seen.
#[cfg(unix)]
#[test]
fn a_path_whose_extension_is_not_utf8_is_a_refusal_in_wz() {
    let files = Files::new("odd");
    let up = up::odd_extension(&files);
    let wz = wz::odd_extension(&files);
    assert_eq!(up, PANIC);
    assert!(
        wz.starts_with("err Unsupported file type"),
        "wz answered {wz:?}"
    );
}
