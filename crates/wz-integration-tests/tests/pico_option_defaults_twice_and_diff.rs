// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — the VALUES every `*_options_default` writes,
//! compiled once against the real zenoh-pico and once against wz, and compared
//! byte for byte.
//!
//! ## What this exists to catch
//!
//! A layout gate pins the SIZE and the field OFFSETS of an options struct, and a
//! symbol census pins that the function EXISTS. Neither says what the function
//! writes, and a C program takes its defaults from it: it declares a struct,
//! calls the default, changes the one field it cares about, and passes the rest
//! on. A default that is wrong does nothing until the field is read, so it stays
//! wrong for as long as the field is ignored, and stops being invisible the day
//! a round makes the field mean something.
//!
//! That is not hypothetical. `z_publisher_options_default` wrote priority 0,
//! pico's CONTROL priority, where pico writes `Z_PRIORITY_DEFAULT` (Data, 5); the
//! comment above it said the values were "the enum's zero values", which held for
//! three of the four. It was found by reading one struct, not by any gate.
//!
//! ## The population, and how a function is measured
//!
//! The population is every `*_options_default` the oracle LIBRARY exports: what
//! a program can link, and the build's own answer to which defaults exist under
//! its feature set. It is not a list written here. The headers supply the struct
//! each one fills, and where a function is defined and declared by no header
//! (`z_close_options_default` is) the driver declares it, for the struct its
//! name says; that naming is checked against every function a header does
//! declare.
//!
//! Each function is called twice on a buffer of the struct's size, once filled
//! with `0x00` and once with `0xff`. A byte the two calls leave equal was WRITTEN
//! by the function (to that value); a byte that follows the fill was not touched
//! (padding, or a field the default leaves to the caller). That separation is
//! what makes the comparison about the function and not about its padding: a
//! struct literal in Rust and a field-by-field store in C leave the padding
//! differently, and neither is a difference a program can see.
//!
//! ## What counts as a difference
//!
//! A byte pico WRITES that wz writes differently, or does not write: a missing
//! or wrong default. That is the whole rule, and the other direction is left out
//! on purpose. A byte pico leaves alone has no value a program may rely on, and
//! wz's writes over such bytes are mostly padding: the struct literal is copied
//! from a temporary whose padding is whatever the stack held (measured: the same
//! junk on both fills, so the two-fill test cannot call it unwritten). Flagging
//! it would make this leg fail on the compiler's choices and not on a default.
//!
//! The reference arm's content is asserted BEFORE the equality: two empty
//! renderings are equal, and this leg would then be measuring the harness.
//!
//! ## The oracle is a build product
//!
//! `libzenohpico.so` and its headers come from `scripts/build-zenoh-pico-cli.sh`.
//! Absence is a hard FAIL rather than a skip.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    wz_capi_pico_cdylib, zenoh_pico_include_dirs, zenoh_pico_library_dir,
};

/// Every `(function, struct type)` a header under `zenoh-pico/api/` declares as
/// `void|z_result_t <name>_options_default(<type> *options);`, in name order.
///
/// A declaration may be wrapped over lines, so the scan works on the text with
/// its whitespace read as one space. Only a declaration counts: the token before
/// the name must be a return type, which keeps a call or a macro out.
fn declared_defaults(vendored_include: &Path) -> Vec<(String, String)> {
    let api = vendored_include.join("zenoh-pico/api");
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    let mut headers: Vec<PathBuf> = std::fs::read_dir(&api)
        .unwrap_or_else(|e| panic!("read {}: {e}", api.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "h"))
        .collect();
    headers.sort();
    for header in headers {
        let text = std::fs::read_to_string(&header).expect("read a header");
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut from = 0;
        while let Some(at) = flat[from..].find("_options_default(") {
            let end_of_name = from + at + "_options_default".len();
            from = end_of_name;
            let name_start = flat[..end_of_name]
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(0, |i| i + 1);
            let name = &flat[name_start..end_of_name];
            let before = flat[..name_start].trim_end();
            if !(before.ends_with("void") || before.ends_with("z_result_t")) {
                continue;
            }
            // `(<type> *options);`
            let params = &flat[end_of_name + 1..];
            let Some(close) = params.find(')') else {
                continue;
            };
            let param = params[..close].trim();
            let Some(star) = param.find('*') else {
                continue;
            };
            let ty = param[..star].trim();
            if ty.is_empty() || !param[star + 1..].trim().starts_with("options") {
                continue;
            }
            found.insert((name.to_owned(), ty.to_owned()));
        }
    }
    found.into_iter().collect()
}

/// Every `*_options_default` the library exports.
fn exported_defaults(lib: &Path) -> BTreeSet<String> {
    let out = Command::new("nm")
        .args(["-D", "--defined-only"])
        .arg(lib)
        .output()
        .expect("spawn nm");
    assert!(out.status.success(), "nm failed on {}", lib.display());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter(|s| s.ends_with("_options_default"))
        .map(str::to_owned)
        .collect()
}

/// The C driver: for each function, call it on a zero-filled and on a
/// ones-filled buffer of its struct's size and print `name size=N bytes=..`,
/// each byte the two calls agree on as two hex digits and each they do not as
/// `??`.
fn driver_source(population: &[(String, String)], undeclared: &[String]) -> String {
    let mut src = String::from(
        r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>
"#,
    );
    // A default the library defines and no header declares is declared here, so
    // the driver can call it; the struct is the one its name says.
    for name in undeclared {
        let ty = conventional_type(name);
        src.push_str(&format!("void {name}({ty} *options);\n"));
    }
    src.push_str(
        r#"

static void report(const char *name, const unsigned char *a, const unsigned char *b, size_t n) {
    printf("%s size=%zu bytes=", name, n);
    for (size_t i = 0; i < n; i++) {
        if (a[i] == b[i]) {
            printf("%02x", a[i]);
        } else {
            printf("??");
        }
    }
    printf("\n");
}

int main(void) {
"#,
    );
    for (name, ty) in population {
        src.push_str(&format!(
            "    {{\n        _Alignas(16) unsigned char a[sizeof({ty})];\n        \
             _Alignas(16) unsigned char b[sizeof({ty})];\n        \
             memset(a, 0x00, sizeof a);\n        memset(b, 0xff, sizeof b);\n        \
             (void){name}(({ty} *)a);\n        (void){name}(({ty} *)b);\n        \
             report(\"{name}\", a, b, sizeof a);\n    }}\n"
        ));
    }
    src.push_str("    return 0;\n}\n");
    src
}

/// Compile the driver against upstream's headers, linked to `lib`, and run it.
fn run_arm(dir: &Path, libdir: &Path, libname: &str, arm: &str, source: &str) -> Vec<String> {
    let src = dir.join(format!("defaults_{arm}.c"));
    std::fs::write(&src, source).expect("write driver source");
    let exe = dir.join(format!("defaults_{arm}"));
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let mut cmd = Command::new(&cc);
    cmd.arg(&src).arg("-DZENOH_LINUX");
    for inc in zenoh_pico_include_dirs() {
        cmd.arg(format!("-I{}", inc.display()));
    }
    cmd.arg("-o")
        .arg(&exe)
        .arg(format!("-L{}", libdir.display()))
        .arg(format!("-l{libname}"))
        .arg(format!("-Wl,-rpath,{}", libdir.display()));
    let built = cmd.output().expect("spawn C compiler");
    assert!(
        built.status.success(),
        "{arm} arm failed to build against {libname}:\n--- stderr ---\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(&exe)
        .output()
        .unwrap_or_else(|e| panic!("{arm}: run the driver: {e}"));
    assert!(
        ran.status.success(),
        "{arm}: the driver exited {:?}\n{}",
        ran.status,
        String::from_utf8_lossy(&ran.stderr)
    );
    String::from_utf8_lossy(&ran.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// One rendered line as `(name, size, bytes)` with the bytes split into their
/// two-character tokens.
fn parse(line: &str) -> (String, usize, Vec<String>) {
    let mut parts = line.split(' ');
    let name = parts.next().expect("a name").to_owned();
    let size = parts
        .next()
        .and_then(|s| s.strip_prefix("size="))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no size in {line:?}"));
    let hex = parts
        .next()
        .and_then(|s| s.strip_prefix("bytes="))
        .unwrap_or_else(|| panic!("no bytes in {line:?}"));
    let tokens: Vec<String> = hex
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    (name, size, tokens)
}

/// Every difference between the reference's rendering of one default and wz's,
/// by the rule in the module doc.
fn differences(
    reference: &(String, usize, Vec<String>),
    wz: &(String, usize, Vec<String>),
) -> Vec<String> {
    let mut out = Vec::new();
    if reference.1 != wz.1 {
        out.push(format!(
            "{}: sizeof is {} on the reference and {} on wz",
            reference.0, reference.1, wz.1
        ));
        return out;
    }
    for (i, (r, w)) in reference.2.iter().zip(&wz.2).enumerate() {
        match (r.as_str(), w.as_str()) {
            // pico leaves the byte alone: nothing to match, whatever wz wrote.
            ("??", _) => {}
            (written, "??") => out.push(format!(
                "{}: byte {i} is written {written} by pico and left alone by wz",
                reference.0
            )),
            (r, w) if r == w => {}
            (r, w) => out.push(format!(
                "{}: byte {i} is {r} on the reference and {w} on wz",
                reference.0
            )),
        }
    }
    out
}

/// The struct a default fills, by the naming every declared one follows:
/// `<stem>_options_default` fills a `<stem>_options_t`.
fn conventional_type(name: &str) -> String {
    let stem = name
        .strip_suffix("_default")
        .unwrap_or_else(|| panic!("{name} is not a default"));
    format!("{stem}_t")
}

// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries; run by run-ci Layer E"]
fn every_options_default_writes_the_values_the_real_pico_writes() {
    let include_dirs = zenoh_pico_include_dirs();
    let declared = declared_defaults(&include_dirs[1]);
    let reference_lib = zenoh_pico_library_dir();
    let exported = exported_defaults(&reference_lib.join("libzenohpico.so"));

    // The population is what the real LIBRARY exports: that is what a program
    // can link, and it is the build's own answer to which defaults exist under its
    // feature set (the headers also declare defaults the configuration compiles
    // out, such as the single-threaded `zp_read` family). It is not a list
    // written here.
    //
    // The struct each fills comes from the header when the header declares the
    // function and from the naming every declared one follows when it does not
    // (`z_close_options_default` is DEFINED by the library and declared by no
    // header). The convention is checked against every declaration, so a
    // function it would get wrong is a failure and not a compile error later.
    let mut population: Vec<(String, String)> = Vec::new();
    let mut undeclared: Vec<String> = Vec::new();
    for name in &exported {
        let by_convention = conventional_type(name);
        match declared.iter().find(|(n, _)| n == name) {
            Some((_, ty)) => {
                assert_eq!(
                    ty, &by_convention,
                    "{name} is declared to fill {ty}, not the {by_convention} its name says"
                );
                population.push((name.clone(), ty.clone()));
            }
            None => {
                undeclared.push(name.clone());
                population.push((name.clone(), by_convention));
            }
        }
    }
    assert!(
        population.len() >= 30,
        "only {} defaults exported (the headers declare {}); the library is not the real \
         one",
        population.len(),
        declared.len()
    );

    let source = driver_source(&population, &undeclared);
    let dir = tempfile::tempdir().expect("tempdir");
    let wz_libdir = wz_capi_pico_cdylib()
        .parent()
        .expect("cdylib has a parent directory")
        .to_path_buf();
    let reference = run_arm(
        dir.path(),
        &reference_lib,
        "zenohpico",
        "reference",
        &source,
    );
    let wz = run_arm(dir.path(), &wz_libdir, "wz_capi_pico", "wz", &source);

    // ANTI-VACUITY: the REFERENCE wrote something for every function, and it
    // wrote the value this leg was built on. Two renderings that wrote nothing
    // are equal and prove nothing.
    assert_eq!(
        reference.len(),
        population.len(),
        "the reference driver printed {} lines for {} functions",
        reference.len(),
        population.len()
    );
    assert_eq!(wz.len(), population.len(), "the wz driver's line count");
    let reference: Vec<_> = reference.iter().map(|l| parse(l)).collect();
    let wz: Vec<_> = wz.iter().map(|l| parse(l)).collect();
    for r in &reference {
        assert!(
            r.2.iter().any(|t| t != "??"),
            "the reference default {} wrote no byte at all, so it measures nothing",
            r.0
        );
    }
    let publisher = reference
        .iter()
        .find(|r| r.0 == "z_publisher_options_default")
        .expect("the publisher default is in the population");
    assert_eq!(
        publisher.2.get(12).map(String::as_str),
        Some("05"),
        "pico's publisher default should write Z_PRIORITY_DEFAULT (5) at the priority \
         field: {publisher:?}"
    );

    let mut found = Vec::new();
    for (r, w) in reference.iter().zip(&wz) {
        assert_eq!(r.0, w.0, "the two drivers print in the same order");
        found.extend(differences(r, w));
    }
    assert!(
        found.is_empty(),
        "wz's option defaults differ from the real zenoh-pico's ({} in all):\n{}",
        found.len(),
        found.join("\n")
    );
}
