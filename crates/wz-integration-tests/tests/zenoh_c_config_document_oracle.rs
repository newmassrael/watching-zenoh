// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — the CONFIG DOCUMENT, read across the two
//! implementations.
//!
//! R2303 (open-debt item 636). `zc_config_to_string` is a drop-in door: a
//! program calls it and hands the text to `zenohd -c`, to a peer built against
//! the real zenoh-c, or back to its own `zc_config_from_str`. wz emitted a FLAT
//! key map (`{"connect/endpoints": […]}`) where upstream emits a NESTED
//! document, and NOTHING in this tree compared the two — measured before the
//! change: `grep -rn zc_config_to_string crates/` found no test and no lane.
//!
//! ## What the two sides are held to, and what they are NOT
//!
//! BYTE identity is unattainable and asserting it would be a lie about what a
//! drop-in is. Upstream serializes zenoh's whole `Config` — 2,916 bytes for a
//! default at 1.10.0, most of them `null`, because that struct is what it holds
//! — while wz's `ConfigState` keeps only the keys a caller inserted and models
//! no schema. Two implementations with different internal models cannot emit
//! the same bytes.
//!
//! What they CAN be held to is that each side's document is READ by the other
//! with every value arriving intact, and this file holds them to it in all FOUR
//! directions — wz→wz, wz→ref, ref→wz, ref→ref. The self directions are the
//! round trip; the cross directions are the drop-in claim. They are run as one
//! product rather than as a listed pair, so neither can be dropped quietly.
//!
//! ## Nothing here transcribes an expected value
//!
//! * The corpus is upstream's own `Z_CONFIG_*` defines, read out of
//!   `zenoh_constants.h`. A key added upstream joins the corpus with no edit
//!   here, and an EMPTY corpus fails rather than passing vacuously.
//! * The witness value for each key is DISCOVERED by asking the reference
//!   library: the first literal off one generic ladder that it both accepts and
//!   reads back DIFFERENTLY from that key's default. A key with no such literal
//!   is a failure, never a skip — a witness equal to the default cannot tell a
//!   document that carried the value from one that carried nothing.
//! * The expected value on the far side is what THAT library says after a
//!   direct insert of the same witness, so no cross-implementation assumption
//!   about spelling is made anywhere.
//!
//! ## The population of DOORS is derived too
//!
//! Open-debt item 636 named ONE door. There were three: `zc_config_to_string`
//! emitting, and TWO separate copies of a line scanner reading —
//! `zc_config_from_str` and `zc_config_from_file`, which had drifted into
//! duplicates of each other. A gate that drove only the door the item named
//! would have closed the item and left the file door broken, so the reader set
//! is derived from upstream's header (`zenoh_commons.h`) rather than listed
//! here, and the probe REPORTS which doors it drove so the two can be compared.
//! A config function upstream declares that this file cannot classify is a
//! failure.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle, zenoh_c_shared_library,
};

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<PathBuf> {
    match zenoh_c_oracle() {
        Some((include, _libdir, _examples)) => Some(include),
        None => {
            eprintln!(
                "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers \
                 and libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX). \
                 Layer C1cc with WZ_C1CC_REQUIRE=1 fails instead of skipping."
            );
            None
        }
    }
}

/// The probe source.
///
/// C rather than a Rust `extern` block, on the sibling oracle's reasoning: the
/// header IS the ABI here, so the probe must be compiled BY a C compiler
/// AGAINST that header for the comparison to mean what it claims.
///
/// It never frees a config. A probe process runs one command and exits, and a
/// `z_config_drop` here would test this file's grasp of the move macros rather
/// than the doors under test — which the crate's own unit tests already cover.
const PROBE: &str = r#"/* `setenv` is POSIX, and the shared compile helper builds with `-std=c11`,
   under which glibc hides it. Without this the compiler IMPLICITLY declares
   what it cannot see — and an implicit declaration returns `int`, so a
   pointer-returning function comes back TRUNCATED. That is not hypothetical:
   the first draft of this probe used `strdup` and segfaulted on the wz arm,
   which read as a wz defect for exactly as long as it took to compile the probe
   by hand and see the warning nobody had read. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

/* The DOCUMENT READER doors this probe drives, in the order it drives them.
   Printed so the harness can compare the set against the one it derives from
   the header: a door added upstream and not driven here shows up as a
   difference rather than as silence. */
#define DOORS "zc_config_from_str,zc_config_from_substr,zc_config_from_file," \
              "zc_config_from_file_substr,zc_config_from_env"

static void show(const char *prefix, z_owned_string_t *s) {
    printf("%s=%.*s\n", prefix, (int)z_string_len(z_string_loan(s)),
           z_string_data(z_string_loan(s)));
}

/* `zc_config_get_from_str` on a loaned config, printed as `<prefix>=<value>`.
   An absent key prints the return code instead of an empty value, so "the
   document did not carry it" and "the document carried an empty string" are
   different lines. */
static void show_get(const char *prefix, const z_loaned_config_t *cfg, const char *key) {
    z_owned_string_t out;
    z_result_t rc = zc_config_get_from_str(cfg, key, &out);
    if (rc != 0) { printf("%s=<rc %d>\n", prefix, (int)rc); return; }
    show(prefix, &out);
}

static int mode_try(int argc, char **argv) {
    if (argc < 4) return 2;
    const char *key = argv[2], *value = argv[3];
    z_owned_config_t base;
    if (z_config_default(&base) != 0) return 3;
    show_get("default", z_config_loan(&base), key);
    z_owned_config_t cfg;
    if (z_config_default(&cfg) != 0) return 3;
    z_result_t rc = zc_config_insert_json5(z_config_loan_mut(&cfg), key, value);
    printf("insert.rc=%d\n", (int)rc);
    if (rc == 0) show_get("get", z_config_loan(&cfg), key);
    return 0;
}

/* Insert ONE value at `argv[2]` and read back a DIFFERENT path, `argv[4]`.

   The axis open-debt item 642 is about: a caller may state a subtree as one
   object (`insert("connect", "{\"endpoints\":[...]}")`) instead of stating its
   leaf, and upstream answers `get("connect/endpoints")` either way. Reading the
   SAME key back could never see that, which is why this mode exists beside
   `try` rather than as a flag on it. */
static int mode_try_at(int argc, char **argv) {
    if (argc < 5) return 2;
    const char *key = argv[2], *value = argv[3], *read_path = argv[4];
    z_owned_config_t cfg;
    if (z_config_default(&cfg) != 0) return 3;
    z_result_t rc = zc_config_insert_json5(z_config_loan_mut(&cfg), key, value);
    printf("insert.rc=%d\n", (int)rc);
    if (rc == 0) show_get("get", z_config_loan(&cfg), read_path);
    return 0;
}

static int mode_emit(int argc, char **argv) {
    if (argc < 3) return 2;
    const char *out_path = argv[2];
    z_owned_config_t cfg;
    if (z_config_default(&cfg) != 0) return 3;
    for (int i = 3; i < argc; i++) {
        char pair[1024];
        if (strlen(argv[i]) >= sizeof(pair)) return 2;
        strcpy(pair, argv[i]);
        char *eq = strchr(pair, '=');
        if (!eq) return 2;
        *eq = '\0';
        z_result_t rc = zc_config_insert_json5(z_config_loan_mut(&cfg), pair, eq + 1);
        printf("insert.%s.rc=%d\n", pair, (int)rc);
    }
    z_owned_string_t doc;
    z_result_t rc = zc_config_to_string(z_config_loan(&cfg), &doc);
    printf("to_string.rc=%d\n", (int)rc);
    if (rc != 0) return 0;
    size_t len = z_string_len(z_string_loan(&doc));
    printf("to_string.bytes=%zu\n", len);
    FILE *f = fopen(out_path, "wb");
    if (!f) return 4;
    fwrite(z_string_data(z_string_loan(&doc)), 1, len, f);
    fclose(f);
    return 0;
}

/* Every reader door, over the SAME document, printed as
   `<door>.<key>=<value>`. Driving them together is the point: two of them held
   separate copies of the parser in wz, and a probe that drove one would have
   reported the other's defect as absent. */
static int mode_read(int argc, char **argv) {
    if (argc < 3) return 2;
    const char *in_path = argv[2];
    size_t path_len = strlen(in_path);

    FILE *f = fopen(in_path, "rb");
    if (!f) return 4;
    static char text[262144];
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    text[n] = '\0';

    printf("doors=%s\n", DOORS);

    for (int door = 0; door < 5; door++) {
        z_owned_config_t cfg;
        z_result_t rc;
        const char *name;
        switch (door) {
        case 0:
            name = "zc_config_from_str";
            rc = zc_config_from_str(&cfg, text);
            break;
        case 1:
            name = "zc_config_from_substr";
            rc = zc_config_from_substr(&cfg, text, n);
            break;
        case 2:
            name = "zc_config_from_file";
            rc = zc_config_from_file(&cfg, in_path);
            break;
        case 3:
            name = "zc_config_from_file_substr";
            rc = zc_config_from_file_substr(&cfg, in_path, path_len);
            break;
        default:
            name = "zc_config_from_env";
            setenv("ZENOH_CONFIG", in_path, 1);
            rc = zc_config_from_env(&cfg);
            break;
        }
        printf("%s.rc=%d\n", name, (int)rc);
        if (rc != 0) continue;
        for (int i = 3; i < argc; i++) {
            char prefix[512];
            snprintf(prefix, sizeof(prefix), "%s.%s", name, argv[i]);
            show_get(prefix, z_config_loan(&cfg), argv[i]);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "try") == 0) return mode_try(argc, argv);
    if (strcmp(argv[1], "try_at") == 0) return mode_try_at(argc, argv);
    if (strcmp(argv[1], "emit") == 0) return mode_emit(argc, argv);
    if (strcmp(argv[1], "read") == 0) return mode_read(argc, argv);
    return 2;
}
"#;

/// The reader doors [`PROBE`] drives, as it names them itself.
const PROBE_READER_DOORS: &[&str] = &[
    "zc_config_from_str",
    "zc_config_from_substr",
    "zc_config_from_file",
    "zc_config_from_file_substr",
    "zc_config_from_env",
];

/// One candidate literal per rung, tried in order against the REFERENCE
/// library until one is both accepted and distinguishable from the key's
/// default.
///
/// ONE ladder for every key rather than a value per key, because a per-key
/// table would be this file asserting what each key means and would go stale
/// silently when upstream retyped one. The oracle decides; the ladder only
/// offers. A key no rung reaches is reported by name so the ladder can be
/// extended deliberately — `scouting/multicast/address` is why the locator rung
/// exists, and it was found by the check failing rather than by reading.
const LADDER: &[&str] = &[
    "\"client\"",
    "\"peer\"",
    "true",
    "false",
    "1234",
    "\"224.0.0.224:7446\"",
    "[\"tcp/127.0.0.1:17447\"]",
    "\"wz-witness\"",
];

/// One compiled arm of the probe.
struct Arm {
    name: &'static str,
    exe: PathBuf,
    libdir: PathBuf,
}

impl Arm {
    /// Run the probe and return its stdout as `key -> value` lines.
    fn run(&self, args: &[&str]) -> BTreeMap<String, String> {
        let out = Command::new(&self.exe)
            .args(args)
            .env("LD_LIBRARY_PATH", &self.libdir)
            .output()
            .unwrap_or_else(|why| panic!("spawn {}: {why}", self.exe.display()));
        assert!(
            out.status.success(),
            "the {} arm exited {:?} for {args:?}\n--- stderr ---\n{}",
            self.name,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr),
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }
}

/// Every `Z_CONFIG_*` key upstream's own header defines.
fn corpus(include: &Path) -> Vec<String> {
    let header = include.join("zenoh_constants.h");
    let text = std::fs::read_to_string(&header)
        .unwrap_or_else(|why| panic!("read {}: {why}", header.display()));
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("#define Z_CONFIG_") else {
            continue;
        };
        let Some((_name, value)) = rest.split_once(char::is_whitespace) else {
            continue;
        };
        let value = value.trim();
        if let Some(path) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            out.push(path.to_owned());
        }
    }
    out
}

/// How this file classifies one config function upstream declares.
#[derive(Debug, PartialEq, Eq)]
enum DoorClass {
    /// Takes a `key` — one value in or out, not a document.
    Key,
    /// Ingests a whole document from somewhere.
    DocumentReader,
    /// Emits the whole document.
    DocumentWriter,
    /// Handle lifecycle: no document and no key.
    Handle,
}

/// Every `z_config_*` / `zc_config_*` function upstream declares, classified.
///
/// The classification is DERIVED from the declaration, in this order:
///
/// 1. a parameter named `key` makes it a KEY door — that is cbindgen echoing
///    upstream's own parameter name, not a guess;
/// 2. `config_from_*` ingests a document, `config_to_*` emits one;
/// 3. the handle names, each cross-checked to carry NO text at all — so a door
///    that grew a `const char *` falls out of the list rather than staying in it
///    on the strength of its name;
/// 4. anything else is `None`, and the caller FAILS on it. An unclassified door
///    is not a pass.
fn classify(decl: &str, name: &str) -> Option<DoorClass> {
    if decl.contains("*key") || decl.contains(" key,") || decl.contains(" key)") {
        return Some(DoorClass::Key);
    }
    let bare = name
        .strip_prefix("zc_config_")
        .or_else(|| name.strip_prefix("z_config_"))?;
    if bare.starts_with("from_") {
        return Some(DoorClass::DocumentReader);
    }
    if bare.starts_with("to_") {
        return Some(DoorClass::DocumentWriter);
    }
    let carries_text = decl.contains("char *") || decl.contains("z_owned_string_t *");
    match bare {
        "default" | "clone" | "drop" | "loan" | "loan_mut" if !carries_text => {
            Some(DoorClass::Handle)
        }
        _ => None,
    }
}

/// Read every config declaration out of `zenoh_commons.h`, classified.
fn declared_doors(include: &Path) -> Vec<(String, DoorClass)> {
    let header = include.join("zenoh_commons.h");
    let text = std::fs::read_to_string(&header)
        .unwrap_or_else(|why| panic!("read {}: {why}", header.display()));
    // cbindgen wraps a long declaration, so a declaration is gathered from its
    // opening `(` to its `);` rather than assumed to be one line.
    let flat: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('*') && !l.trim_start().starts_with("/*"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut out = Vec::new();
    let mut rest = flat.as_str();
    while let Some(at) = rest.find("_config_") {
        // Walk back to the start of the identifier and forward to `);`.
        let head = &rest[..at];
        let start = head
            .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        let Some(end) = rest[at..].find(");") else {
            break;
        };
        let decl = &rest[start..at + end + 1];
        let name: String = decl
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if (name.starts_with("z_config_") || name.starts_with("zc_config_"))
            && decl[name.len()..].trim_start().starts_with('(')
            && !out.iter().any(|(n, _): &(String, DoorClass)| *n == name)
        {
            let class = classify(decl, &name).unwrap_or_else(|| {
                panic!(
                    "upstream declares `{name}` and this file cannot classify it. An \
                     unclassified config door is a FAILURE, not a pass: it may be a \
                     document door this oracle is not driving.\n{decl}"
                )
            });
            out.push((name, class));
        }
        rest = &rest[at + end + 1..];
    }
    out
}

/// Compile the probe against both libraries.
fn build_arms(include: &Path, dir: &Path) -> [Arm; 2] {
    let src_dir = dir.join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_config_document.c"), PROBE).expect("write the probe source");

    let cdylib = wz_capi_c_cdylib();
    let wz_libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let wz_exe = compile_zenoh_c_example(
        "wz_config_document",
        dir,
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: the config-document probe does NOT link against wz's \
             C-ABI cdylib. A missing symbol here is a program upstream can write and \
             wz cannot run.\n{diag}"
        )
    });

    let reference =
        zenoh_c_shared_library().expect("the oracle resolved, so its libzenohc.so is present");
    let ref_libdir = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let ref_exe = compile_zenoh_c_example(
        "wz_config_document",
        &ref_dir,
        include,
        &src_dir,
        &ref_libdir,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the config-document probe does not link against the REAL libzenohc.so\n{diag}")
    });

    [
        Arm {
            name: "wz",
            exe: wz_exe,
            libdir: wz_libdir,
        },
        Arm {
            name: "reference",
            exe: ref_exe,
            libdir: ref_libdir,
        },
    ]
}

#[test]
#[ignore = "reads the installed zenoh-c oracle; run by run-ci Layer C1cc"]
fn a_config_document_written_by_either_implementation_is_read_by_the_other() {
    let Some(include) = oracle_or_note() else {
        return;
    };

    // THE DOOR POPULATION, derived from upstream's header. Done first because
    // everything below only exercises the doors it names, and a set this file
    // got wrong would make the rest of the test measure the wrong surface.
    let doors = declared_doors(&include);
    assert!(
        doors.len() >= 10,
        "only {} config declaration(s) found in zenoh_commons.h — the header parse \
         is broken, and a population of zero passes every check below",
        doors.len()
    );
    let readers: Vec<&str> = doors
        .iter()
        .filter(|(_, c)| *c == DoorClass::DocumentReader)
        .map(|(n, _)| n.as_str())
        .collect();
    let writers: Vec<&str> = doors
        .iter()
        .filter(|(_, c)| *c == DoorClass::DocumentWriter)
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(
        writers,
        vec!["zc_config_to_string"],
        "the document WRITER set moved; this oracle drives only the one it knew"
    );

    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let [wz, reference] = build_arms(&include, dir.path());

    // The probe says which reader doors it drove; the header says which exist.
    // Compared rather than assumed, because open-debt item 636 named ONE door
    // and there were three.
    let probe_doors = {
        let doc = dir.path().join("doorcheck.json5");
        reference.run(&["emit", doc.to_str().expect("utf-8 path")]);
        let out = reference.run(&["read", doc.to_str().expect("utf-8 path")]);
        out.get("doors")
            .expect("the probe prints its door list")
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        probe_doors,
        PROBE_READER_DOORS
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>(),
        "the probe's own door list and this file's copy of it disagree"
    );
    let mut declared = readers.clone();
    declared.sort_unstable();
    let mut driven: Vec<&str> = probe_doors.iter().map(String::as_str).collect();
    driven.sort_unstable();
    assert_eq!(
        driven, declared,
        "the document READER doors upstream declares and the ones this probe drives \
         differ. A door left undriven is a door whose parser can be the old one — \
         which is exactly what `zc_config_from_file` was."
    );

    // THE CORPUS, from upstream's own constants.
    let paths = corpus(&include);
    assert!(
        paths.len() >= 10,
        "only {} Z_CONFIG_* key(s) read out of zenoh_constants.h — an empty corpus \
         makes every assertion below vacuous",
        paths.len()
    );
    assert!(
        paths.iter().filter(|p| p.contains('/')).count() >= 5,
        "fewer than five multi-segment keys in the corpus, so this proves little \
         about nesting — which is the whole subject"
    );

    // THE WITNESSES, discovered against the reference library.
    let mut witnesses: Vec<(String, String)> = Vec::new();
    let mut unreachable: Vec<String> = Vec::new();
    for path in &paths {
        let mut chosen = None;
        for candidate in LADDER {
            let out = reference.run(&["try", path, candidate]);
            let accepted = out.get("insert.rc").map(String::as_str) == Some("0");
            let default = out.get("default").cloned().unwrap_or_default();
            let got = out.get("get").cloned().unwrap_or_default();
            if accepted && got != default {
                chosen = Some((*candidate).to_owned());
                break;
            }
        }
        match chosen {
            Some(value) => witnesses.push((path.clone(), value)),
            None => unreachable.push(path.clone()),
        }
    }
    assert!(
        unreachable.is_empty(),
        "no rung of the ladder gives a DISCRIMINATING value for {unreachable:?}. A \
         witness equal to the key's default cannot tell a document that carried the \
         value from one that carried nothing, so this is a failure rather than a \
         skip: extend LADDER."
    );

    // What each library says after a DIRECT insert of its witness — the
    // expectation for that same library after a document round trip. Taken per
    // arm so no cross-implementation assumption about spelling is made.
    let expected = |arm: &Arm| -> BTreeMap<String, String> {
        witnesses
            .iter()
            .map(|(path, value)| {
                let out = arm.run(&["try", path, value]);
                assert_eq!(
                    out.get("insert.rc").map(String::as_str),
                    Some("0"),
                    "the {} arm refused the witness {value} at {path}",
                    arm.name
                );
                (
                    path.clone(),
                    out.get("get")
                        .unwrap_or_else(|| panic!("{} read nothing back at {path}", arm.name))
                        .clone(),
                )
            })
            .collect()
    };
    let expect_wz = expected(&wz);
    let expect_ref = expected(&reference);

    // EMIT, once per arm.
    let pairs: Vec<String> = witnesses
        .iter()
        .map(|(path, value)| format!("{path}={value}"))
        .collect();
    let mut documents: BTreeMap<&str, PathBuf> = BTreeMap::new();
    for arm in [&wz, &reference] {
        let out_path = dir.path().join(format!("{}.json5", arm.name));
        let mut args: Vec<&str> = vec!["emit", out_path.to_str().expect("utf-8 path")];
        args.extend(pairs.iter().map(String::as_str));
        let out = arm.run(&args);
        assert_eq!(
            out.get("to_string.rc").map(String::as_str),
            Some("0"),
            "the {} arm's zc_config_to_string failed",
            arm.name
        );
        documents.insert(arm.name, out_path);
    }

    // ANCHOR: a value known from OUTSIDE both programs. Every corpus path that
    // carries a `/` must be SPELT AS NESTING, so the flat key must not occur in
    // either document. An arm-vs-arm comparison cannot see both arms emitting
    // flat; this can.
    for (arm, path) in documents.iter() {
        let text = std::fs::read_to_string(path).expect("the arm wrote its document");
        for key in paths.iter().filter(|p| p.contains('/')) {
            assert!(
                !text.contains(&format!("\"{key}\"")),
                "the {arm} document spells `{key}` FLAT. A path key is a query over the \
                 tree, not a member name — upstream's own reader refuses the flat \
                 spelling.\n{text}"
            );
        }
    }

    // THE FOUR DIRECTIONS, as a product rather than a list.
    let mut failures: Vec<String> = Vec::new();
    for writer in [&wz, &reference] {
        for reader in [&wz, &reference] {
            let doc = documents[writer.name].to_str().expect("utf-8 path");
            let mut args: Vec<&str> = vec!["read", doc];
            args.extend(paths.iter().map(String::as_str));
            let out = reader.run(&args);
            let want = if reader.name == "wz" {
                &expect_wz
            } else {
                &expect_ref
            };
            for door in PROBE_READER_DOORS {
                let rc = out.get(&format!("{door}.rc")).map(String::as_str);
                if rc != Some("0") {
                    failures.push(format!(
                        "  {}'s document -> {}'s {door}: rc {}",
                        writer.name,
                        reader.name,
                        rc.unwrap_or("<no line>")
                    ));
                    continue;
                }
                for (path, expect) in want {
                    let got = out.get(&format!("{door}.{path}")).map(String::as_str);
                    if got != Some(expect.as_str()) {
                        failures.push(format!(
                            "  {}'s document -> {}'s {door} at {path}: got {:?}, want {expect:?}",
                            writer.name,
                            reader.name,
                            got.unwrap_or("<no line>")
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} config-document direction(s) lost a value between wz's C ABI and the real \
         libzenohc.\n{}\n--- wz's document ---\n{}\n--- reference's document (first \
         400 bytes) ---\n{}",
        failures.len(),
        failures.join("\n"),
        std::fs::read_to_string(&documents["wz"]).unwrap_or_default(),
        std::fs::read_to_string(&documents["reference"])
            .unwrap_or_default()
            .chars()
            .take(400)
            .collect::<String>(),
    );

    // THE INSERT SHAPE (open-debt item 642). A caller may state a subtree as one
    // OBJECT rather than stating its leaf, and upstream answers the leaf path
    // either way — so a store that only answers the key it was handed diverges
    // on an insert upstream accepts. The two spellings of the SAME config must
    // read alike.
    //
    // Derived from the corpus: every witness path with a `/` splits at its last
    // separator into the object's key and its member. A corpus of only
    // single-segment keys would leave nothing to check and fails here.
    // WHICH object spellings are legal is decided by UPSTREAM, per run, not by a
    // table here. Not every parent takes a one-member object — `usrpwd` wants
    // its user and password together and refuses either alone (`Z_EGENERIC`,
    // measured) — and a config upstream will not accept is not part of a
    // drop-in contract. Naming those keys in an exemption list would be the
    // escape hatch this file refuses everywhere else; asking the reference is
    // the same move the witness ladder already makes.
    let mut shape_failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut declined_upstream: Vec<String> = Vec::new();
    for (path, witness) in &witnesses {
        let Some((parent, leaf)) = path.rsplit_once('/') else {
            continue;
        };
        let object = format!("{{\"{leaf}\": {witness}}}");
        let on_ref = reference.run(&["try_at", parent, &object, path]);
        if on_ref.get("insert.rc").map(String::as_str) != Some("0") {
            declined_upstream.push(format!("{parent} <- {object}"));
            continue;
        }
        checked += 1;
        // The PREMISE, asserted rather than assumed: upstream answers the leaf
        // path the same whether the caller stated the leaf or the object above
        // it. If this ever fails, the contract below is not upstream's.
        let expect_ref_here = &expect_ref[path];
        if on_ref.get("get").map(String::as_str) != Some(expect_ref_here.as_str()) {
            shape_failures.push(format!(
                "  reference: stated `{object}` at {parent}, then {path} reads {:?}, \
                 want {expect_ref_here:?} — the premise of this axis does not hold",
                on_ref.get("get").map_or("<no line>", String::as_str)
            ));
            continue;
        }
        let on_wz = wz.run(&["try_at", parent, &object, path]);
        if on_wz.get("insert.rc").map(String::as_str) != Some("0") {
            shape_failures.push(format!(
                "  wz refused `{object}` at {parent} — upstream accepts it: rc {}",
                on_wz.get("insert.rc").map_or("<no line>", String::as_str)
            ));
            continue;
        }
        let expect_wz_here = &expect_wz[path];
        let got = on_wz.get("get").map(String::as_str);
        if got != Some(expect_wz_here.as_str()) {
            shape_failures.push(format!(
                "  wz: stated `{object}` at {parent}, then {path} reads {:?}, want \
                 {expect_wz_here:?}",
                got.unwrap_or("<no line>")
            ));
        }
    }
    assert!(
        checked >= 5,
        "only {checked} object spelling(s) survived upstream's own acceptance, so this \
         axis proves little. Declined upstream: {declined_upstream:?}"
    );
    assert!(
        shape_failures.is_empty(),
        "{} insert-shape divergence(s) over {checked} spelling(s) upstream accepts: the \
         same config answers differently depending on whether the caller stated a leaf \
         or the object above it.\n{}\n(upstream itself declined {}: {declined_upstream:?})",
        shape_failures.len(),
        shape_failures.join("\n"),
        declined_upstream.len(),
    );
}
