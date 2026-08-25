// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — does `z_string_array_push_by_alias` ALIAS?
//!
//! ## A divergence that was recorded, argued, and never measured
//!
//! wz's pico ABI copied in BOTH push spellings, and the export's own doc called
//! that a structural necessity: the state owned `items: Vec<String>` and lent
//! views pointing into them, so an aliased entry had nowhere to live. The debt
//! ledger carried it as a named divergence for rounds.
//!
//! Two things were wrong with leaving it there, and they pointed opposite ways.
//! The structural ARGUMENT had expired — the sibling zenoh-c ABI implemented
//! real aliasing at R311y568 with one extra indirection per entry, and the same
//! move works here. But the DIVERGENCE itself was never measured: "upstream
//! aliases" was read off the function's name, not off the library.
//!
//! Measuring it reversed the item. Upstream copies too, so wz was already
//! correct and the ledger had carried a gap that did not exist; had the
//! "expired argument" been acted on alone, this round would have introduced the
//! divergence it set out to close. The indirection was still worth keeping —
//! see the last section — but for a different defect than the one it was
//! reached for.
//!
//! ## The discriminator, and what it MEASURED
//!
//! An alias and a copy are indistinguishable on every read path — `len`, `get`,
//! `is_empty` all answer identically. They differ on exactly one question: does
//! the entry DESCRIBE the caller's bytes? The probe asks it by pointer
//! identity, and corroborates with the consequence (mutate the source buffer
//! afterwards and see whether the array moves).
//!
//! The answer from the real `libzenohpico.so` is that **`_by_alias` COPIES**.
//! Upstream builds an alias `_z_string_t` and hands it to
//! `_z_string_svec_append(a, &str, true)`, whose last argument deep-copies. So
//! wz was never diverging here — the ledger item was read off the function's
//! NAME. wz keeps copying, and this leg is what makes that a measured claim
//! rather than a coincidence.
//!
//! The SIBLING zenoh-c ABI answers the other way, measured by the same
//! technique in `zenoh_c_pure_function_oracle` (`array.alias_is_source_buffer=1`
//! on both arms). A third dialect split, alongside keyexpr and encoding.
//!
//! ## Why this cannot be a vacuous pass
//!
//! "Neither push aliases" is also what a probe blind to aliasing would report.
//! So the probe first proves it can SEE one: the `z_view_string_t` it hands to
//! the push aliases the caller's buffer, and the same pointer-identity
//! comparison detects that (`view.is_caller_buffer=1`, asserted on BOTH arms).
//!
//! ## What this leg deliberately does NOT probe
//!
//! POINTER STABILITY across a growing push. wz boxes each entry, so a pointer
//! `z_string_array_get` handed out stays valid after a reallocating push;
//! upstream's `_z_string_svec_t` stores entries inline and the same program
//! reads freed memory there. That is a wz SUPERSET, and putting it in a shared
//! probe would red the diff for a difference that is not a defect — it belongs
//! in a wz-side test, which is where the sibling ABI keeps its copy of the same
//! claim.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    compile_pico_source, wz_capi_pico_cdylib, zenoh_pico_include_dirs, zenoh_pico_library_dir,
    zenoh_pico_shared_library,
};

/// The probe.
///
/// Every constructor gets its own statement before the value is read. Folding a
/// constructor and an accessor into one `printf` leaves them unsequenced, and
/// R311y568 shipped exactly that on the sibling ABI: gcc evaluated the accessor
/// first and the leg compared two arms' stack junk for a round. Layer C0's
/// unsequenced-probe lint now rejects the shape, and this file is written the
/// way the lint requires.
const PROBE: &str = r#"#include <stdio.h>
#include <string.h>
#include "zenoh-pico.h"

/* Print one entry by index, or say it is absent. */
static void show(const char *label, const z_loaned_string_array_t *arr, size_t k) {
    const z_loaned_string_t *s = z_string_array_get(arr, k);
    if (s == NULL) {
        printf("%s=<null>\n", label);
        return;
    }
    printf("%s=%.*s\n", label, (int)z_string_len(s), z_string_data(s));
}

int main(void) {
    z_owned_string_array_t arr;
    z_string_array_new(&arr);
    printf("new.len=%zu\n", z_string_array_len(z_string_array_loan(&arr)));

    /* Buffers the PROGRAM owns, so the mutation below is the program's and not
       the library's. Both start with the SAME bytes: a difference after the
       mutation is then attributable to the push spelling and to nothing else. */
    char alias_buf[8];
    char copy_buf[8];
    memcpy(alias_buf, "SAME", 5);
    memcpy(copy_buf, "SAME", 5);

    z_view_string_t alias_view;
    z_view_string_t copy_view;
    z_result_t arc = z_view_string_from_str(&alias_view, alias_buf);
    z_result_t crc = z_view_string_from_str(&copy_view, copy_buf);
    printf("view.rc=%d/%d\n", (int)arc, (int)crc);
    /* Whether the VIEW itself aliases. If it does not, no push spelling can
       ever be observed to alias through this route and the distinction is
       unreachable from C -- which is a finding about the API, not about wz. */
    printf("view.is_caller_buffer=%d\n",
           (int)(z_string_data(z_view_string_loan(&alias_view)) == alias_buf));

    size_t n1 = z_string_array_push_by_alias(z_string_array_loan_mut(&arr),
                                             z_view_string_loan(&alias_view));
    printf("push_by_alias.len=%zu\n", n1);
    size_t n2 = z_string_array_push_by_copy(z_string_array_loan_mut(&arr),
                                            z_view_string_loan(&copy_view));
    printf("push_by_copy.len=%zu\n", n2);

    /* BEFORE: both entries must read back as the bytes that were pushed. This
       is the leg's own precondition -- if the two already differ here, the
       mutation below proves nothing. */
    show("before.alias", z_string_array_loan(&arr), 0);
    show("before.copy", z_string_array_loan(&arr), 1);

    /* THE DIRECT QUESTION: does the entry describe the CALLER'S bytes? A
       pointer value cannot be diffed across arms, but its IDENTITY with a
       buffer this program owns can -- and that is precisely what "alias" means.
       It is stronger than the mutation below, which only observes a
       consequence. */
    {
        const z_loaned_string_t *a0 = z_string_array_get(z_string_array_loan(&arr), 0);
        const z_loaned_string_t *c0 = z_string_array_get(z_string_array_loan(&arr), 1);
        printf("alias.is_caller_buffer=%d\n", (int)(z_string_data(a0) == alias_buf));
        printf("copy.is_caller_buffer=%d\n", (int)(z_string_data(c0) == copy_buf));
    }

    /* THE DISCRIMINATOR. */
    alias_buf[0] = 'X';
    copy_buf[0] = 'X';

    show("after.alias", z_string_array_loan(&arr), 0);
    show("after.copy", z_string_array_loan(&arr), 1);

    printf("final.len=%zu\n", z_string_array_len(z_string_array_loan(&arr)));
    z_string_array_drop(z_string_array_move(&arr));
    printf("done\n");
    return 0;
}
"#;

/// Compile once, link twice, run both, return the two stdouts.
fn run_both_arms() -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src = dir.path().join("wz_pico_string_array_alias.c");
    std::fs::write(&src, PROBE).expect("write the probe source");
    let includes = zenoh_pico_include_dirs();

    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_pico_source(&src, dir.path(), &includes, &wz_libdir, "wz_capi_pico")
        .unwrap_or_else(|diag| {
            panic!(
                "§5.27 api-compat-pico: the string-array alias probe does NOT link \
                 against wz's pico cdylib.\n{diag}"
            )
        });

    // Through the REGISTERED resolver, not a path join — Layer A4 reads a file's
    // foreign class off the resolver functions it names.
    let reference = zenoh_pico_shared_library();
    assert!(
        reference.is_file(),
        "the reference libzenohpico.so vanished between resolution and use"
    );
    let ref_libdir = zenoh_pico_library_dir();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_pico_source(&src, &ref_dir, &includes, &ref_libdir, "zenohpico")
        .unwrap_or_else(|diag| {
            panic!(
                "the string-array alias probe does not link against the REAL \
                 libzenohpico.so\n{diag}"
            )
        });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        let out = Command::new(exe)
            .env("LD_LIBRARY_PATH", libdir)
            .output()
            .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (wz_ok, wz_stdout) = run(&on_wz, &wz_libdir);
    let (ref_ok, ref_stdout) = run(&on_ref, &ref_libdir);
    assert!(
        ref_ok,
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one \
         here.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "the wz arm exited non-zero. Its stdout up to the failure:\n{wz_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<PathBuf> {
    let lib = zenoh_pico_library_dir().join("libzenohpico.so");
    if lib.is_file() {
        return Some(lib);
    }
    eprintln!(
        "skip: the zenoh-pico ORACLE is absent. This leg needs the CMake-built \
         libzenohpico.so and its generated config.h — run \
         scripts/build-zenoh-pico-cli.sh."
    );
    None
}

/// THE GATE: wz's two push spellings behave as the real library's do.
///
/// `partial`: the string-array push pair, not the whole ABI.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "reads the CMake-built libzenohpico.so oracle; run by run-ci Layer E"]
fn string_array_push_spellings_on_wz_capi_pico_match_real_libzenohpico() {
    if oracle_or_note().is_none() {
        return;
    }
    let (wz_stdout, ref_stdout) = run_both_arms();

    // Asserted BEFORE the diff: two empty captures are equal, and an equality
    // between them would report the strongest result this file can produce
    // while measuring nothing.
    assert!(
        ref_stdout.lines().count() >= 10,
        "the reference arm printed only {} line(s) — the probe did not run.\n{ref_stdout}",
        ref_stdout.lines().count()
    );

    // THE PROBE'S POSITIVE CONTROL, and the reason its answer is a measurement
    // rather than a tautology.
    //
    // Both arms report that NEITHER push produces an aliasing entry. On its own
    // that is exactly what a probe blind to aliasing would report, so the leg
    // first shows it can SEE one: the `z_view_string_t` handed to the push is
    // itself an alias of the caller's buffer, and the same pointer-identity
    // comparison detects it. A probe that returned 0 everywhere would fail
    // here.
    for (arm, stdout) in [("wz", &wz_stdout), ("reference", &ref_stdout)] {
        assert_eq!(
            line_value(stdout, "view.is_caller_buffer"),
            "1",
            "on the {arm} arm the `z_view_string_t` does not alias the caller's \
             buffer, so this probe cannot detect aliasing at all and every `0` \
             below would be uninformative.\n{stdout}"
        );
    }

    // What the reference ACTUALLY answers, stated here so a future change to
    // upstream shows up as this assertion rather than as a silent agreement.
    // R311y570 measured it: pico's `_by_alias` copies, despite the name and
    // despite this tree having recorded the opposite as a wz divergence for
    // rounds. The SIBLING zenoh-c ABI really does alias — the two ABIs differ,
    // which is why each is measured against its own library.
    assert_eq!(
        line_value(&ref_stdout, "alias.is_caller_buffer"),
        "0",
        "the real libzenohpico now ALIASES in `z_string_array_push_by_alias`, \
         which it did not when R311y570 measured it. wz copies to match, so this \
         is now a real divergence and `wz-capi-pico` must follow.\n{ref_stdout}"
    );
    assert_eq!(
        line_value(&ref_stdout, "after.copy"),
        "SAME",
        "the reference's COPY entry moved when its source buffer was mutated, \
         which means the probe is measuring the buffer rather than the push"
    );

    let wz: Vec<&str> = wz_stdout.lines().collect();
    let reference: Vec<&str> = ref_stdout.lines().collect();
    let mut differing: Vec<String> = Vec::new();
    for (i, expected) in reference.iter().enumerate() {
        match wz.get(i) {
            Some(actual) if actual == expected => {}
            Some(actual) => differing.push(format!("  wz: {actual}\n  ref: {expected}")),
            None => differing.push(format!("  wz: <missing>\n  ref: {expected}")),
        }
    }
    if wz.len() > reference.len() {
        for extra in &wz[reference.len()..] {
            differing.push(format!("  wz: {extra}\n  ref: <missing>"));
        }
    }
    assert!(
        differing.is_empty(),
        "{} of {} probe line(s) differ between wz's pico ABI and the real \
         libzenohpico:\n{}",
        differing.len(),
        reference.len(),
        differing.join("\n")
    );
}

/// The value after `=` on the line whose key is `key`, or a marker.
fn line_value(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .unwrap_or("<absent>")
        .to_owned()
}
