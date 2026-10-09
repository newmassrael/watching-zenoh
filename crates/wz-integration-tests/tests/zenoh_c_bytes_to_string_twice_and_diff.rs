// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- what `z_bytes_to_string` does with bytes that are not text, on
//! wz's cdylib as on the real `libzenohc.so`: one C program, compiled once, linked twice,
//! stdout diffed.
//!
//! ## Why this exists
//!
//! wz's `z_bytes_to_string` copied ANY bytes and its doc said that was deliberate, because
//! upstream "prints a byte run with `%.*s`" and refusing would make wz refuse a sample
//! zenoh-c delivers. Nothing had measured that. It was found by a probe of the shared-memory
//! plane: a value read out of a freshly allocated chunk (whose tail is whatever the pool held)
//! converted on wz and was refused by the real library, so the same program printed the value
//! on one and nothing on the other.
//!
//! ## The three cases
//!
//! Valid text, bytes that are not UTF-8, and text with an embedded NUL. The second is the
//! subject; the other two are the controls that the refusal is about the encoding and not about
//! the conversion or about a byte value.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library,
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

const PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

/* z_bytes_to_string on bytes built from a buffer, and z_bytes_to_slice on the same bytes. */
static void try_bytes(const char *label, const uint8_t *data, size_t len) {
    z_owned_bytes_t bytes;
    z_bytes_copy_from_buf(&bytes, data, len);
    z_owned_string_t text;
    int rc = z_bytes_to_string(z_loan(bytes), &text);
    size_t text_len = rc == 0 ? z_string_len(z_loan(text)) : 0;
    if (rc == 0) { z_drop(z_move(text)); }
    z_owned_slice_t slice;
    int slice_rc = z_bytes_to_slice(z_loan(bytes), &slice);
    size_t slice_len = slice_rc == 0 ? z_slice_len(z_loan(slice)) : 0;
    if (slice_rc == 0) { z_drop(z_move(slice)); }
    printf("%s: to_string rc=%d len=%zu to_slice rc=%d len=%zu\n", label, rc, text_len,
           slice_rc, slice_len);
    z_drop(z_move(bytes));
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const uint8_t ok[] = {'a', 'b', 'c'};
    const uint8_t bad[] = {'a', 0xff, 0xfe, 'b'};
    const uint8_t nul[] = {'a', 0, 'b'};
    try_bytes("valid", ok, sizeof ok);
    try_bytes("invalid", bad, sizeof bad);
    try_bytes("embedded-nul", nul, sizeof nul);
    printf("done\n");
    return 0;
}
"#;

/// Compile the probe once per library and return what each printed.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_bytes_to_string.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_bytes_to_string",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!("§5.27 api-compat-c: the bytes probe does NOT link against wz's cdylib.\n{diag}")
    });

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let libdir_ref = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_bytes_to_string",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the bytes probe does not link against the REAL libzenohc.so\n{diag}")
    });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        let out = Command::new(exe)
            .env("LD_LIBRARY_PATH", libdir)
            .output_bounded()
            .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (ref_ok, ref_stdout) = run(&on_ref, &libdir_ref);
    let (wz_ok, wz_stdout) = run(&on_wz, &wz_libdir);
    assert!(
        ref_ok,
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one here.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "the bytes probe exited non-zero on wz's C ABI.\n--- stdout on wz ---\n{wz_stdout}\n\
         --- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// THE GATE: bytes that are not UTF-8 are refused by `z_bytes_to_string` on wz as on libzenohc,
/// and the slice conversion of the same bytes succeeds on both.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn bytes_that_are_not_utf8_are_refused_by_to_string_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // The ORACLE first: two identical answers diff clean, and a reference that took the
    // invalid bytes would make the equality below say nothing about the rule this leg is for.
    assert!(
        ref_stdout.contains("invalid: to_string rc=-1 len=0 to_slice rc=0 len=4"),
        "the reference did not refuse non-UTF-8 bytes while keeping them as a slice, so the \
         rule this leg compares against is not what it assumes:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("valid: to_string rc=0 len=3 to_slice rc=0 len=3")
            && ref_stdout.contains("embedded-nul: to_string rc=0 len=3 to_slice rc=0 len=3")
            && ref_stdout.contains("done"),
        "the reference did not convert the two controls:\n{ref_stdout}"
    );

    assert_eq!(
        wz_stdout, ref_stdout,
        "§5.27 api-compat-c: wz's z_bytes_to_string and libzenohc's disagree on what is text.\n\
         --- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
    );
}
