// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — the PURE-FUNCTION twice-and-diff.
//!
//! ## What this answers that the other zenoh-c legs do not
//!
//! The dropin fixture proves upstream's example programs LINK and RUN; the
//! interop legs put a foreign implementation on the wire. Neither reaches the
//! part of the ABI that never touches a session: the encoding constant table,
//! keyexpr canonization, keyexpr set relations, string and slice construction.
//! Those are ordinary functions with ordinary answers, and a drop-in that
//! returns a different answer is wrong in a way no interop leg can see —
//! `z_keyexpr_canonize` is called before a session exists, and `z_encoding_*`
//! is called to build a value the program then compares.
//!
//! So this file does what `pico_pure_function_oracle.rs` does for the sibling
//! ABI: ONE probe source, compiled once, linked TWICE — against wz's cdylib and
//! against the real `libzenohc.so` — with the two stdouts diffed line for line.
//! Nothing here transcribes an expected value, which is the point: R311y564
//! added 53 encoding constants keyed by a hand-written table index and six
//! keyexpr relations whose exact semantics (does `concat` canonize? does
//! `is_canon` return a code or a bool?) were read off a signature. A
//! transcribed expectation would have frozen whatever this author believed;
//! the reference arm is what actually decides.
//!
//! ## The probe must be OBSERVABLE on failure
//!
//! Every line is `key=value`, so a mismatch names the function rather than
//! reporting that two blobs differ. The diff prints every differing line, not
//! the first — a canonization rule that is wrong is usually wrong in several
//! places, and the set is the work list.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle};

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<(PathBuf, PathBuf)> {
    match zenoh_c_oracle() {
        Some((include, libdir, _examples)) => Some((include, libdir)),
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
/// C rather than a Rust `extern` block on purpose: the header is the ABI here,
/// so the probe has to be compiled BY a C compiler AGAINST that header for the
/// comparison to mean what it claims. A Rust declaration would restate the
/// signature and could restate it wrong on both arms at once.
const PROBE: &str = r#"#include <stdio.h>
#include <string.h>
#include "zenoh.h"

/* Render a loaned encoding through `z_encoding_to_string`. */
static void show_encoding(const char *label, const z_loaned_encoding_t *e) {
    z_owned_string_t s;
    z_encoding_to_string(e, &s);
    printf("encoding.%s=%.*s\n", label,
           (int)z_string_len(z_string_loan(&s)), z_string_data(z_string_loan(&s)));
    z_string_drop(z_string_move(&s));
}

#define SHOW_ENCODING(fn) show_encoding(#fn, fn())

/* Canonize a mutable copy of `input` and report the verdict plus the result. */
static void show_canonize(const char *input) {
    char buf[256];
    size_t len = strlen(input);
    memcpy(buf, input, len + 1);
    z_result_t rc = z_keyexpr_canonize_null_terminated(buf);
    printf("canonize[%s].rc=%d\n", input, (int)rc);
    printf("canonize[%s].out=%s\n", input, rc == 0 ? buf : "<unchanged>");
    printf("is_canon[%s]=%d\n", input, (int)z_keyexpr_is_canon(input, strlen(input)));
}

/* Report a two-keyexpr relation under all three set predicates. */
static void show_relation(const char *a, const char *b) {
    z_view_keyexpr_t va, vb;
    if (z_view_keyexpr_from_str(&va, (char *)a) != 0) {
        printf("relation[%s|%s]=<a rejected>\n", a, b);
        return;
    }
    if (z_view_keyexpr_from_str(&vb, (char *)b) != 0) {
        printf("relation[%s|%s]=<b rejected>\n", a, b);
        return;
    }
    const z_loaned_keyexpr_t *la = z_view_keyexpr_loan(&va);
    const z_loaned_keyexpr_t *lb = z_view_keyexpr_loan(&vb);
    printf("equals[%s|%s]=%d\n", a, b, (int)z_keyexpr_equals(la, lb));
    printf("includes[%s|%s]=%d\n", a, b, (int)z_keyexpr_includes(la, lb));
    printf("intersects[%s|%s]=%d\n", a, b, (int)z_keyexpr_intersects(la, lb));
}

/* Render an owned keyexpr, or the failure code. */
static void show_owned(const char *label, z_result_t rc, z_owned_keyexpr_t *ke) {
    if (rc != 0) {
        printf("%s.rc=%d\n", label, (int)rc);
        return;
    }
    z_view_string_t vs;
    z_keyexpr_as_view_string(z_keyexpr_loan(ke), &vs);
    printf("%s.rc=0\n", label);
    printf("%s.out=%.*s\n", label,
           (int)z_string_len(z_view_string_loan(&vs)), z_string_data(z_view_string_loan(&vs)));
    z_keyexpr_drop(z_keyexpr_move(ke));
}

int main(void) {
    /* --- the encoding constant table ------------------------------------ */
    SHOW_ENCODING(z_encoding_zenoh_bytes);
    SHOW_ENCODING(z_encoding_zenoh_string);
    SHOW_ENCODING(z_encoding_zenoh_serialized);
    SHOW_ENCODING(z_encoding_application_octet_stream);
    SHOW_ENCODING(z_encoding_text_plain);
    SHOW_ENCODING(z_encoding_application_json);
    SHOW_ENCODING(z_encoding_text_json);
    SHOW_ENCODING(z_encoding_application_cdr);
    SHOW_ENCODING(z_encoding_application_cbor);
    SHOW_ENCODING(z_encoding_application_yaml);
    SHOW_ENCODING(z_encoding_text_yaml);
    SHOW_ENCODING(z_encoding_text_json5);
    SHOW_ENCODING(z_encoding_application_python_serialized_object);
    SHOW_ENCODING(z_encoding_application_protobuf);
    SHOW_ENCODING(z_encoding_application_java_serialized_object);
    SHOW_ENCODING(z_encoding_application_openmetrics_text);
    SHOW_ENCODING(z_encoding_image_png);
    SHOW_ENCODING(z_encoding_image_jpeg);
    SHOW_ENCODING(z_encoding_image_gif);
    SHOW_ENCODING(z_encoding_image_bmp);
    SHOW_ENCODING(z_encoding_image_webp);
    SHOW_ENCODING(z_encoding_application_xml);
    SHOW_ENCODING(z_encoding_application_x_www_form_urlencoded);
    SHOW_ENCODING(z_encoding_text_html);
    SHOW_ENCODING(z_encoding_text_xml);
    SHOW_ENCODING(z_encoding_text_css);
    SHOW_ENCODING(z_encoding_text_javascript);
    SHOW_ENCODING(z_encoding_text_markdown);
    SHOW_ENCODING(z_encoding_text_csv);
    SHOW_ENCODING(z_encoding_application_sql);
    SHOW_ENCODING(z_encoding_application_coap_payload);
    SHOW_ENCODING(z_encoding_application_json_patch_json);
    SHOW_ENCODING(z_encoding_application_json_seq);
    SHOW_ENCODING(z_encoding_application_jsonpath);
    SHOW_ENCODING(z_encoding_application_jwt);
    SHOW_ENCODING(z_encoding_application_mp4);
    SHOW_ENCODING(z_encoding_application_soap_xml);
    SHOW_ENCODING(z_encoding_application_yang);
    SHOW_ENCODING(z_encoding_audio_aac);
    SHOW_ENCODING(z_encoding_audio_flac);
    SHOW_ENCODING(z_encoding_audio_mp4);
    SHOW_ENCODING(z_encoding_audio_ogg);
    SHOW_ENCODING(z_encoding_audio_vorbis);
    SHOW_ENCODING(z_encoding_video_h261);
    SHOW_ENCODING(z_encoding_video_h263);
    SHOW_ENCODING(z_encoding_video_h264);
    SHOW_ENCODING(z_encoding_video_h265);
    SHOW_ENCODING(z_encoding_video_h266);
    SHOW_ENCODING(z_encoding_video_mp4);
    SHOW_ENCODING(z_encoding_video_ogg);
    SHOW_ENCODING(z_encoding_video_raw);
    SHOW_ENCODING(z_encoding_video_vp8);
    SHOW_ENCODING(z_encoding_video_vp9);
    show_encoding("loan_default", z_encoding_loan_default());

    /* --- encoding parse / render / compare ------------------------------- */
    {
        z_owned_encoding_t e;
        printf("encoding.from_str.rc=%d\n", (int)z_encoding_from_str(&e, "text/plain;utf8"));
        show_encoding("from_str", z_encoding_loan(&e));
        printf("encoding.from_str.equals_text_plain=%d\n",
               (int)z_encoding_equals(z_encoding_loan(&e), z_encoding_text_plain()));
        z_encoding_drop(z_encoding_move(&e));

        printf("encoding.from_substr.rc=%d\n",
               (int)z_encoding_from_substr(&e, "application/jsonXXX", 16));
        show_encoding("from_substr", z_encoding_loan(&e));
        z_encoding_drop(z_encoding_move(&e));

        printf("encoding.unknown.rc=%d\n", (int)z_encoding_from_str(&e, "wz/not-a-real-label"));
        show_encoding("unknown", z_encoding_loan(&e));
        z_encoding_drop(z_encoding_move(&e));

        z_encoding_clone(&e, z_encoding_application_cbor());
        printf("encoding.set_schema.rc=%d\n",
               (int)z_encoding_set_schema_from_str(z_encoding_loan_mut(&e), "v2"));
        show_encoding("set_schema", z_encoding_loan(&e));
        printf("encoding.constant_after_set_schema=");
        {
            z_owned_string_t s;
            z_encoding_to_string(z_encoding_application_cbor(), &s);
            printf("%.*s\n", (int)z_string_len(z_string_loan(&s)), z_string_data(z_string_loan(&s)));
            z_string_drop(z_string_move(&s));
        }
        z_encoding_drop(z_encoding_move(&e));
    }

    /* --- keyexpr canonization -------------------------------------------- */
    show_canonize("home/temp");
    show_canonize("home/$*/temp");
    show_canonize("home/**/*/temp");
    show_canonize("home/$*$*$*foo");
    show_canonize("home//temp");
    show_canonize("home/foo?bar");
    show_canonize("home/fo*o");
    show_canonize("**/**");
    /* The DIALECT discriminators: a `$*` INSIDE a wild run is the one case
       zenoh-c and zenoh-pico answer differently, so these are what stop wz
       from silently serving pico's canonical form on this ABI. */
    show_canonize("**/$*/temp");
    show_canonize("**/$*");
    show_canonize("**/$*$*/temp");
    show_canonize("a/**/*/*/b");

    /* --- keyexpr set relations ------------------------------------------- */
    show_relation("demo/**", "demo/a/b");
    show_relation("demo/a/b", "demo/**");
    show_relation("demo/**", "demo/**");
    show_relation("demo/*", "demo/a");
    show_relation("demo/a", "other/a");
    show_relation("demo/*/b", "demo/a/*");

    /* --- keyexpr constructors -------------------------------------------- */
    {
        z_owned_keyexpr_t ke;
        show_owned("from_str", z_keyexpr_from_str(&ke, "demo/example"), &ke);
        show_owned("from_substr", z_keyexpr_from_substr(&ke, "demo/example/tail", 12), &ke);

        char buf[64];
        strcpy(buf, "home/$*/temp");
        show_owned("from_str_autocanonize", z_keyexpr_from_str_autocanonize(&ke, buf), &ke);
        printf("from_str_autocanonize.buf=%s\n", buf);
        strcpy(buf, "home/**/*/temp");
        size_t blen = strlen(buf);
        show_owned("from_substr_autocanonize",
                   z_keyexpr_from_substr_autocanonize(&ke, buf, &blen), &ke);
        printf("from_substr_autocanonize.buf=%s\n", buf);
        printf("from_substr_autocanonize.len=%zu\n", blen);
        strcpy(buf, "home/$*/temp");
        z_view_keyexpr_t vac;
        printf("view_autocanonize.rc=%d\n",
               (int)z_view_keyexpr_from_str_autocanonize(&vac, buf));
        printf("view_autocanonize.buf=%s\n", buf);
        printf("from_str.noncanon=%d\n", (int)z_keyexpr_from_str(&ke, "home/**/*/x"));
        printf("from_str.empty_chunk=%d\n", (int)z_keyexpr_from_str(&ke, "home//x"));
        z_view_keyexpr_t vbad;
        printf("view_from_str.noncanon=%d\n",
               (int)z_view_keyexpr_from_str(&vbad, (char *)"home/**/*/x"));

        z_view_keyexpr_t left;
        z_view_keyexpr_from_str(&left, (char *)"demo/example");
        show_owned("concat",
                   z_keyexpr_concat(&ke, z_view_keyexpr_loan(&left), "/tail", 5), &ke);
        z_view_keyexpr_t right;
        z_view_keyexpr_from_str(&right, (char *)"tail/**");
        show_owned("join",
                   z_keyexpr_join(&ke, z_view_keyexpr_loan(&left), z_view_keyexpr_loan(&right)),
                   &ke);

        z_keyexpr_clone(&ke, z_view_keyexpr_loan(&left));
        printf("clone.check=%d\n", (int)z_internal_keyexpr_check(&ke));
        show_owned("clone", 0, &ke);
        printf("clone.check_after_drop=%d\n", (int)z_internal_keyexpr_check(&ke));

        z_view_keyexpr_t empty;
        z_view_keyexpr_empty(&empty);
        printf("view.is_empty=%d\n", (int)z_view_keyexpr_is_empty(&empty));
        printf("view.is_empty_after_from_str=%d\n", (int)z_view_keyexpr_is_empty(&left));
    }

    return 0;
}
"#;

/// Compile the probe once, link it twice, and return the two stdouts.
fn run_both_arms(include: &Path, libdir_ref: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_pure_functions.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_pure_functions",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: the pure-function probe does NOT link against wz's \
             C-ABI cdylib. A missing symbol here is a program upstream can write and \
             wz cannot run.\n{diag}"
        )
    });
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_pure_functions",
        &ref_dir,
        include,
        &src_dir,
        libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the pure-function probe does not link against the REAL libzenohc.so\n{diag}")
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
    let (ref_ok, ref_stdout) = run(&on_ref, libdir_ref);
    assert!(
        ref_ok,
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one here \
         — the comparison below would be meaningless.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "the pure-function probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// THE GATE: every pure function answers what the real library answers.
///
/// It covers the encoding table and the keyexpr plane, which is what R311y564
/// built, and says nothing about the session planes the interop legs cover.
///
/// NO cross-impl proof annotation, and Layer A4 requires its absence rather than merely
/// permitting it: a file whose foreign artifacts the corpus classifier cannot
/// see may not carry a claim at all, not even `none`. The reference arm here IS
/// a foreign implementation — the real `libzenohc.so`, linked and run — but the
/// classifier registers `zenoh_pico_shared_library` and has no zenoh-c
/// equivalent, and the kind vocabulary has no `wz->zenoh-c`. This file's
/// siblings (`upstream_option_defaults_on_wz_capi_c_match_real_libzenohc`, the
/// footprint gate) are unannotated for the same reason. Registering the root and
/// the kind would let `api-compat-c` claim its first REFERENCE-implementation
/// proof; it is a change to A4's taxonomy and belongs in its own round.
#[test]
#[ignore = "reads the installed zenoh-c oracle; run by run-ci Layer C1cc"]
fn upstream_pure_functions_on_wz_capi_c_match_real_libzenohc() {
    let Some((include, libdir_ref)) = oracle_or_note() else {
        return;
    };
    let (wz_stdout, ref_stdout) = run_both_arms(&include, &libdir_ref);

    // Asserted BEFORE the diff: two empty captures are equal, and an equality
    // between them would report the strongest result this file can produce
    // while measuring nothing.
    assert!(
        ref_stdout.lines().count() > 100,
        "the reference arm printed only {} line(s) — the probe did not run, so an \
         equality below would be an equality between two failures.\n{ref_stdout}",
        ref_stdout.lines().count()
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
        "{} of {} probe line(s) differ between wz's C ABI and the real libzenohc:\n{}",
        differing.len(),
        reference.len(),
        differing.join("\n")
    );
}
