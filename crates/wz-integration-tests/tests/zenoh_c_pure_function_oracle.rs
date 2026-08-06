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

use wz_integration_tests::common::{
    compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle, zenoh_c_shared_library,
};

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
#include <stdbool.h>
#include <stdint.h>
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

    /* --- the serialization plane ----------------------------------------- */
    {
        /* Every fixed-width value: serialize, then read the BYTES back, so the
           comparison is over the wire form rather than over a round trip that
           would agree with itself on either library. */
#define SHOW_SER(label, call)                                                  \
    do {                                                                       \
        z_owned_bytes_t b;                                                     \
        z_result_t rc = call;                                                  \
        printf("ser." label ".rc=%d", (int)rc);                                \
        if (rc == 0) {                                                         \
            z_bytes_reader_t r = z_bytes_get_reader(z_bytes_loan(&b));         \
            uint8_t raw[64];                                                   \
            size_t n = z_bytes_reader_read(&r, raw, sizeof raw);               \
            printf(" len=%zu bytes=", n);                                      \
            for (size_t i = 0; i < n; i++) printf("%02x", raw[i]);             \
            z_bytes_drop(z_bytes_move(&b));                                    \
        }                                                                      \
        printf("\n");                                                          \
    } while (0)

        SHOW_SER("uint8", ze_serialize_uint8(&b, 0xAB));
        SHOW_SER("int8", ze_serialize_int8(&b, -3));
        SHOW_SER("uint16", ze_serialize_uint16(&b, 0x1234));
        SHOW_SER("int16", ze_serialize_int16(&b, -300));
        SHOW_SER("uint32", ze_serialize_uint32(&b, 0xDEADBEEFu));
        SHOW_SER("int32", ze_serialize_int32(&b, -70000));
        SHOW_SER("uint64", ze_serialize_uint64(&b, 0x0102030405060708ull));
        SHOW_SER("int64", ze_serialize_int64(&b, -5000000000ll));
        SHOW_SER("float", ze_serialize_float(&b, 1.5f));
        SHOW_SER("double", ze_serialize_double(&b, -2.25));
        SHOW_SER("bool_true", ze_serialize_bool(&b, true));
        SHOW_SER("bool_false", ze_serialize_bool(&b, false));
        SHOW_SER("str", ze_serialize_str(&b, "hello"));
        SHOW_SER("substr", ze_serialize_substr(&b, "hello world", 5));
        SHOW_SER("buf", ze_serialize_buf(&b, (const uint8_t *)"\x01\x02\x03", 3));
#undef SHOW_SER

        /* And the READ side, driven off each library's OWN serialization: a
           value that round-trips on both is still a divergence if the two put
           different bytes on the wire, which the block above catches. */
        z_owned_bytes_t b;
        uint32_t u32v = 0;
        ze_serialize_uint32(&b, 0xCAFEBABEu);
        printf("de.uint32.rc=%d val=%u\n",
               (int)ze_deserialize_uint32(z_bytes_loan(&b), &u32v), (unsigned)u32v);
        z_bytes_drop(z_bytes_move(&b));

        int16_t i16v = 0;
        ze_serialize_int16(&b, -1234);
        printf("de.int16.rc=%d val=%d\n",
               (int)ze_deserialize_int16(z_bytes_loan(&b), &i16v), (int)i16v);
        z_bytes_drop(z_bytes_move(&b));

        bool bv = false;
        ze_serialize_bool(&b, true);
        printf("de.bool.rc=%d val=%d\n",
               (int)ze_deserialize_bool(z_bytes_loan(&b), &bv), (int)bv);
        z_bytes_drop(z_bytes_move(&b));

        /* A payload of the WRONG width must be refused, not truncated. */
        uint16_t u16v = 0;
        ze_serialize_uint32(&b, 7);
        printf("de.uint16_from_uint32.rc=%d\n",
               (int)ze_deserialize_uint16(z_bytes_loan(&b), &u16v));
        z_bytes_drop(z_bytes_move(&b));

        /* SEQUENCED, not folded into one printf: C leaves argument evaluation
           order unspecified, and gcc evaluates right to left — so a single call
           would read the out-param BEFORE the deserializer filled it. The first
           cut of this probe did exactly that and reported a two-line divergence
           that was the harness reading uninitialised stack, not wz. */
        z_owned_string_t s;
        ze_serialize_str(&b, "round trip");
        z_result_t src = ze_deserialize_string(z_bytes_loan(&b), &s);
        printf("de.string.rc=%d val=%.*s\n", (int)src,
               (int)z_string_len(z_string_loan(&s)), z_string_data(z_string_loan(&s)));
        z_string_drop(z_string_move(&s));
        z_bytes_drop(z_bytes_move(&b));

        z_owned_slice_t sl;
        ze_serialize_buf(&b, (const uint8_t *)"\xAA\xBB", 2);
        z_result_t slrc = ze_deserialize_slice(z_bytes_loan(&b), &sl);
        printf("de.slice.rc=%d len=%zu\n", (int)slrc, z_slice_len(z_slice_loan(&sl)));
        z_slice_drop(z_slice_move(&sl));
        z_bytes_drop(z_bytes_move(&b));

        /* The SERIALIZER form, which must agree byte for byte with the
           value-level one for the same sequence. */
        ze_owned_serializer_t ser;
        ze_serializer_empty(&ser);
        ze_serializer_serialize_uint16(ze_serializer_loan_mut(&ser), 0x0102);
        ze_serializer_serialize_int8(ze_serializer_loan_mut(&ser), -1);
        ze_serializer_serialize_bool(ze_serializer_loan_mut(&ser), true);
        ze_serializer_serialize_substr(ze_serializer_loan_mut(&ser), "abc", 3);
        ze_serializer_finish(ze_serializer_move(&ser), &b);
        {
            z_bytes_reader_t r = z_bytes_get_reader(z_bytes_loan(&b));
            uint8_t raw[64];
            size_t n = z_bytes_reader_read(&r, raw, sizeof raw);
            printf("serializer.len=%zu bytes=", n);
            for (size_t i = 0; i < n; i++) printf("%02x", raw[i]);
            printf("\n");
        }
        /* …and the deserializer walks it back, reporting `is_done` at each
           step, which is the loop shape a consumer actually writes. */
        {
            ze_deserializer_t de = ze_deserializer_from_bytes(z_bytes_loan(&b));
            uint16_t a = 0;
            int8_t c = 0;
            bool d = false;
            z_owned_string_t e;
            /* Sequenced for the same reason as above: `is_done` must be read
               AFTER the step it reports on. */
            z_result_t r1 = ze_deserializer_deserialize_uint16(&de, &a);
            printf("de2.uint16.rc=%d done=%d\n", (int)r1, (int)ze_deserializer_is_done(&de));
            z_result_t r2 = ze_deserializer_deserialize_int8(&de, &c);
            printf("de2.int8.rc=%d done=%d\n", (int)r2, (int)ze_deserializer_is_done(&de));
            z_result_t r3 = ze_deserializer_deserialize_bool(&de, &d);
            printf("de2.bool.rc=%d done=%d\n", (int)r3, (int)ze_deserializer_is_done(&de));
            z_result_t r4 = ze_deserializer_deserialize_string(&de, &e);
            printf("de2.string.rc=%d done=%d\n", (int)r4, (int)ze_deserializer_is_done(&de));
            printf("de2.values=%u/%d/%d/%.*s\n", (unsigned)a, (int)c, (int)d,
                   (int)z_string_len(z_string_loan(&e)), z_string_data(z_string_loan(&e)));
            z_string_drop(z_string_move(&e));
        }
        z_bytes_drop(z_bytes_move(&b));
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
/// R311y565 — `api-compat-c`'s FIRST reference-implementation proof. Every
/// earlier cross-impl claim on this atom is pico-mediated (a real zenoh-pico CLI
/// opposite a wz-hosted upstream program); this one links zenoh's OWN library
/// as the second arm, which is the counterparty the drop-in claim is actually
/// about. It became recordable when `zenoh_c_shared_library` was registered as a
/// foreign root and `wz->zenoh-c` added to the kind vocabulary — before that A4
/// could not see the file links anything foreign and forbade it a claim.
///
/// `partial`: the encoding table and the keyexpr plane, not the session planes.
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "reads the installed zenoh-c oracle; run by run-ci Layer C1cc"]
fn upstream_pure_functions_on_wz_capi_c_match_real_libzenohc() {
    let Some((include, _libdir)) = oracle_or_note() else {
        return;
    };
    // The reference arm is reached through the REGISTERED resolver, not through a
    // path join. That is what lets Layer A4's classifier see this file links a
    // foreign implementation — see `zenoh_c_shared_library`'s own docs for the
    // round where the inlined form cost the sibling ABI five true claims.
    let reference = zenoh_c_shared_library()
        .expect("the oracle resolved above, so its libzenohc.so is present");
    let libdir_ref = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
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
