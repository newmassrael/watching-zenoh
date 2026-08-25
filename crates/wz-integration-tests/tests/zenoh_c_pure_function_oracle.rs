// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
#include <stdlib.h>
#include "zenoh.h"

/* R311y568 — the state the new blocks at the end of `main` observe. Globals
   rather than a context pointer because the probe is single-threaded apart from
   the one task it joins, and a printed COUNT is what distinguishes a callback
   that RAN from one that merely linked. */
static int task_ran = 0;
static int log_calls = 0;
static int log_drops = 0;
static int match_calls = 0;
static int match_last = -1;

static void *task_body(void *arg) { (void)arg; task_ran = 1; return NULL; }
static void free_str(void *data, void *context) { (void)context; free(data); }
static void on_log(zc_log_severity_t sev, const z_loaned_string_t *msg, void *ctx) {
    (void)sev; (void)msg; (void)ctx; log_calls++;
}
static void on_log_drop(void *ctx) { (void)ctx; log_drops++; }
static void on_match(const z_matching_status_t *st, void *ctx) {
    (void)ctx; match_calls++; match_last = st ? (int)st->matching : -1;
}

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

    /* --- R311y568: the families the DROP-IN CENSUS forced into existence ---
       Every block below drives symbols that did not exist in wz's cdylib
       before this round, so none had ever been compared against the reference.
       They are pure or session-free, which is why they belong in THIS file
       rather than in an interop leg: a wrong answer here is invisible on the
       wire because it never reaches one. */

    /* The five consolidation constructors + the five constant getters. */
    printf("consolidation.auto=%d\n", (int)z_query_consolidation_auto().mode);
    printf("consolidation.default=%d\n", (int)z_query_consolidation_default().mode);
    printf("consolidation.none=%d\n", (int)z_query_consolidation_none().mode);
    printf("consolidation.monotonic=%d\n", (int)z_query_consolidation_monotonic().mode);
    printf("consolidation.latest=%d\n", (int)z_query_consolidation_latest().mode);
    printf("default.cc.push=%d\n", (int)z_internal_congestion_control_default_push());
    printf("default.cc.request=%d\n", (int)z_internal_congestion_control_default_request());
    printf("default.cc.response=%d\n", (int)z_internal_congestion_control_default_response());
    printf("default.priority=%d\n", (int)z_priority_default());
    printf("default.locality=%d\n", (int)zc_locality_default());

    /* The two option structs that were NOT DECLARED before this round. Their
       defaults are the whole observable content of an 8-byte struct. */
    {
        z_publisher_delete_options_t pdo;
        z_publisher_delete_options_default(&pdo);
        printf("pub_delete_opts.timestamp_null=%d size=%zu\n",
               (int)(pdo.timestamp == NULL), sizeof pdo);
        z_query_reply_err_options_t qreo;
        z_query_reply_err_options_default(&qreo);
        printf("reply_err_opts.encoding_null=%d size=%zu\n",
               (int)(qreo.encoding == NULL), sizeof qreo);
    }

    /* The four keyexpr RELATION levels, over pairs chosen to hit each one.
       `z_keyexpr_relation_to` collapses three predicates into a ladder, and
       the ladder's ORDER is what a hand-written version gets wrong — an equal
       pair answered as INTERSECTS is a plausible bug no single pair exposes.

       Behind upstream's OWN `#if`, not a wz-authored one: the probe is compiled
       against upstream's header, so the header's gate is the definition of
       which arm has this symbol. Copying the condition rather than inventing a
       flag is what keeps the two arms comparable — and it is how this block
       first proved wz was over-exporting, by failing to link against the
       reference. */
#if defined(Z_FEATURE_UNSTABLE_API)
    {
        const char *pairs[][2] = {
            {"a/b", "a/b"},
            {"a/**", "a/b/c"},
            {"a/*/c", "a/b/*"},
            {"a/b", "x/y"},
            {"**", "a/b/c"},
            {"a/*", "a/*"},
        };
        for (size_t i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
            z_view_keyexpr_t l, r;
            z_view_keyexpr_from_str(&l, pairs[i][0]);
            z_view_keyexpr_from_str(&r, pairs[i][1]);
            printf("relation[%s|%s]=%d\n", pairs[i][0], pairs[i][1],
                   (int)z_keyexpr_relation_to(z_view_keyexpr_loan(&l),
                                              z_view_keyexpr_loan(&r)));
        }
    }
#endif

    /* The six `z_bytes_*` constructors and the reader's three cursor calls.
       The reader block is SEQUENCED deliberately: `tell` and `remaining` are
       read after each step, so a cursor that moves by the wrong amount shows
       up on the step that moved it rather than only at the end. */
    {
        z_owned_bytes_t b1, b2, b3, b4, b5, b6, empty;
        z_owned_slice_t sl;
        z_owned_string_t st;
        z_slice_copy_from_buf(&sl, (const uint8_t *)"SLICE", 5);
        z_string_copy_from_str(&st, "STRING");

        z_bytes_copy_from_slice(&b1, z_slice_loan(&sl));
        printf("bytes.copy_from_slice.len=%zu empty=%d\n",
               z_bytes_len(z_bytes_loan(&b1)), (int)z_bytes_is_empty(z_bytes_loan(&b1)));
        z_bytes_copy_from_string(&b2, z_string_loan(&st));
        printf("bytes.copy_from_string.len=%zu\n", z_bytes_len(z_bytes_loan(&b2)));
        /* MOVING constructors: the sources are consumed by the callee. */
        z_bytes_from_slice(&b3, z_slice_move(&sl));
        printf("bytes.from_slice.len=%zu\n", z_bytes_len(z_bytes_loan(&b3)));
        z_bytes_from_string(&b4, z_string_move(&st));
        printf("bytes.from_string.len=%zu\n", z_bytes_len(z_bytes_loan(&b4)));

        /* The constructor is SEQUENCED BEFORE the accessor, on its own
           statement. Folding both into one `printf` leaves them unsequenced:
           the compiler is free to evaluate `z_bytes_len` first, and gcc does,
           so the length is read out of an UNINITIALISED `z_owned_bytes_t`.
           That is what R311y568 shipped, and it measured stack junk on both
           arms — locally the junk happened to agree and the leg was green;
           hosted it did not and the reference printed a stack address. */
        static uint8_t STATIC_BUF[4] = {1, 2, 3, 4};
        z_result_t rc5 = z_bytes_from_static_buf(&b5, STATIC_BUF, sizeof STATIC_BUF);
        printf("bytes.from_static_buf.rc=%d len=%zu\n", (int)rc5,
               z_bytes_len(z_bytes_loan(&b5)));

        char *owned_str = (char *)malloc(6);
        memcpy(owned_str, "OWNED", 6);
        z_result_t rc6 = z_bytes_from_str(&b6, owned_str, free_str, NULL);
        printf("bytes.from_str.rc=%d len=%zu\n", (int)rc6,
               z_bytes_len(z_bytes_loan(&b6)));

        z_bytes_empty(&empty);
        printf("bytes.empty.is_empty=%d\n", (int)z_bytes_is_empty(z_bytes_loan(&empty)));

        z_bytes_reader_t rd = z_bytes_get_reader(z_bytes_loan(&b1));
        uint8_t buf[8];
        printf("reader.start tell=%lld remaining=%zu\n",
               (long long)z_bytes_reader_tell(&rd), z_bytes_reader_remaining(&rd));
        z_bytes_reader_read(&rd, buf, 2);
        printf("reader.after_read2 tell=%lld remaining=%zu\n",
               (long long)z_bytes_reader_tell(&rd), z_bytes_reader_remaining(&rd));
        printf("reader.seek_set0.rc=%d tell=%lld\n",
               (int)z_bytes_reader_seek(&rd, 0, SEEK_SET), (long long)z_bytes_reader_tell(&rd));
        printf("reader.seek_cur3.rc=%d tell=%lld\n",
               (int)z_bytes_reader_seek(&rd, 3, SEEK_CUR), (long long)z_bytes_reader_tell(&rd));
        printf("reader.seek_end0.rc=%d tell=%lld remaining=%zu\n",
               (int)z_bytes_reader_seek(&rd, 0, SEEK_END), (long long)z_bytes_reader_tell(&rd),
               z_bytes_reader_remaining(&rd));
        /* PAST the end and BEFORE the start: a version that CLAMPED instead of
           refusing would pass an rc-only check and differ on `tell` here. */
        printf("reader.seek_past.rc=%d tell=%lld\n",
               (int)z_bytes_reader_seek(&rd, 99, SEEK_SET), (long long)z_bytes_reader_tell(&rd));
        printf("reader.seek_neg.rc=%d tell=%lld\n",
               (int)z_bytes_reader_seek(&rd, -99, SEEK_SET), (long long)z_bytes_reader_tell(&rd));

        z_bytes_drop(z_bytes_move(&b1));
        z_bytes_drop(z_bytes_move(&b2));
        z_bytes_drop(z_bytes_move(&b3));
        z_bytes_drop(z_bytes_move(&b4));
        z_bytes_drop(z_bytes_move(&b5));
        z_bytes_drop(z_bytes_move(&b6));
        z_bytes_drop(z_bytes_move(&empty));
    }

    /* The string array's MUTABLE half.

       NOTE what is deliberately NOT compared here. wz boxes each entry so a
       pointer from `z_string_array_get` survives a later reallocating push;
       upstream does not, and a probe that read a pre-growth pointer back
       SEGFAULTED the reference arm on its first run. That is a wz SUPERSET, so
       it cannot be a twice-and-diff claim — a property the reference does not
       have has no reference answer to agree with. It is asserted where it
       belongs instead, as a wz-side unit test in `crate::scout`.

       What IS compared is every answer both libraries can give: the push return
       values, the length after growth, the element read back at each index
       BEFORE any further push, and the clone's length. */
    {
        z_owned_string_array_t arr, copy;
        z_string_array_new(&arr);
        printf("array.new.len=%zu empty=%d\n",
               z_string_array_len(z_string_array_loan(&arr)),
               (int)z_string_array_is_empty(z_string_array_loan(&arr)));
        z_owned_string_t a, b;
        z_string_copy_from_str(&a, "alpha");
        z_string_copy_from_str(&b, "beta");
        printf("array.push_alias=%zu\n",
               z_string_array_push_by_alias(z_string_array_loan_mut(&arr), z_string_loan(&a)));
        printf("array.push_copy=%zu\n",
               z_string_array_push_by_copy(z_string_array_loan_mut(&arr), z_string_loan(&b)));
        /* Read back through a FRESH `get` each time — the only form both
           libraries support. */
        for (size_t i = 0; i < z_string_array_len(z_string_array_loan(&arr)); i++) {
            const z_loaned_string_t *e = z_string_array_get(z_string_array_loan(&arr), i);
            printf("array.get[%zu]=%.*s\n", i, (int)z_string_len(e), z_string_data(e));
        }
        /* R311y570 — does `_by_alias` actually ALIAS? Every read path answers
           identically for an alias and a copy, so the only C-visible difference
           is whether the entry DESCRIBES the source buffer. A pointer value
           cannot be diffed across arms; its IDENTITY with a pointer this
           program also holds can, and that is exactly the claim the two
           spellings make. Asked here because the sibling pico probe measured
           this and found upstream's `_by_alias` copying despite its name — a
           thing this tree had believed from the function's spelling. */
        {
            const z_loaned_string_t *e0 = z_string_array_get(z_string_array_loan(&arr), 0);
            const z_loaned_string_t *e1 = z_string_array_get(z_string_array_loan(&arr), 1);
            printf("array.alias_is_source_buffer=%d\n",
                   (int)(z_string_data(e0) == z_string_data(z_string_loan(&a))));
            printf("array.copy_is_source_buffer=%d\n",
                   (int)(z_string_data(e1) == z_string_data(z_string_loan(&b))));
        }
        for (int i = 0; i < 8; i++) {
            z_string_array_push_by_copy(z_string_array_loan_mut(&arr), z_string_loan(&b));
        }
        printf("array.len_after_growth=%zu\n", z_string_array_len(z_string_array_loan(&arr)));
        {
            const z_loaned_string_t *e0 = z_string_array_get(z_string_array_loan(&arr), 0);
            printf("array.get0_after_growth=%.*s\n",
                   (int)z_string_len(e0), z_string_data(e0));
        }
        printf("array.get_past_end_null=%d\n",
               (int)(z_string_array_get(z_string_array_loan(&arr), 999) == NULL));
        z_string_array_clone(&copy, z_string_array_loan(&arr));
        printf("array.clone.len=%zu\n", z_string_array_len(z_string_array_loan(&copy)));
        z_string_array_drop(z_string_array_move(&copy));
        z_string_array_drop(z_string_array_move(&arr));
        z_string_drop(z_string_move(&a));
        z_string_drop(z_string_move(&b));
    }

    /* The TASK plane. The counter is bumped by the spawned function and read
       AFTER the join, so the claim is that the task RAN — a `z_task_join` that
       did not wait would print 0 on one arm and 1 on the other. */
    {
        z_owned_task_t t, t2, t3;
        task_ran = 0;
        /* SEQUENCED, not folded into one `printf`. C leaves the evaluation
           order of argument expressions unspecified, so `check(&t)` beside
           `init(&t)` is read before the init on one arm and after it on the
           other — which this probe reported as an ABI difference on its first
           run and was not one. The existing deserializer block above carries
           the same note for the same reason. */
        z_result_t task_rc = z_task_init(&t, NULL, task_body, NULL);
        int task_check = (int)z_internal_task_check(&t);
        printf("task.init.rc=%d check=%d\n", (int)task_rc, task_check);
        z_result_t join_rc = z_task_join(z_task_move(&t));
        printf("task.join.rc=%d ran=%d\n", (int)join_rc, task_ran);
        z_task_init(&t2, NULL, task_body, NULL);
        z_task_detach(z_task_move(&t2));
        printf("task.detached.check=%d\n", (int)z_internal_task_check(&t2));
        z_internal_task_null(&t3);
        printf("task.null.check=%d\n", (int)z_internal_task_check(&t3));
    }

    /* The LOG closure family. The CALL is what distinguishes a working closure
       from a gravestone, so it is driven rather than only checked. */
    {
        zc_owned_closure_log_t lc;
        zc_internal_closure_log_null(&lc);
        printf("log.null.check=%d\n", (int)zc_internal_closure_log_check(&lc));
        log_calls = 0;
        log_drops = 0;
        zc_closure_log(&lc, on_log, on_log_drop, NULL);
        printf("log.built.check=%d\n", (int)zc_internal_closure_log_check(&lc));
        z_view_string_t msg;
        z_view_string_from_str(&msg, "hello");
        zc_closure_log_call(zc_closure_log_loan(&lc), ZC_LOG_SEVERITY_WARN,
                            z_view_string_loan(&msg));
        printf("log.calls=%d\n", log_calls);
        zc_closure_log_drop(zc_closure_log_move(&lc));
        printf("log.drops=%d check=%d\n", log_drops, (int)zc_internal_closure_log_check(&lc));
    }

    /* The MATCHING-STATUS closure's own four entry points. */
    {
        z_owned_closure_matching_status_t mc;
        z_internal_closure_matching_status_null(&mc);
        printf("match.null.check=%d\n", (int)z_internal_closure_matching_status_check(&mc));
        match_calls = 0;
        match_last = -1;
        z_closure_matching_status(&mc, on_match, NULL, NULL);
        printf("match.built.check=%d\n", (int)z_internal_closure_matching_status_check(&mc));
        z_matching_status_t st;
        st.matching = true;
        z_closure_matching_status_call(z_closure_matching_status_loan(&mc), &st);
        printf("match.calls=%d last=%d\n", match_calls, match_last);
        z_closure_matching_status_drop(z_closure_matching_status_move(&mc));
    }

    /* The three `z_internal_*_handler_*` pairs whose families are HAND-WRITTEN
       in wz rather than macro-generated. The gravestone / live distinction is
       the whole observable content of the pair. */
    {
        z_owned_fifo_handler_query_t fq;
        z_owned_fifo_handler_reply_t fr;
        z_owned_ring_handler_sample_t rs;
        z_internal_fifo_handler_query_null(&fq);
        z_internal_fifo_handler_reply_null(&fr);
        z_internal_ring_handler_sample_null(&rs);
        printf("handler.null.checks=%d/%d/%d\n",
               (int)z_internal_fifo_handler_query_check(&fq),
               (int)z_internal_fifo_handler_reply_check(&fr),
               (int)z_internal_ring_handler_sample_check(&rs));
        z_owned_closure_query_t cq;
        z_owned_closure_reply_t cr;
        z_owned_closure_sample_t cs;
        z_fifo_channel_query_new(&cq, &fq, 4);
        z_fifo_channel_reply_new(&cr, &fr, 4);
        z_ring_channel_sample_new(&cs, &rs, 4);
        printf("handler.live.checks=%d/%d/%d\n",
               (int)z_internal_fifo_handler_query_check(&fq),
               (int)z_internal_fifo_handler_reply_check(&fr),
               (int)z_internal_ring_handler_sample_check(&rs));
        z_fifo_handler_query_drop(z_fifo_handler_query_move(&fq));
        z_fifo_handler_reply_drop(z_fifo_handler_reply_move(&fr));
        z_ring_handler_sample_drop(z_ring_handler_sample_move(&rs));
        z_closure_query_drop(z_closure_query_move(&cq));
        z_closure_reply_drop(z_closure_reply_move(&cr));
        z_closure_sample_drop(z_closure_sample_move(&cs));
    }

    /* The owned REPLY-ERROR family's gravestone half. A LIVE reply error needs
       a queryable that answers with one, which is an interop question rather
       than a pure-function one; what is pure here is the null / check / drop
       cycle.

       `z_reply_err_loan` on a gravestone is deliberately NOT compared, and the
       reason is a MEASURED divergence rather than an omission: upstream's loan
       is a cast of the owned struct's own address and is therefore never NULL,
       while wz's hands back the boxed `ReplyMarshal` the accessors read — which
       is null for a gravestone. wz cannot match without giving up that model,
       and the model is load-bearing: `z_reply_err(reply)` is the OTHER producer
       of a `z_loaned_reply_err_t*`, and one C pointer type cannot carry two
       pointee types. The divergence runs in the safe direction — a caller that
       loans a gravestone gets NULL here and a pointer into a dead value
       upstream — and it is unreachable for a caller who checks first, which is
       what `z_internal_reply_err_check` is for. */
    {
        z_owned_reply_err_t re;
        z_internal_reply_err_null(&re);
        printf("reply_err.null.check=%d\n", (int)z_internal_reply_err_check(&re));
        z_reply_err_drop(z_reply_err_move(&re));
        printf("reply_err.after_drop.check=%d\n", (int)z_internal_reply_err_check(&re));
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

    // ANCHORS: lines whose value is known from OUTSIDE the two programs.
    //
    // The diff below is an equality between two stdouts, and an equality is
    // silent when both sides are wrong the same way. R311y570 is the proof:
    // the two `z_bytes_*` constructor lines read an UNINITIALISED
    // `z_owned_bytes_t`, so both arms printed stack junk — and locally the junk
    // agreed, so the leg stayed green while measuring nothing. Hosted disagreed
    // and that is the only reason it was found.
    //
    // Each anchor states a length this file can derive without running anything
    // (`STATIC_BUF` is 4 bytes; `"OWNED"` is 5 characters), and it is asserted
    // against BOTH arms, so neither a wz defect nor a probe defect can hide.
    const ANCHORS: &[&str] = &[
        "bytes.from_static_buf.rc=0 len=4",
        "bytes.from_str.rc=0 len=5",
        "bytes.copy_from_slice.len=5 empty=0",
        "bytes.copy_from_string.len=6",
        "bytes.empty.is_empty=1",
        // R311y570 — the two push spellings, stated as the FACT upstream's API
        // contract asserts rather than left to an arm-vs-arm agreement. The
        // sibling pico ABI is the reason this is anchored: there the same
        // measurement found upstream's `_by_alias` COPYING despite its name, so
        // "the two arms agree" is demonstrably not the same claim as "the
        // function does what it is called".
        "array.alias_is_source_buffer=1",
        "array.copy_is_source_buffer=0",
    ];
    for (arm, stdout) in [("wz", &wz_stdout), ("reference", &ref_stdout)] {
        for anchor in ANCHORS {
            assert!(
                stdout.lines().any(|l| l == *anchor),
                "the {arm} arm never printed the anchor line `{anchor}`. An anchor \
                 is a value derived OUTSIDE both programs, so its absence means the \
                 probe measured something other than what it names — which is what \
                 an arm-vs-arm diff cannot see.\n--- {arm} stdout ---\n{stdout}"
            );
        }
    }

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
