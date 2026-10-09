// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — which payload constructors ALIAS the caller's
//! buffer, and when does the caller's deleter run?
//!
//! ## What was recorded, and what was never measured
//!
//! wz's payload model is an owning `Vec<u8>`, so every pico constructor that
//! takes a caller's buffer COPIED it: `z_bytes_from_static_str` and
//! `z_bytes_from_static_buf` copy where pico's names say "static", and
//! `z_bytes_from_buf` / `z_bytes_from_str` / `z_slice_from_buf` /
//! `z_string_from_str` run the caller's deleter at CONSTRUCTION where pico runs
//! it when the value is dropped. The crate's own docs called the first "a cost
//! divergence, confined to cost" and the second "one observable consequence".
//!
//! Both sentences were read off the source, and this workspace has paid for
//! that shape before: `pico_string_array_alias_twice_and_diff` measured a
//! recorded "upstream aliases" divergence and found upstream COPIES, so the
//! item had described a gap that did not exist. This probe asks the real
//! `libzenohpico.so` each question first, so the direction of every fix comes
//! from the library and not from a constructor's name.
//!
//! ## The discriminators
//!
//! An alias and a copy read back identically through `len`, `bytes` and every
//! accessor. They differ on questions a C program can ask:
//!
//! * POINTER IDENTITY — does the view `z_bytes_get_contiguous_view` (or the
//!   slice iterator, or `z_slice_data`, or `z_string_data`) describe the
//!   CALLER'S buffer? A pointer value cannot be diffed across arms; its
//!   identity with a buffer the program owns can.
//! * MUTATION — the consequence of that identity: change the source after the
//!   constructor and see whether the payload moved.
//! * DELETER TIMING — a counter the deleter bumps, sampled after construction,
//!   after a view, after a clone, after each drop. This is what `bytes_clone`
//!   sharing looks like from C: one deleter call, after the LAST holder.
//!
//! ## Why this cannot be a vacuous pass
//!
//! "Nothing aliases" is what a probe blind to aliasing would report. The
//! control is `z_bytes_copy_from_str`, which must copy on both arms, and the
//! probe's `z_view_slice_t` route is the route that reports identity for the
//! alias constructors on the arm that has them.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    compile_pico_source, wz_capi_pico_cdylib, zenoh_pico_include_dirs, zenoh_pico_library_dir,
    zenoh_pico_shared_library,
};

/// The probe.
///
/// Every constructor and every drop gets its own statement before a value is
/// read. Folding a constructor and an accessor into one `printf` leaves them
/// unsequenced (R311y568), and Layer C0's unsequenced-probe lint rejects the
/// shape.
const PROBE: &str = r#"#include <stdio.h>
#include <string.h>
#include "zenoh-pico.h"

static int deleted = 0;
static const void *deleted_value = NULL;

static void counting_deleter(void *value, void *context) {
    (void)context;
    deleted++;
    deleted_value = value;
}

/* Read a payload through the contiguous view and say what the caller can tell:
   whether it describes `src`, how long it is, and what it holds. */
static void show(const char *label, const z_loaned_bytes_t *b, const void *src) {
    z_view_slice_t v;
    z_result_t rc = z_bytes_get_contiguous_view(b, &v);
    printf("%s.view.rc=%d\n", label, (int)rc);
    if (rc != Z_OK) {
        return;
    }
    const z_loaned_slice_t *sl = z_view_slice_loan(&v);
    const uint8_t *d = z_slice_data(sl);
    size_t n = z_slice_len(sl);
    printf("%s.is_source=%d\n", label, (int)(d == (const uint8_t *)src));
    printf("%s.len=%zu\n", label, n);
    printf("%s.bytes=%.*s\n", label, (int)n, (const char *)d);
}

int main(void) {
    z_owned_bytes_t b;
    z_owned_bytes_t c;
    z_result_t rc;

    /* CONTROL: a copy constructor must not alias, on either arm. */
    char copy_buf[8];
    memcpy(copy_buf, "SAME", 5);
    rc = z_bytes_copy_from_str(&b, copy_buf);
    printf("copy_str.rc=%d\n", (int)rc);
    show("copy_str", z_bytes_loan(&b), copy_buf);
    copy_buf[0] = 'X';
    show("copy_str.after_mutation", z_bytes_loan(&b), copy_buf);
    z_bytes_drop(z_bytes_move(&b));

    /* STATIC STRING: pico's name says static. The buffer is writable here only
       so the mutation below can observe the consequence of aliasing. */
    char static_str[8];
    memcpy(static_str, "SAME", 5);
    rc = z_bytes_from_static_str(&b, static_str);
    printf("static_str.rc=%d\n", (int)rc);
    show("static_str", z_bytes_loan(&b), static_str);
    static_str[0] = 'X';
    show("static_str.after_mutation", z_bytes_loan(&b), static_str);
    z_bytes_drop(z_bytes_move(&b));

    /* STATIC BUFFER. */
    char static_buf[8];
    memcpy(static_buf, "SAME", 5);
    rc = z_bytes_from_static_buf(&b, (const uint8_t *)static_buf, 4);
    printf("static_buf.rc=%d\n", (int)rc);
    show("static_buf", z_bytes_loan(&b), static_buf);
    static_buf[0] = 'X';
    show("static_buf.after_mutation", z_bytes_loan(&b), static_buf);
    {
        z_bytes_slice_iterator_t it = z_bytes_get_slice_iterator(z_bytes_loan(&b));
        z_view_slice_t seg;
        bool more = z_bytes_slice_iterator_next(&it, &seg);
        printf("static_buf.iter.more=%d\n", (int)more);
        printf("static_buf.iter.is_source=%d\n",
               (int)(z_slice_data(z_view_slice_loan(&seg)) == (const uint8_t *)static_buf));
    }
    z_bytes_drop(z_bytes_move(&b));

    /* OWNED BUFFER WITH A DELETER: WHEN does the deleter run, and how many
       times, across a clone. */
    char heap_buf[8];
    memcpy(heap_buf, "HEAP", 5);
    deleted = 0;
    deleted_value = NULL;
    rc = z_bytes_from_buf(&b, (uint8_t *)heap_buf, 4, counting_deleter, NULL);
    printf("from_buf.rc=%d\n", (int)rc);
    printf("from_buf.deleted.after_construct=%d\n", deleted);
    show("from_buf", z_bytes_loan(&b), heap_buf);
    printf("from_buf.deleted.after_view=%d\n", deleted);
    rc = z_bytes_clone(&c, z_bytes_loan(&b));
    printf("from_buf.clone.rc=%d\n", (int)rc);
    show("from_buf.clone", z_bytes_loan(&c), heap_buf);
    printf("from_buf.deleted.after_clone=%d\n", deleted);
    z_bytes_drop(z_bytes_move(&b));
    printf("from_buf.deleted.after_drop_original=%d\n", deleted);
    z_bytes_drop(z_bytes_move(&c));
    printf("from_buf.deleted.after_drop_clone=%d\n", deleted);
    printf("from_buf.deleted_value_is_source=%d\n", (int)(deleted_value == (const void *)heap_buf));

    /* BOUNDARIES: a zero-length buffer with a deleter, and a NULL deleter
       (pico documents it as "static"). */
    deleted = 0;
    deleted_value = NULL;
    rc = z_bytes_from_buf(&b, (uint8_t *)heap_buf, 0, counting_deleter, NULL);
    printf("zero_len.rc=%d\n", (int)rc);
    printf("zero_len.deleted.after_construct=%d\n", deleted);
    printf("zero_len.len=%zu\n", z_bytes_len(z_bytes_loan(&b)));
    z_bytes_drop(z_bytes_move(&b));
    printf("zero_len.deleted.after_drop=%d\n", deleted);

    rc = z_bytes_from_buf(&b, (uint8_t *)heap_buf, 4, NULL, NULL);
    printf("null_deleter.rc=%d\n", (int)rc);
    show("null_deleter", z_bytes_loan(&b), heap_buf);
    z_bytes_drop(z_bytes_move(&b));
    printf("null_deleter.dropped\n");

    /* OWNED STRING WITH A DELETER, moved into a payload. */
    char heap_str[8];
    memcpy(heap_str, "HEAP", 5);
    deleted = 0;
    deleted_value = NULL;
    rc = z_bytes_from_str(&b, heap_str, counting_deleter, NULL);
    printf("from_str.rc=%d\n", (int)rc);
    printf("from_str.deleted.after_construct=%d\n", deleted);
    show("from_str", z_bytes_loan(&b), heap_str);
    z_bytes_drop(z_bytes_move(&b));
    printf("from_str.deleted.after_drop=%d\n", deleted);

    /* A SLICE with a deleter, then moved into a payload. */
    deleted = 0;
    deleted_value = NULL;
    z_owned_slice_t sl;
    rc = z_slice_from_buf(&sl, (uint8_t *)heap_buf, 4, counting_deleter, NULL);
    printf("slice_from_buf.rc=%d\n", (int)rc);
    printf("slice_from_buf.is_source=%d\n",
           (int)(z_slice_data(z_slice_loan(&sl)) == (const uint8_t *)heap_buf));
    printf("slice_from_buf.deleted.after_construct=%d\n", deleted);
    rc = z_bytes_from_slice(&b, z_slice_move(&sl));
    printf("slice_moved.rc=%d\n", (int)rc);
    show("slice_moved", z_bytes_loan(&b), heap_buf);
    printf("slice_moved.deleted.after_move=%d\n", deleted);
    z_bytes_drop(z_bytes_move(&b));
    printf("slice_moved.deleted.after_drop=%d\n", deleted);

    /* A STRING with a deleter, dropped on its own. */
    deleted = 0;
    deleted_value = NULL;
    z_owned_string_t str;
    rc = z_string_from_str(&str, heap_str, counting_deleter, NULL);
    printf("string_from_str.rc=%d\n", (int)rc);
    printf("string_from_str.is_source=%d\n",
           (int)(z_string_data(z_string_loan(&str)) == heap_str));
    printf("string_from_str.deleted.after_construct=%d\n", deleted);
    z_string_drop(z_string_move(&str));
    printf("string_from_str.deleted.after_drop=%d\n", deleted);

    /* MOVES OF OWNED VALUES: does the payload take over the slice's or the
       string's OWN allocation, or copy it? The pointer the source reports
       before the move is the identity the payload is compared against. */
    z_owned_slice_t owned_slice;
    rc = z_slice_copy_from_buf(&owned_slice, (const uint8_t *)"SLIC", 4);
    printf("owned_slice.rc=%d\n", (int)rc);
    const void *owned_slice_data = z_slice_data(z_slice_loan(&owned_slice));
    rc = z_bytes_from_slice(&b, z_slice_move(&owned_slice));
    printf("owned_slice_moved.rc=%d\n", (int)rc);
    show("owned_slice_moved", z_bytes_loan(&b), owned_slice_data);
    z_bytes_drop(z_bytes_move(&b));

    z_owned_string_t owned_string;
    rc = z_string_copy_from_str(&owned_string, "STRG");
    printf("owned_string.rc=%d\n", (int)rc);
    const void *owned_string_data = z_string_data(z_string_loan(&owned_string));
    rc = z_bytes_from_string(&b, z_string_move(&owned_string));
    printf("owned_string_moved.rc=%d\n", (int)rc);
    show("owned_string_moved", z_bytes_loan(&b), owned_string_data);
    z_bytes_drop(z_bytes_move(&b));

    /* CLONES: pico's payload clone SHARES its storage, and its slice and string
       clones copy. */
    char clone_buf[8];
    memcpy(clone_buf, "CLON", 5);
    rc = z_bytes_copy_from_str(&b, clone_buf);
    printf("owned_clone.from.rc=%d\n", (int)rc);
    rc = z_bytes_clone(&c, z_bytes_loan(&b));
    printf("owned_clone.rc=%d\n", (int)rc);
    {
        z_view_slice_t vb;
        z_view_slice_t vc;
        z_result_t rb = z_bytes_get_contiguous_view(z_bytes_loan(&b), &vb);
        z_result_t rcc = z_bytes_get_contiguous_view(z_bytes_loan(&c), &vc);
        printf("owned_clone.view.rc=%d/%d\n", (int)rb, (int)rcc);
        printf("owned_clone.shares_storage=%d\n",
               (int)(z_slice_data(z_view_slice_loan(&vb)) == z_slice_data(z_view_slice_loan(&vc))));
    }
    z_bytes_drop(z_bytes_move(&b));
    z_bytes_drop(z_bytes_move(&c));

    z_owned_slice_t slice_src;
    rc = z_slice_copy_from_buf(&slice_src, (const uint8_t *)"SLIC", 4);
    printf("slice_clone.from.rc=%d\n", (int)rc);
    z_owned_slice_t slice_dup;
    rc = z_slice_clone(&slice_dup, z_slice_loan(&slice_src));
    printf("slice_clone.rc=%d\n", (int)rc);
    printf("slice_clone.shares_storage=%d\n",
           (int)(z_slice_data(z_slice_loan(&slice_src)) == z_slice_data(z_slice_loan(&slice_dup))));
    z_slice_drop(z_slice_move(&slice_src));
    z_slice_drop(z_slice_move(&slice_dup));

    z_owned_string_t string_src;
    rc = z_string_copy_from_str(&string_src, "STRG");
    printf("string_clone.from.rc=%d\n", (int)rc);
    z_owned_string_t string_dup;
    rc = z_string_clone(&string_dup, z_string_loan(&string_src));
    printf("string_clone.rc=%d\n", (int)rc);
    printf("string_clone.shares_storage=%d\n",
           (int)(z_string_data(z_string_loan(&string_src)) == z_string_data(z_string_loan(&string_dup))));
    z_string_drop(z_string_move(&string_src));
    z_string_drop(z_string_move(&string_dup));

    /* EXTRACTION: a payload read out into a slice is a COPY on pico, and a
       program that assumes otherwise reads freed memory. */
    char out_buf[8];
    memcpy(out_buf, "SAME", 5);
    rc = z_bytes_from_static_buf(&b, (const uint8_t *)out_buf, 4);
    printf("to_slice.from.rc=%d\n", (int)rc);
    z_owned_slice_t extracted;
    rc = z_bytes_to_slice(z_bytes_loan(&b), &extracted);
    printf("to_slice.rc=%d\n", (int)rc);
    printf("to_slice.is_source=%d\n",
           (int)(z_slice_data(z_slice_loan(&extracted)) == (const uint8_t *)out_buf));
    z_slice_drop(z_slice_move(&extracted));
    z_bytes_drop(z_bytes_move(&b));

    printf("done\n");
    return 0;
}
"#;

/// Compile once, link twice, run both, return the two stdouts.
fn run_both_arms() -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src = dir.path().join("wz_pico_bytes_alias.c");
    std::fs::write(&src, PROBE).expect("write the probe source");
    let includes = zenoh_pico_include_dirs();

    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_pico_source(&src, dir.path(), &includes, &wz_libdir, "wz_capi_pico")
        .unwrap_or_else(|diag| {
            panic!(
                "§5.27 api-compat-pico: the payload alias probe does NOT link \
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
                "the payload alias probe does not link against the REAL \
                 libzenohpico.so\n{diag}"
            )
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

/// THE GATE: wz's payload constructors alias, and run their deleters, as the
/// real library's do.
///
/// `partial`: the constructors of `z_bytes_t` / `z_slice_t` / `z_string_t`, not
/// the whole ABI.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "reads the CMake-built libzenohpico.so oracle; run by run-ci Layer E"]
fn payload_constructors_on_wz_capi_pico_alias_and_release_as_real_libzenohpico() {
    if oracle_or_note().is_none() {
        return;
    }
    let (wz_stdout, ref_stdout) = run_both_arms();

    // Asserted BEFORE the diff: two empty captures are equal, and an equality
    // between them would report the strongest result this file can produce
    // while measuring nothing.
    assert!(
        ref_stdout.lines().count() >= 100,
        "the reference arm printed only {} line(s) — the probe did not run.\n{ref_stdout}",
        ref_stdout.lines().count()
    );

    // WHAT THE REFERENCE ACTUALLY ANSWERS, stated so a change to upstream shows
    // up as one of these rather than as a silent agreement — and so that wz's
    // agreement below is a measurement and not two arms that both saw nothing.
    //
    // The control comes first: a probe that reported `is_source=1` for a
    // constructor that must copy would be blind in the other direction, and
    // one that reported 0 for everything is what the alias rows would read as
    // if the pointer comparison could not see an alias at all.
    for (key, expected) in [
        // The copy constructor never aliases, and stays put when the source moves.
        ("copy_str.is_source", "0"),
        ("copy_str.after_mutation.bytes", "SAME"),
        // Every constructor that takes a caller's buffer DESCRIBES it, and a
        // change made through the caller's pointer shows in the payload.
        ("static_str.is_source", "1"),
        ("static_str.after_mutation.bytes", "XAME"),
        ("static_buf.iter.is_source", "1"),
        ("from_buf.is_source", "1"),
        ("from_str.is_source", "1"),
        ("slice_from_buf.is_source", "1"),
        ("string_from_str.is_source", "1"),
        // The deleter runs ONCE, when the LAST holder is dropped — not at
        // construction, and not when the first of two holders goes.
        ("from_buf.deleted.after_construct", "0"),
        ("from_buf.deleted.after_clone", "0"),
        ("from_buf.deleted.after_drop_original", "0"),
        ("from_buf.deleted.after_drop_clone", "1"),
        ("slice_moved.deleted.after_move", "0"),
        ("slice_moved.deleted.after_drop", "1"),
        // A move takes over the allocation, and a payload clone shares it; the
        // slice and string clones and an extraction copy.
        ("owned_slice_moved.is_source", "1"),
        ("owned_string_moved.is_source", "1"),
        ("owned_clone.shares_storage", "1"),
        ("slice_clone.shares_storage", "0"),
        ("string_clone.shares_storage", "0"),
        ("to_slice.is_source", "0"),
    ] {
        assert_eq!(
            line_value(&ref_stdout, key),
            expected,
            "the real libzenohpico no longer answers `{key}={expected}`, which \
             is what R2964 measured. wz follows the library, so this is now a \
             divergence to re-measure, not a probe line to edit.\n{ref_stdout}"
        );
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
        "{} of {} probe line(s) differ between wz's pico ABI and the real \
         libzenohpico:\n{}\n--- reference stdout ---\n{ref_stdout}",
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
