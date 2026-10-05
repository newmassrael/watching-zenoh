// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- what a shared-memory provider DOES when it is asked for
//! chunks, on wz's cdylib as on the real `libzenohc.so`: one C program, compiled once,
//! linked twice, stdout diffed.
//!
//! ## Why this exists
//!
//! The C ABI's built-in provider was written as a process-memory allocator that frees a
//! chunk the moment its owner drops it, from a first-fit free list that spends nothing on
//! headers. Upstream's provider does neither: a dropped chunk waits on its busy list until
//! a collection takes it, and its allocator (talc) spends a header on every chunk and a
//! kilobyte of the arena on its own bins. The sibling differential
//! (`zenoh_c_session_shm_provider_twice_and_diff.rs`) measures how a session OBTAINS a
//! provider and one cell of its accounting; nothing measured the allocation SEMANTICS,
//! which is what a program that allocates once a second for as long as it runs depends on.
//! This is that measurement. It was written BEFORE the C ABI was moved onto the runtime's
//! provider, and its first run against wz was the list of differences that move had to
//! close (pools of 0 and 1000 bytes made, 999 one-byte chunks held, a plain allocation
//! served from a chunk dropped and not collected, an aligned request served that the real
//! library refuses, a deep `z_shm_clone`); the move is the round that made it agree.
//!
//! ## Measured on the real library before it was a test
//!
//! A default provider of 1000 bytes or fewer cannot be created and one of 4096 can. In a
//! 4096-byte pool chunks of 1 and 8 bytes stop at 127, of 64 at 42, of 100 at 27, of 512 at
//! 5, of 1024 at 2 and of 2000 at 1. A chunk dropped but not collected is not served again by
//! a plain allocation. `z_shm_provider_garbage_collect` answers the size of the largest chunk
//! it took. A provider handed a gravestone SEGFAULTS the real library, so every leg here
//! checks that its provider was made before it uses it.
//!
//! ## The legs
//!
//! - **A** pool creation at 0, 1000, 4096 and 5000 bytes.
//! - **B** capacity: how many chunks of 1, 64, 512 and 1024 bytes a 4096-byte pool serves.
//! - **C** a full pool, a chunk dropped, a plain allocation, a collection, a plain
//!   allocation again.
//! - **D** a fragmented pool: three chunks, the outer two dropped, a request that fits the
//!   total free space and no single hole -- with the status each policy reports.
//! - **E** the policies on a pool one chunk fills: plain, collecting, defragmenting, and the
//!   one that takes back the newest chunk whether or not it is held.
//! - **F** alignment: the address of an aligned chunk, a layout whose size is not a multiple
//!   of its alignment, and a size of zero.
//! - **G** the bytes: a pattern written through one chunk is read back through it, and the
//!   length is the length asked for.

use std::path::{Path, PathBuf};
use std::process::Command;

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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

/* A result as one line. The error fields are read only for the status that sets them:
   the other is uninitialised on the real library and printing it would diff garbage. */
static void show(const char *tag, z_buf_layout_alloc_result_t *r) {
    if (r->status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK) {
        printf("%s status=OK len=%zu\n", tag, z_shm_mut_len(z_loan_mut(r->buf)));
    } else if (r->status == ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR) {
        printf("%s status=ALLOC_ERROR err=%d\n", tag, (int)r->alloc_error);
    } else {
        printf("%s status=LAYOUT_ERROR err=%d\n", tag, (int)r->layout_error);
    }
}

static void release(z_buf_layout_alloc_result_t *r) {
    if (r->status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK) {
        z_shm_mut_drop(z_move(r->buf));
        r->status = ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR;
    }
}

/* How many chunks of `chunk` bytes a fresh `pool`-byte provider serves before it refuses. */
static size_t capacity(size_t pool, size_t chunk) {
    z_owned_shm_provider_t p;
    if (z_shm_provider_default_new(&p, pool) != Z_OK) { return (size_t)-1; }
    z_buf_layout_alloc_result_t *held = calloc(1000, sizeof *held);
    size_t n = 0;
    while (n < 999) {
        z_shm_provider_alloc(&held[n], z_loan(p), chunk);
        if (held[n].status != ZC_BUF_LAYOUT_ALLOC_STATUS_OK) { break; }
        n++;
    }
    for (size_t i = 0; i < n; i++) { release(&held[i]); }
    free(held);
    z_shm_provider_drop(z_move(p));
    return n;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    z_owned_shm_provider_t p;
    z_buf_layout_alloc_result_t r, a[4];
    int rc;

    /* A */
    size_t sizes[] = {0, 1000, 4096, 5000};
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        rc = z_shm_provider_default_new(&p, sizes[i]);
        printf("A.new(%zu) ok=%d\n", sizes[i], rc == Z_OK);
        if (rc == Z_OK) { z_shm_provider_drop(z_move(p)); }
    }

    /* B */
    size_t chunks[] = {1, 64, 512, 1024};
    for (size_t i = 0; i < sizeof chunks / sizeof chunks[0]; i++) {
        printf("B.capacity(4096,%zu)=%zu\n", chunks[i], capacity(4096, chunks[i]));
    }

    /* C */
    if (z_shm_provider_default_new(&p, 4096) != Z_OK) { printf("C.new FAILED\n"); return 1; }
    for (int i = 0; i < 2; i++) {
        z_shm_provider_alloc(&a[i], z_loan(p), 1024);
        char tag[16];
        snprintf(tag, sizeof tag, "C.a%d", i);
        show(tag, &a[i]);
    }
    z_shm_provider_alloc(&r, z_loan(p), 1024);
    show("C.third", &r);
    release(&r);
    release(&a[1]);
    z_shm_provider_alloc(&r, z_loan(p), 1024);
    show("C.plain_after_drop", &r);
    release(&r);
    printf("C.gc=%zu\n", z_shm_provider_garbage_collect(z_loan(p)));
    z_shm_provider_alloc(&r, z_loan(p), 1024);
    show("C.plain_after_gc", &r);
    release(&r);
    printf("C.gc_again=%zu\n", z_shm_provider_garbage_collect(z_loan(p)));
    release(&a[0]);
    z_shm_provider_drop(z_move(p));

    /* D */
    if (z_shm_provider_default_new(&p, 4096) != Z_OK) { printf("D.new FAILED\n"); return 1; }
    z_buf_layout_alloc_result_t c[3];
    for (int i = 0; i < 3; i++) {
        z_shm_provider_alloc(&c[i], z_loan(p), 700);
        char tag[16];
        snprintf(tag, sizeof tag, "D.c%d", i);
        show(tag, &c[i]);
    }
    release(&c[0]);
    release(&c[2]);
    printf("D.available=%zu defragment=%zu\n", z_shm_provider_available(z_loan(p)),
           z_shm_provider_defragment(z_loan(p)));
    z_shm_provider_alloc(&r, z_loan(p), 1400);
    show("D.plain1400", &r);
    release(&r);
    z_shm_provider_alloc_gc(&r, z_loan(p), 1400);
    show("D.gc1400", &r);
    release(&r);
    z_shm_provider_alloc_gc_defrag(&r, z_loan(p), 1400);
    show("D.gc_defrag1400", &r);
    release(&r);
    z_shm_provider_alloc_gc_defrag(&r, z_loan(p), 700);
    show("D.gc_defrag700", &r);
    release(&r);
    release(&c[1]);
    z_shm_provider_drop(z_move(p));

    /* E */
    if (z_shm_provider_default_new(&p, 4096) != Z_OK) { printf("E.new FAILED\n"); return 1; }
    z_shm_provider_alloc(&a[0], z_loan(p), 2048);
    show("E.fill", &a[0]);
    z_shm_provider_alloc(&r, z_loan(p), 2048);
    show("E.plain_while_held", &r);
    release(&r);
    z_shm_provider_alloc_gc(&r, z_loan(p), 2048);
    show("E.gc_while_held", &r);
    release(&r);
    z_shm_provider_alloc_gc_defrag_dealloc(&r, z_loan(p), 2048);
    show("E.dealloc_while_held", &r);
    release(&r);
    release(&a[0]);
    z_shm_provider_alloc(&r, z_loan(p), 2048);
    show("E.plain_after_drop", &r);
    release(&r);
    z_shm_provider_alloc_gc(&r, z_loan(p), 2048);
    show("E.gc_after_drop", &r);
    release(&r);
    z_shm_provider_drop(z_move(p));

    /* F */
    if (z_shm_provider_default_new(&p, 4096) != Z_OK) { printf("F.new FAILED\n"); return 1; }
    z_shm_provider_alloc(&r, z_loan(p), 3);
    z_alloc_alignment_t five = { 5 };
    z_buf_layout_alloc_result_t al;
    z_shm_provider_alloc_aligned(&al, z_loan(p), 64, five);
    show("F.aligned64_pow5", &al);
    if (al.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK) {
        uintptr_t addr = (uintptr_t)z_shm_mut_data_mut(z_loan_mut(al.buf));
        printf("F.addr_mod_32=%u\n", (unsigned)(addr % 32));
    }
    release(&al);
    z_alloc_alignment_t three = { 3 };
    z_shm_provider_alloc_aligned(&al, z_loan(p), 10, three);
    show("F.size10_pow3", &al);
    release(&al);
    z_shm_provider_alloc(&al, z_loan(p), 0);
    show("F.size0", &al);
    release(&al);
    release(&r);

    /* G */
    z_shm_provider_alloc(&al, z_loan(p), 16);
    if (al.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK) {
        uint8_t *d = z_shm_mut_data_mut(z_loan_mut(al.buf));
        for (int i = 0; i < 16; i++) { d[i] = (uint8_t)(0xA0 + i); }
        const uint8_t *s = z_shm_mut_data(z_loan_mut(al.buf));
        int same = 1;
        for (int i = 0; i < 16; i++) { if (s[i] != (uint8_t)(0xA0 + i)) { same = 0; } }
        printf("G.readback=%d len=%zu\n", same, z_shm_mut_len(z_loan_mut(al.buf)));
    }
    release(&al);
    z_shm_provider_drop(z_move(p));
    printf("done\n");
    return 0;
}
"#;

/// Compile the probe once per library and run it.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_shm_alloc.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_shm_alloc",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: the allocation probe does NOT link against wz's cdylib.\n{diag}"
        )
    });

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let libdir_ref = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_shm_alloc",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the allocation probe does not link against the REAL libzenohc.so\n{diag}")
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
    let (ref_ok, ref_stdout) = run(&on_ref, &libdir_ref);
    let (wz_ok, wz_stdout) = run(&on_wz, &wz_libdir);
    assert!(
        ref_ok,
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one here.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "the allocation probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// THE GATE: a provider is made, fills, refuses, collects and aligns identically on wz and
/// libzenohc.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_providers_allocation_semantics_are_identical_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h")).unwrap_or_default();
    let defines = |name: &str| {
        configure
            .lines()
            .any(|l| l.trim() == format!("#define {name}"))
    };
    if !(defines("Z_FEATURE_UNSTABLE_API") && defines("Z_FEATURE_SHARED_MEMORY")) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where the provider plane does not exist."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // The ORACLE first: two identical failures diff clean.
    assert!(
        ref_stdout.contains("done") && ref_stdout.contains("A.new(4096) ok=1"),
        "the reference did not run the allocation legs to the end:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("C.plain_after_drop status=ALLOC_ERROR"),
        "the reference served a plain allocation from a chunk that was dropped and not \
         collected, so the leg that separates wz's old allocator from upstream's measures \
         nothing:\n{ref_stdout}"
    );

    assert_eq!(
        wz_stdout, ref_stdout,
        "§5.27 api-compat-c: wz's C ABI and libzenohc disagree about what a provider does \
         when asked for chunks.\n--- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
    );
}
