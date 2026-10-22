// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zenoh-pico's two header arms, each against the wz build of the same arm: what a C
//! program allocates, wz writes inside of.
//!
//! `Z_FEATURE_MULTI_THREAD` changes the size of structs a program allocates in its own
//! frame without naming them in its source: `_z_fifo_mt_t` and `_z_ring_mt_t` (184 and
//! 136 bytes multi-threaded, 48 and 48 single-threaded), which pico's channel macros
//! allocate and hand to `_z_fifo_mt_init` / `_z_ring_mt_init`, and `z_open_options_t`
//! (16 bytes against 1), which `z_open_options_default` fills. A single-threaded program
//! once linked wz's one multi-threaded build: the init zeroed 184 bytes into a 48-byte
//! slot and the default wrote 16 bytes into a 1-byte struct (open-debt item 918).
//!
//! The probe puts a guard block right after each struct, calls wz's writer, and reports
//! whether the guard survived. It runs in each arm against that arm's wz build, and once
//! against the mismatched pair, which must fail: that run is the control showing the
//! probe can see an overrun.

use std::path::Path;
use std::process::Command;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{compile_pico_source, PicoHeaderArm};

const PROBE: &str = r#"
#include <stdio.h>
#include <string.h>
#include "zenoh-pico.h"
#include "zenoh-pico/collections/fifo_mt.h"
#include "zenoh-pico/collections/ring_mt.h"

#define GUARD 64

static int intact(const unsigned char *guard) {
    for (int i = 0; i < GUARD; i++) {
        if (guard[i] != 0xA5) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    int bad = 0;

    struct { _z_fifo_mt_t value; unsigned char guard[GUARD]; } fifo;
    memset(fifo.guard, 0xA5, GUARD);
    if (_z_fifo_mt_init(&fifo.value, 4) != _Z_RES_OK) {
        printf("layout-probe: _z_fifo_mt_init failed\n");
        return 2;
    }
    if (!intact(fifo.guard)) {
        printf("layout-probe: _z_fifo_mt_init wrote past sizeof(_z_fifo_mt_t)\n");
        bad = 1;
    }
    _z_fifo_mt_clear(&fifo.value, NULL);

    struct { _z_ring_mt_t value; unsigned char guard[GUARD]; } ring;
    memset(ring.guard, 0xA5, GUARD);
    if (_z_ring_mt_init(&ring.value, 4) != _Z_RES_OK) {
        printf("layout-probe: _z_ring_mt_init failed\n");
        return 2;
    }
    if (!intact(ring.guard)) {
        printf("layout-probe: _z_ring_mt_init wrote past sizeof(_z_ring_mt_t)\n");
        bad = 1;
    }
    _z_ring_mt_clear(&ring.value, NULL);

    struct { z_open_options_t value; unsigned char guard[GUARD]; } open;
    memset(open.guard, 0xA5, GUARD);
    z_open_options_default(&open.value);
    if (!intact(open.guard)) {
        printf("layout-probe: z_open_options_default wrote past sizeof(z_open_options_t)\n");
        bad = 1;
    }

    printf("layout-probe: fifo=%zu ring=%zu open_options=%zu\n", sizeof(_z_fifo_mt_t),
           sizeof(_z_ring_mt_t), sizeof(z_open_options_t));
    if (!bad) {
        printf("layout-probe: ok\n");
    }
    return bad;
}
"#;

/// Compile the probe against `headers` and link it to the wz build of `library`, then
/// run it. Returns whether it exited cleanly and what it printed.
fn run_probe(headers: PicoHeaderArm, library: PicoHeaderArm, dir: &Path) -> (bool, String) {
    let out_dir = dir.join(format!("{headers:?}-{library:?}"));
    std::fs::create_dir_all(&out_dir).expect("probe build dir");
    let src = out_dir.join("wz_pico_header_arm_layout.c");
    std::fs::write(&src, PROBE).expect("write the probe source");
    let cdylib = library.wz_cdylib();
    let libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let exe = compile_pico_source(
        &src,
        &out_dir,
        &headers.include_dirs(),
        &libdir,
        "wz_capi_pico",
    )
    .unwrap_or_else(|diag| {
        panic!("the layout probe does not link ({headers:?} headers, {library:?} build)\n{diag}")
    });
    let out = Command::new(&exe)
        .output_bounded()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", exe.display()));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

// wz-proves: none -- the header arm and the wz build a C program links, paired
#[test]
#[ignore = "compiles against the CMake-configured pico headers of both arms and links \
            both wz builds; run by run-ci Layer E"]
fn each_header_arm_is_written_inside_of_by_its_own_build() {
    let dir = tempfile::tempdir().expect("tempdir for the probes");
    for arm in [PicoHeaderArm::MultiThreaded, PicoHeaderArm::SingleThreaded] {
        let (clean, text) = run_probe(arm, arm, dir.path());
        assert!(
            clean && text.contains("layout-probe: ok"),
            "{arm:?}: wz's build of this arm wrote past a struct the program allocated:\n{text}"
        );
    }

    // The control: the single-threaded headers against the multi-threaded build, the
    // pairing that overran. A probe that passes this cannot see what it checks for.
    let (clean, text) = run_probe(
        PicoHeaderArm::SingleThreaded,
        PicoHeaderArm::MultiThreaded,
        dir.path(),
    );
    assert!(
        !clean,
        "the mismatched pair ran clean, so the probe cannot see an overrun:\n{text}"
    );
}
