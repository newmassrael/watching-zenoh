// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zenoh-pico's header arms, each against the wz build of the same arm: what a C
//! program allocates, wz writes inside of, and where the program reads it.
//!
//! The switches change the size of structs a program allocates in its own frame.
//! `Z_FEATURE_MULTI_THREAD` does it without the program naming them: `_z_fifo_mt_t` and
//! `_z_ring_mt_t` (184 and 136 bytes multi-threaded, 48 and 48 single-threaded), which
//! pico's channel macros allocate and hand to `_z_fifo_mt_init` / `_z_ring_mt_init`, and
//! `z_open_options_t` (16 bytes against 1). `Z_FEATURE_UNSTABLE_API` does it to every
//! option struct with a `reliability`, `source_info` or `cancellation_token` field, and
//! in `z_get_options_t` the missing pair sits before `accept_replies`, which moves. A
//! single-threaded program once linked wz's one multi-threaded build: the init zeroed
//! 184 bytes into a 48-byte slot and the default wrote 16 bytes into a 1-byte struct
//! (open-debt item 918); a program compiled against upstream's default header had no wz
//! build of its layout at all (open-debt item 917). The local switches add a locality
//! field to seven option structs (open-debt item 914).
//!
//! The probe puts a guard block right after each struct, calls wz's writer, and reports
//! whether the guard survived; for `z_get_options_t` it also reads `accept_replies`
//! where the program's header puts it, and in the local arm the locality fields the
//! defaults write. It runs in each arm against that arm's wz build, and against three
//! mismatched pairs, which must fail: those runs are the controls showing the probe can
//! see a struct written past or beside.

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

static int bad = 0;

static int intact(const unsigned char *guard) {
    for (int i = 0; i < GUARD; i++) {
        if (guard[i] != 0xA5) {
            return 0;
        }
    }
    return 1;
}

/* Fill a `T` with wz's default writer `f` and check nothing past it was written. */
#define CHECK_DEFAULT(T, f)                                                     \
    do {                                                                        \
        struct { T value; unsigned char guard[GUARD]; } s;                      \
        memset(s.guard, 0xA5, GUARD);                                           \
        f(&s.value);                                                            \
        if (!intact(s.guard)) {                                                 \
            printf("layout-probe: " #f " wrote past sizeof(" #T ") = %zu\n",    \
                   sizeof(T));                                                  \
            bad = 1;                                                            \
        }                                                                       \
    } while (0)

int main(void) {
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

    CHECK_DEFAULT(z_open_options_t, z_open_options_default);
    CHECK_DEFAULT(z_put_options_t, z_put_options_default);
    CHECK_DEFAULT(z_delete_options_t, z_delete_options_default);
    CHECK_DEFAULT(z_publisher_options_t, z_publisher_options_default);
    CHECK_DEFAULT(z_publisher_put_options_t, z_publisher_put_options_default);
    CHECK_DEFAULT(z_publisher_delete_options_t, z_publisher_delete_options_default);
    CHECK_DEFAULT(z_get_options_t, z_get_options_default);
    CHECK_DEFAULT(z_querier_get_options_t, z_querier_get_options_default);
    CHECK_DEFAULT(z_query_reply_options_t, z_query_reply_options_default);
    CHECK_DEFAULT(z_query_reply_del_options_t, z_query_reply_del_options_default);
    CHECK_DEFAULT(z_liveliness_get_options_t, z_liveliness_get_options_default);
#if Z_FEATURE_ADVANCED_PUBLICATION == 1
    /* Embeds `z_publisher_options_t`, so the local switch moves its every later field. */
    CHECK_DEFAULT(ze_advanced_publisher_options_t, ze_advanced_publisher_options_default);
    printf("layout-probe: advanced_publisher_options=%zu\n",
           sizeof(ze_advanced_publisher_options_t));
#endif

    /* The field after the unstable pair, read where this program's header puts it. */
    z_get_options_t get;
    memset(&get, 0xEE, sizeof(get));
    z_get_options_default(&get);
    if (get.accept_replies != Z_REPLY_KEYEXPR_DEFAULT) {
        printf("layout-probe: z_get_options_default left accept_replies at %d\n",
               (int)get.accept_replies);
        bad = 1;
    }
#if Z_FEATURE_LOCAL_QUERYABLE == 1
    if (get.allowed_destination != Z_LOCALITY_ANY) {
        printf("layout-probe: z_get_options_default left allowed_destination at %d\n",
               (int)get.allowed_destination);
        bad = 1;
    }
#endif
#if Z_FEATURE_LOCAL_SUBSCRIBER == 1
    /* The locality fields the local switches add, where this program's header puts them. */
    z_subscriber_options_t sub;
    memset(&sub, 0xEE, sizeof(sub));
    z_subscriber_options_default(&sub);
    if (sub.allowed_origin != Z_LOCALITY_ANY) {
        printf("layout-probe: z_subscriber_options_default left allowed_origin at %d\n",
               (int)sub.allowed_origin);
        bad = 1;
    }
    z_put_options_t put;
    memset(&put, 0xEE, sizeof(put));
    z_put_options_default(&put);
    if (put.allowed_destination != Z_LOCALITY_ANY) {
        printf("layout-probe: z_put_options_default left allowed_destination at %d\n",
               (int)put.allowed_destination);
        bad = 1;
    }
#endif

    printf("layout-probe: fifo=%zu ring=%zu open_options=%zu get_options=%zu\n",
           sizeof(_z_fifo_mt_t), sizeof(_z_ring_mt_t), sizeof(z_open_options_t),
           sizeof(z_get_options_t));
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
#[ignore = "compiles against the CMake-configured pico headers of every arm and links \
            every wz build; run by run-ci Layer E"]
fn each_header_arm_is_written_inside_of_by_its_own_build() {
    let dir = tempfile::tempdir().expect("tempdir for the probes");
    for arm in [
        PicoHeaderArm::MultiThreaded,
        PicoHeaderArm::SingleThreaded,
        PicoHeaderArm::UpstreamDefault,
        PicoHeaderArm::Local,
    ] {
        let (clean, text) = run_probe(arm, arm, dir.path());
        assert!(
            clean && text.contains("layout-probe: ok"),
            "{arm:?}: wz's build of this arm wrote past or beside a struct the program \
             allocated:\n{text}"
        );
    }

    // The controls: each pairing of another arm's headers with the reference build — the
    // smaller arms', which it overran, and the local arm's, whose locality fields it does
    // not write. A probe that passes these cannot see what it checks for.
    for headers in [
        PicoHeaderArm::SingleThreaded,
        PicoHeaderArm::UpstreamDefault,
        PicoHeaderArm::Local,
    ] {
        let (clean, text) = run_probe(headers, PicoHeaderArm::MultiThreaded, dir.path());
        assert!(
            !clean,
            "{headers:?} headers against the reference build ran clean, so the probe \
             cannot see an overrun:\n{text}"
        );
    }
}
