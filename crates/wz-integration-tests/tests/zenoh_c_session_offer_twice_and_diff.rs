// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — what a session's links OFFER at their handshake, read
//! from its config, on wz's cdylib as on the real `libzenohc.so`: one C program,
//! compiled once, linked twice, stdout compared.
//!
//! ## Upstream's rule
//!
//! zenoh builds every transport from its manager config, and that config reads
//! `transport/unicast/{qos/enabled, lowlatency, compression/enabled}`
//! (`io/zenoh-transport/src/unicast/manager.rs` @
//! `self = self.qos(*config.transport().unicast().qos().enabled());`), with the
//! dialling and the accepting side reading the same values. QoS is ON by
//! default. QoS and lowlatency together are refused when the manager is built
//! (`bail!("'qos' and 'lowlatency' options are incompatible");`), inside
//! `zenoh::open`, which zenoh-c reports as `Z_ENETWORK`.
//!
//! ## What this measured before R2970
//!
//! wz's zenoh-c session offered NOTHING, on either side of a link, whatever its
//! config said. Two default sessions agreed on no QoS where two real ones
//! agree on it (`qos=0` against `qos=1`), and a config enabling both QoS and
//! lowlatency opened where upstream refuses it (`open=0` against `open=-4`).
//!
//! ## The legs
//!
//! Two listeners stay up for the whole run: `A1` with the default config, and
//! `A2` with QoS off and lowlatency and compression on. Each leg opens one
//! connecting session with its own config, waits for its transport, prints what
//! that transport negotiated, publishes one sample named after the leg and
//! prints whether the listener received it intact.
//!
//! - `default` / `noqos` / `noshm` / `compression_into_default` /
//!   `lean_into_default` — into `A1`.
//! - `into_lean_listener` — a default connector into `A2`: QoS is refused by
//!   the ACCEPTING side's config, which is the half an accept loop with no offer
//!   of its own could not express.
//! - `lean_compressed` — lowlatency and compression on both ends: nothing a C
//!   accessor reports, so the leg's claim is that the lean, compressed transport
//!   carries the sample on both libraries. It does not ask for its transport:
//!   upstream's lowlatency transport answers `z_info_transports` through
//!   `tokio::runtime::Handle::current()` on the caller's thread
//!   (`io/zenoh-transport/src/unicast/lowlatency/transport.rs` @
//!   `fn get_links(&self) -> Vec<Link> {`) and so panics when a C thread asks —
//!   measured here as an abort of the reference arm the first time this leg
//!   asked. That abort is also the one direct sign the transport really was made
//!   lowlatency on both ends.
//! - `qos_and_lowlatency` — refused at the open.
//!
//! ## The shared-memory column
//!
//! On the shared-memory arm upstream negotiates SHM by default and reports it on a
//! transport. This column was HELD as a pin -- upstream `1` where wz was `0` -- while a
//! zenoh peer that agreed on SHM would have sent Puts laid out as slices that wz's
//! generated Put codec could not read (open-debt item 823). That stopped being true when
//! the layout was adopted and the session began offering SHM (R3052), but the column went
//! on reading `0` for another round, because the transport snapshot reads `is_shm` from
//! the session only when the session model is built with its SHM feature and the C ABI's
//! SHM arm did not enable it (R3059). With it enabled the column is the real library's,
//! `1,1,0,1,1,1`, and the whole output is compared as it stands, on an arm without shared
//! memory as on one with it.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
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

const PROBE: &str = r#"#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include "zenoh.h"

#define KEY_PREFIX "wz/offer/"

/* A sample counts only if the payload names the key it arrived on, so a
   stray or corrupted delivery is counted as bad rather than as good. */
static atomic_int got_ok;
static atomic_int got_bad;

static void on_sample(struct z_loaned_sample_t *sample, void *ctx) {
    (void)ctx;
    z_view_string_t key;
    z_keyexpr_as_view_string(z_sample_keyexpr(sample), &key);
    z_owned_string_t payload;
    z_bytes_to_string(z_sample_payload(sample), &payload);
    const char *k = z_string_data(z_loan(key));
    size_t klen = z_string_len(z_loan(key));
    const char *p = z_string_data(z_loan(payload));
    size_t plen = z_string_len(z_loan(payload));
    size_t prefix = strlen(KEY_PREFIX);
    if (klen == prefix + plen && memcmp(k + prefix, p, plen) == 0) {
        atomic_fetch_add(&got_ok, 1);
    } else {
        atomic_fetch_add(&got_bad, 1);
    }
    z_drop(z_move(payload));
}

static void count_transport(struct z_loaned_transport_t *t, void *ctx) {
    (void)t;
    (*(int *)ctx)++;
}

static void print_transport(struct z_loaned_transport_t *t, void *ctx) {
    const char *leg = (const char *)ctx;
#if defined(Z_FEATURE_SHARED_MEMORY)
    printf("%s transport qos=%d shm=%d\n", leg, (int)z_transport_is_qos(t),
           (int)z_transport_is_shm(t));
#else
    printf("%s transport qos=%d shm=-\n", leg, (int)z_transport_is_qos(t));
#endif
}

static int transports(z_owned_session_t *s) {
    int n = 0;
    z_owned_closure_transport_t cb;
    z_closure_transport(&cb, count_transport, NULL, &n);
    z_info_transports(z_loan(*s), z_move(cb));
    return n;
}

static int open_with(z_owned_session_t *s, const char *role, const char *endpoint,
                     const char *const *kv) {
    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { return -100; }
    if (zc_config_insert_json5(z_config_loan_mut(&config), "scouting/multicast/enabled",
                               "false") != Z_OK) { return -101; }
    char value[256];
    snprintf(value, sizeof value, "[\"%s\"]", endpoint);
    if (zc_config_insert_json5(z_config_loan_mut(&config), role, value) != Z_OK) {
        return -102;
    }
    for (; kv && kv[0]; kv += 2) {
        if (zc_config_insert_json5(z_config_loan_mut(&config), kv[0], kv[1]) != Z_OK) {
            return -103;
        }
    }
    return z_open(s, z_move(config), NULL);
}

static int listen_with(z_owned_session_t *s, z_owned_subscriber_t *sub, const char *endpoint,
                       const char *const *kv) {
    int rc = open_with(s, "listen/endpoints", endpoint, kv);
    if (rc != Z_OK) { return rc; }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KEY_PREFIX "**");
    z_owned_closure_sample_t cb;
    z_closure(&cb, on_sample, NULL, NULL);
    return z_declare_subscriber(z_loan(*s), sub, z_loan(ke), z_move(cb), NULL);
}

/* `ask` is 0 for a transport both ends made LOWLATENCY: upstream's lowlatency
   transport answers `z_info_transports` by calling `Handle::current()` from
   the caller's thread and panics outside a tokio runtime (see the module doc).
   Such a leg waits instead of asking, and is judged on delivery alone. */
static void leg(const char *name, const char *endpoint, const char *const *kv, int ask) {
    z_owned_session_t b;
    int rc = open_with(&b, "connect/endpoints", endpoint, kv);
    printf("%s open=%d\n", name, rc);
    if (rc != Z_OK) { return; }
    if (ask) {
        for (int i = 0; i < 250 && transports(&b) == 0; i++) { z_sleep_ms(20); }
        z_owned_closure_transport_t cb;
        z_closure_transport(&cb, print_transport, NULL, (void *)name);
        z_info_transports(z_loan(b), z_move(cb));
    } else {
        z_sleep_ms(500);
    }

    /* Let the listener's subscription reach this session, then publish. */
    z_sleep_ms(300);
    int before = atomic_load(&got_ok);
    char key[128];
    snprintf(key, sizeof key, KEY_PREFIX "%s", name);
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_owned_bytes_t payload;
    z_bytes_from_static_str(&payload, name);
    rc = z_put(z_loan(b), z_loan(ke), z_move(payload), NULL);
    for (int i = 0; i < 150 && atomic_load(&got_ok) == before; i++) { z_sleep_ms(20); }
    printf("%s put=%d delivered=%d\n", name, rc, atomic_load(&got_ok) - before);
    z_drop(z_move(b));
    z_sleep_ms(100);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: probe <endpoint-a1> <endpoint-a2>\n"); return 2; }
    const char *const none[] = {NULL};
    const char *const noqos[] = {"transport/unicast/qos/enabled", "false", NULL};
    const char *const noshm[] = {"transport/shared_memory/enabled", "false", NULL};
    const char *const lean[] = {"transport/unicast/qos/enabled", "false",
                                "transport/unicast/lowlatency", "true", NULL};
    const char *const lean_compressed[] = {"transport/unicast/qos/enabled", "false",
                                           "transport/unicast/lowlatency", "true",
                                           "transport/unicast/compression/enabled", "true",
                                           NULL};
    const char *const compressed[] = {"transport/unicast/compression/enabled", "true", NULL};
    const char *const qos_and_lowlatency[] = {"transport/unicast/lowlatency", "true", NULL};

    z_owned_session_t a1, a2;
    z_owned_subscriber_t s1, s2;
    printf("A1 listen=%d\n", listen_with(&a1, &s1, argv[1], none));
    printf("A2 listen=%d\n", listen_with(&a2, &s2, argv[2], lean_compressed));

    leg("default", argv[1], none, 1);
    leg("noqos", argv[1], noqos, 1);
    leg("noshm", argv[1], noshm, 1);
    leg("compression_into_default", argv[1], compressed, 1);
    leg("lean_into_default", argv[1], lean, 1);
    leg("into_lean_listener", argv[2], none, 1);
    leg("lean_compressed", argv[2], lean_compressed, 0);
    leg("qos_and_lowlatency", argv[1], qos_and_lowlatency, 1);

    printf("bad=%d\n", atomic_load(&got_bad));
    z_drop(z_move(s1));
    z_drop(z_move(s2));
    z_drop(z_move(a1));
    z_drop(z_move(a2));
    printf("done\n");
    return 0;
}
"#;

/// Compile the probe once per library and run it, each on its own ports.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_session_offer.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_session_offer",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!("§5.27 api-compat-c: the session-offer probe does NOT link against wz's cdylib.\n{diag}")
    });

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let libdir_ref = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_session_offer",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the session-offer probe does not link against the REAL libzenohc.so\n{diag}")
    });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        // Two ports under ONE reservation, as the harness requires.
        let (reservation, second) = PortReservation::pick_pair();
        let out = Command::new(exe)
            .arg(format!("tcp/127.0.0.1:{}", reservation.port()))
            .arg(format!("tcp/127.0.0.1:{second}"))
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
        "the session-offer probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// Every `shm=<v>` value the probe printed, in order: the column the reference's own
/// rule is read off, so a reference that does not show it measures nothing.
fn shm_column(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.split_once(" shm=").map(|(_, value)| value.to_owned()))
        .collect()
}

/// THE GATE: a session offers what its config enables, on both sides of a
/// link, identically on wz and libzenohc.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "opens sessions and reads a zenoh-c oracle; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn a_sessions_transport_capabilities_follow_its_config_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h")).unwrap_or_default();
    let defines = |name: &str| {
        configure
            .lines()
            .any(|l| l.trim() == format!("#define {name}"))
    };
    if !defines("Z_FEATURE_UNSTABLE_API") {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_UNSTABLE_API, where \
             z_info_transports and z_transport_is_qos do not exist."
        );
        return;
    }
    let shm_arm = defines("Z_FEATURE_SHARED_MEMORY");
    assert_zenoh_c_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // The ORACLE first: a reference that does not show the rule measures nothing.
    for expected in [
        "A1 listen=0",
        "A2 listen=0",
        "default transport qos=1",
        "noqos transport qos=0",
        "noshm transport qos=1",
        "compression_into_default transport qos=1",
        "lean_into_default transport qos=0",
        "into_lean_listener transport qos=0",
        "lean_compressed open=0",
        "qos_and_lowlatency open=-4",
        "bad=0",
        "done",
    ] {
        assert!(
            ref_stdout.contains(expected),
            "the reference did not print `{expected}`, so the rule this leg compares \
             against is not what it assumes:\n{ref_stdout}"
        );
    }
    for leg in [
        "default",
        "noqos",
        "noshm",
        "compression_into_default",
        "lean_into_default",
        "into_lean_listener",
        "lean_compressed",
    ] {
        assert!(
            ref_stdout.contains(&format!("{leg} put=0 delivered=1")),
            "the reference did not deliver the `{leg}` sample:\n{ref_stdout}"
        );
    }

    if shm_arm {
        // Upstream agrees on SHM wherever both ends leave it on: every leg but the one
        // that turned it off. The oracle first, so the equality below is against a
        // reference that shows the rule.
        assert_eq!(
            shm_column(&ref_stdout),
            ["1", "1", "0", "1", "1", "1"],
            "the reference's SHM column is not the one this leg was taken from:\n{ref_stdout}"
        );
    } else {
        assert!(
            shm_column(&ref_stdout).iter().all(|v| v == "-"),
            "on an arm without shared memory the reference prints `shm=-`:\n{ref_stdout}"
        );
    }
    assert_eq!(
        wz_stdout, ref_stdout,
        "§5.27 api-compat-c: wz's C ABI and libzenohc disagree about what a session's \
         links offer.\n--- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
    );
}
