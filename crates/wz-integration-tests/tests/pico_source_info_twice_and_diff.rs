// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — the `source_info` FOREIGN ADJUDICATOR.
//!
//! ## The last plane on which wz only ever judged itself
//!
//! R311y561 built the pico ABI's put-side `source_info`, y562-y563 built the
//! reply and query sides, and every witness any of them produced is wz driving
//! wz with damage probes standing in for a second opinion. y566 closed that on
//! the ZENOH-C ABI with a patched upstream program compiled once and linked
//! twice; the debt ledger has carried the pico half since, calling it "the
//! cheapest high-value item on this list" because the technique already exists
//! and transfers.
//!
//! It transfers, and it gets SIMPLER on this side. zenoh-c's
//! `z_entity_global_id_t` is opaque with accessors and no constructor, so its
//! probe has to declare a publisher it does not otherwise want purely to obtain
//! an id. pico exports `z_entity_global_id_new(&gid, &zid, eid)` — a real
//! constructor — and `z_source_info_t` is a plain by-value struct passed by
//! pointer rather than an owned/moved family. So the probe says what it means:
//! build an id, build a source info, put with it, read it back.
//!
//! ## Why a SESSION probe rather than an accessor probe
//!
//! The interesting claim is not that the accessors round-trip in isolation — it
//! is that the `(zid, eid, sn)` a publisher SETS is the `(zid, eid, sn)` a
//! subscriber READS, which is a wire claim and needs a live session on each arm.
//!
//! ## TWO sessions, because the topology was CALIBRATED and the obvious one fails
//!
//! The zenoh-c adjudicator uses ONE session: a zenoh-c peer delivers its own put
//! to its own subscriber. A pico peer does NOT. That was measured before this
//! probe was written rather than discovered by a red lane — the single-session
//! form ran clean through `put.rc=0` on the REAL `libzenohpico.so` and then
//! blocked in `z_recv` forever, so a leg built on it would have hung identically
//! on both arms and, under a timeout, been reported as agreement.
//!
//! So each arm opens two sessions in one process over a real TCP link, with the
//! SUBSCRIBER listening and the publisher dialling — the direction this tree's
//! topology note prescribes, since a declared publisher that dials out never
//! arms its write filter. The two arms still differ only in which implementation
//! answers.
//!
//! The subscriber uses a RING CHANNEL rather than a callback, which is what
//! makes the leg deterministic: `z_recv` blocks until the sample arrives instead
//! of sleeping and hoping. A callback probe would be a rate measurement wearing
//! a boolean's clothes.
//!
//! ## What is printed, and what deliberately is not
//!
//! The `zid` is per-session and CANNOT match across the two arms — each library
//! mints its own. So the probe prints the entity id, the sequence number, and
//! whether the zid ROUND-TRIPS (the sample's zid equals the one the program put
//! in), never the zid bytes. Printing them would make the diff fail for the one
//! reason that is not a defect — the same rule the zenoh-c adjudicator records.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    compile_pico_source, wz_capi_pico_cdylib, zenoh_pico_include_dirs, zenoh_pico_library_dir,
    zenoh_pico_shared_library, PortReservation,
};

/// upstream's `z_pub.c` + `z_sub.c` fused and PATCHED to carry a source info.
///
/// Written here rather than edited into `vendor/zenoh-pico` so the oracle
/// checkout stays pristine — the same choice the zenoh-c adjudicator makes, and
/// for the same reason: a patched submodule is a reference nobody can trust
/// twice.
///
/// The whole `source_info` READ half sits behind pico's own
/// `#ifdef Z_FEATURE_UNSTABLE_API` (`primitives.h:2218-2244` gates
/// `z_sample_source_info`), so the probe copies upstream's condition rather than
/// inventing one. The CONSTRUCTORS are ungated on this side, which is itself a
/// difference from zenoh-c worth having the probe demonstrate rather than assert.
const PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh-pico.h"

/* TWO sessions over a real TCP link, and that is a CALIBRATED choice rather
   than a stylistic one. The zenoh-c adjudicator gets away with one session
   because a zenoh-c peer delivers its own put to its own subscriber; a pico
   peer does NOT. Measured before this probe was written: the single-session
   form ran clean through `put.rc=0` on the REAL libzenohpico and then blocked
   in `z_recv` forever. A leg built on it would have timed out identically on
   both arms and been reported as agreement.

   So the subscriber LISTENS and the publisher DIALS it, which is also the
   direction this tree's topology note prescribes — a declared publisher that
   dials out never arms its write filter, so the reverse arrangement delivers
   nothing between two real picos either. */
/* R311y572 — `key` is `uint8_t`, not `const char *`. pico's config keys are
   small integer constants (`Z_CONFIG_LISTEN_KEY` is `0x42`) and
   `zp_config_insert` takes a `uint8_t`; the pointer-typed parameter this had
   round-tripped only because a SysV-x86-64 truncation is lossless for values
   that small, and gcc warned about it on every build of this probe. */
static int open_session(z_owned_session_t *out, uint8_t key, const char *endpoint) {
    z_owned_config_t config;
    z_config_default(&config);
    if (zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "peer") < 0) return -1;
    if (zp_config_insert(z_loan_mut(config), key, endpoint) < 0) return -1;
    if (z_open(out, z_move(config), NULL) < 0) return -1;
    /* pico needs its read and lease tasks started explicitly; upstream's own
       examples do this immediately after `z_open`. Without them nothing moves
       and the ring below would never fill. */
    if (zp_start_read_task(z_loan_mut(*out), NULL) < 0) return -1;
    if (zp_start_lease_task(z_loan_mut(*out), NULL) < 0) return -1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <endpoint>\n"); return 2; }

    z_owned_session_t subs;
    if (open_session(&subs, Z_CONFIG_LISTEN_KEY, argv[1]) < 0) {
        printf("open.sub=FAILED\n"); return 1;
    }

    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, "wz/pico/source_info/probe") < 0) {
        printf("keyexpr=FAILED\n"); return 1;
    }

    /* A RING channel, so the read below BLOCKS rather than sleeps. */
    z_owned_closure_sample_t closure;
    z_owned_ring_handler_sample_t handler;
    z_ring_channel_sample_new(&closure, &handler, 4);
    z_owned_subscriber_t sub;
    if (z_declare_subscriber(z_loan(subs), &sub, z_loan(ke), z_move(closure), NULL) < 0) {
        printf("declare_subscriber=FAILED\n"); return 1;
    }

    z_owned_session_t pubs;
    if (open_session(&pubs, Z_CONFIG_CONNECT_KEY, argv[1]) < 0) {
        printf("open.pub=FAILED\n"); return 1;
    }

    /* THE PATCH begins. Upstream's z_pub.c never touches source_info.

       Note what pico makes EASY that zenoh-c does not: `z_entity_global_id_new`
       is a real constructor, so no publisher has to be declared purely to
       obtain an id, and `z_source_info_t` is a by-value struct rather than an
       owned/moved family. The zenoh-c probe needs both detours. */
    z_id_t zid = z_info_zid(z_loan(pubs));
    z_entity_global_id_t gid;
    printf("gid.new.rc=%d\n", (int)z_entity_global_id_new(&gid, &zid, 4242u));
    printf("gid.eid=%u\n", (unsigned)z_entity_global_id_eid(&gid));
    z_id_t gid_zid = z_entity_global_id_zid(&gid);
    printf("gid.zid_round_trips=%d\n", memcmp(&gid_zid, &zid, sizeof zid) == 0);

    z_source_info_t info = z_source_info_new(&gid, 28784u);
    printf("source_info.sn=%u\n", (unsigned)z_source_info_sn(&info));
    z_entity_global_id_t back = z_source_info_id(&info);
    printf("source_info.eid_round_trips=%d\n",
           z_entity_global_id_eid(&back) == z_entity_global_id_eid(&gid));
    z_id_t back_zid = z_entity_global_id_zid(&back);
    printf("source_info.zid_round_trips=%d\n",
           memcmp(&back_zid, &zid, sizeof zid) == 0);

    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "pico-source-info");
    z_put_options_t opts;
    z_put_options_default(&opts);
    opts.source_info = &info;

    z_result_t put_rc = z_put(z_loan(pubs), z_loan(ke), z_move(payload), &opts);
    printf("put.rc=%d\n", (int)put_rc);
    if (put_rc < 0) { return 1; }

    z_owned_sample_t sample;
    z_result_t rc = z_recv(z_loan(handler), &sample);
    printf("recv.rc=%d\n", (int)rc);
    if (rc == Z_OK) {
        const z_loaned_sample_t *sm = z_loan(sample);
        z_view_string_t ke_str;
        z_keyexpr_as_view_string(z_sample_keyexpr(sm), &ke_str);
        printf("sample.keyexpr=%.*s\n",
               (int)z_string_len(z_loan(ke_str)), z_string_data(z_loan(ke_str)));
        z_owned_string_t body;
        z_bytes_to_string(z_sample_payload(sm), &body);
        printf("sample.payload=%.*s\n",
               (int)z_string_len(z_loan(body)), z_string_data(z_loan(body)));
        z_drop(z_move(body));
#ifdef Z_FEATURE_UNSTABLE_API
        const z_source_info_t *got = z_sample_source_info(sm);
        printf("sample.source_info_present=%d\n", got != NULL);
        if (got != NULL) {
            z_entity_global_id_t sample_gid = z_source_info_id(got);
            z_id_t got_zid = z_entity_global_id_zid(&sample_gid);
            /* THE WIRE CLAIM: the sn and the eid the publisher set are the ones
               the subscriber reads. Both are program-chosen CONSTANTS, so unlike
               the zid they ARE comparable across the two arms. */
            printf("sample.sn=%u\n", (unsigned)z_source_info_sn(got));
            printf("sample.eid=%u\n", (unsigned)z_entity_global_id_eid(&sample_gid));
            /* The zid is per-session and cannot match across arms, so only the
               round trip against the PUBLISHER's own zid is printed. */
            printf("sample.zid_round_trips=%d\n",
                   memcmp(&got_zid, &zid, sizeof zid) == 0);
        }
#endif
        z_drop(z_move(sample));
    }

    z_drop(z_move(sub));
    z_drop(z_move(handler));
    z_drop(z_move(pubs));
    z_drop(z_move(subs));
    printf("done\n");
    return 0;
}
"#;

/// Compile once, link twice, run both, return the two stdouts.
fn run_both_arms() -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src = dir.path().join("wz_pico_source_info.c");
    std::fs::write(&src, PROBE).expect("write the probe source");
    let includes = zenoh_pico_include_dirs();

    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_pico_source(&src, dir.path(), &includes, &wz_libdir, "wz_capi_pico")
        .unwrap_or_else(|diag| {
            panic!(
                "§5.27 api-compat-pico: the patched source-info probe does NOT link \
                 against wz's pico cdylib. A missing symbol here is a program upstream \
                 can write and wz cannot run.\n{diag}"
            )
        });

    // Through the REGISTERED resolver, not a path join: Layer A4 reads a file's
    // foreign class off the resolver functions it names, so a hand-built path
    // makes the reference arm invisible to the audit even though it links real
    // pico. `zenoh_pico_shared_library` is named here for exactly that reason
    // (and asserts the artifact exists), `zenoh_pico_library_dir` is what `-L`
    // needs.
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
                "the patched source-info probe does not link against the REAL \
                 libzenohpico.so\n{diag}"
            )
        });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        // A port EACH, held across the child's whole run: both arms LISTEN, so
        // sharing one would make the second fail to bind for a reason that has
        // nothing to do with either implementation.
        let port = PortReservation::pick();
        let out = Command::new(exe)
            .arg(format!("tcp/127.0.0.1:{}", port.port()))
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
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one here \
         — the comparison below would be meaningless.\n{ref_stdout}"
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
         scripts/build-zenoh-pico-cli.sh. Hosted CI provisions it before the \
         sweep that runs this, so a skip here is a LOCAL gap, not a passing run."
    );
    None
}

/// THE ADJUDICATOR: a patched upstream program carries a `source_info`
/// identically on wz's pico ABI and on the real `libzenohpico.so`.
///
/// The reference arm LINKS `libzenohpico.so` itself, which is a stronger witness
/// than spawning a pico CLI: the foreign implementation answers every call the
/// probe makes rather than only the ones that reach the wire.
///
/// `partial`: it covers the PUT plane's `source_info` on this ABI. The get,
/// querier and reply folds carry the same field through the same seam and are
/// not driven here — the same scope the zenoh-c adjudicator declares, for the
/// same reason.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "links the CMake-built libzenohpico.so oracle; run by run-ci Layer E, \
            whose ignored-test sweep carries no --skip token this file matches"]
fn a_patched_upstream_put_carries_source_info_identically_on_wz_and_libzenohpico() {
    if oracle_or_note().is_none() {
        return;
    }
    let (wz_stdout, ref_stdout) = run_both_arms();

    // Asserted BEFORE the diff: two empty captures are equal, and an equality
    // between them would report the strongest result this file can produce
    // while measuring nothing.
    assert!(
        ref_stdout.contains("done"),
        "the reference arm did not reach the end of the probe, so an equality \
         below would be an equality between two failures.\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("sample.source_info_present=1"),
        "the REFERENCE arm did not carry the source info to its own subscriber. \
         Without that, this leg is vacuous — it would be comparing two libraries \
         that both drop the field.\n{ref_stdout}"
    );
    // The two comparable wire values, pinned on the reference arm specifically.
    // A probe whose constants never reached the sample would still diff EQUAL if
    // both arms dropped them, which is the shape a `_present` check alone misses.
    assert!(
        ref_stdout.contains("sample.sn=28784") && ref_stdout.contains("sample.eid=4242"),
        "the REFERENCE arm did not deliver the program's own sn / eid, so those \
         lines cannot adjudicate anything.\n{ref_stdout}"
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
