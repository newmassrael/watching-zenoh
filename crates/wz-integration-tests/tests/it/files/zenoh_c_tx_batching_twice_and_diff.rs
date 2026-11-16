// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport/link/tx/queue/batching/enabled`, read off the link a session writes: one C
//! program, compiled once, linked against wz's cdylib and against the real `libzenohc.so`, and
//! run once per value of the key with its connecting session dialling through a tap.
//!
//! ## Upstream's rule
//!
//! The key reaches every unicast pipeline (`io/zenoh-transport/src/manager.rs` @
//! `self = self.batching_enabled(*link.tx().queue().batching().enabled());`), and the pipeline
//! moves the batch a message was written into out to the link at once when batching is off
//! (`io/zenoh-transport/src/common/pipeline.rs` @ `if !self.batching || $msg.is_express() {`).
//! With batching on, the batch stays open for the next message until the writer pulls it, so a
//! burst that outruns the writer shares batches.
//!
//! ## The leg
//!
//! The program opens a listening session with a subscriber, then a session that dials the
//! listener through this test's tap with the key stated. It puts until the subscriber hears one,
//! then puts a burst of `BURST` samples with congestion control `BLOCK`, so none is dropped for
//! want of a batch, and waits for the subscriber to hear them. The tap's record of what the
//! dialling session wrote is split into its batches, each a length prefix and the bytes behind
//! it, and every transport message of a batch is dissected for its puts.
//!
//! The reference arm is asked first and must show the rule: with the key `false` no batch carries
//! two puts, with it `true` some batch does, and the whole burst crossed the link both times. A
//! reference that does not show it cannot adjudicate wz's, and the leg fails there. wz's arm must
//! then show the same on both values.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
};
use wz_integration_tests::wire_tap::{tap_proxy, Recording, Side};
use wz_session_core::dissect::{dissect_transport_message, Field, FieldValue};

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

/// How many samples the burst puts, handed to the program on its command line. Far more than a
/// writer keeps up with one at a time, so a session that batches is seen to.
const BURST: usize = 4000;

const PROBE: &str = r#"#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

static atomic_int got;

static void on_sample(struct z_loaned_sample_t *sample, void *ctx) {
    (void)sample;
    (void)ctx;
    atomic_fetch_add(&got, 1);
}

static int open_with(z_owned_session_t *s, const char *role, const char *endpoint,
                     const char *batching) {
    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { return -100; }
    if (zc_config_insert_json5(z_config_loan_mut(&config), "scouting/multicast/enabled",
                               "false") != Z_OK) { return -101; }
    char value[256];
    snprintf(value, sizeof value, "[\"%s\"]", endpoint);
    if (zc_config_insert_json5(z_config_loan_mut(&config), role, value) != Z_OK) {
        return -102;
    }
    if (batching && zc_config_insert_json5(z_config_loan_mut(&config),
                                           "transport/link/tx/queue/batching/enabled",
                                           batching) != Z_OK) {
        return -103;
    }
    return z_open(s, z_move(config), NULL);
}

/* BLOCK, so a put waits for a batch rather than being dropped without one: every put of the
   burst crosses the link and the batches are the only thing the key can move. */
static int put_one(const z_loaned_session_t *s, const char *key) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_owned_bytes_t payload;
    z_bytes_from_static_str(&payload, "b");
    z_put_options_t options;
    z_put_options_default(&options);
    options.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    return z_put(s, z_loan(ke), z_move(payload), &options);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
                "usage: probe <listen-endpoint> <connect-endpoint> <true|false> <burst>\n");
        return 2;
    }
    const int burst = atoi(argv[4]);
    if (burst <= 0) { return 2; }
    z_owned_session_t a, b;
    z_owned_subscriber_t sub;
    int rc = open_with(&a, "listen/endpoints", argv[1], NULL);
    printf("listen=%d\n", rc);
    if (rc != Z_OK) { return 1; }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "wz/batching/**");
    z_owned_closure_sample_t cb;
    z_closure(&cb, on_sample, NULL, NULL);
    rc = z_declare_subscriber(z_loan(a), &sub, z_loan(ke), z_move(cb), NULL);
    printf("subscriber=%d\n", rc);
    if (rc != Z_OK) { return 1; }
    rc = open_with(&b, "connect/endpoints", argv[2], argv[3]);
    printf("connect=%d\n", rc);
    if (rc != Z_OK) { return 1; }

    /* Put until the listener's subscription has reached this session and a sample arrives. */
    for (int i = 0; i < 250 && atomic_load(&got) == 0; i++) {
        put_one(z_loan(b), "wz/batching/warm");
        z_sleep_ms(20);
    }
    z_sleep_ms(200);
    int before = atomic_load(&got);
    printf("warm=%d\n", before > 0);

    int refused = 0;
    for (int i = 0; i < burst; i++) {
        if (put_one(z_loan(b), "wz/batching/burst") != Z_OK) { refused++; }
    }
    for (int i = 0; i < 250 && atomic_load(&got) - before < burst; i++) { z_sleep_ms(20); }
    printf("burst refused=%d delivered=%d\n", refused, atomic_load(&got) - before);

    z_drop(z_move(b));
    z_drop(z_move(sub));
    z_drop(z_move(a));
    printf("done\n");
    return 0;
}
"#;

/// The probe linked against each library: `(on wz, wz's libdir, on the reference, its libdir)`,
/// with the directory that holds them.
struct Arms {
    on_wz: PathBuf,
    wz_libdir: PathBuf,
    on_ref: PathBuf,
    ref_libdir: PathBuf,
    _dir: tempfile::TempDir,
}

/// Compile the probe once per library.
fn build_both_arms(include: &Path) -> Arms {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_tx_batching.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_tx_batching",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| panic!("the batching probe does NOT link against wz's cdylib.\n{diag}"));

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let ref_libdir = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_tx_batching",
        &ref_dir,
        include,
        &src_dir,
        &ref_libdir,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the batching probe does not link against the REAL libzenohc.so\n{diag}")
    });

    Arms {
        on_wz,
        wz_libdir,
        on_ref,
        ref_libdir,
        _dir: dir,
    }
}

/// What one run's dialling session put on its link: how many batches carried a put, how many
/// puts they carried in all, and the most any one batch carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BurstReading {
    batches: usize,
    puts: usize,
    most: usize,
}

impl BurstReading {
    /// Whether this run shows upstream's rule for the key's value: off, every batch that carries
    /// a put carries that one alone; on, some batch carries two or more. Either way the whole
    /// burst crossed the link, so the batches read are the burst's and not a remnant of it.
    fn shows(self, batching: bool) -> bool {
        let crossed = self.puts >= BURST;
        if batching {
            crossed && self.most >= 2
        } else {
            crossed && self.batches == self.puts
        }
    }
}

/// The puts under `field`, at any depth.
fn puts_in(field: &Field) -> usize {
    let own = usize::from(field.name == "put");
    match &field.value {
        FieldValue::Nested(children) => own + children.iter().map(puts_in).sum::<usize>(),
        _ => own,
    }
}

/// The puts of every batch on a stream link, in order: each batch is a two-byte little-endian
/// length and the transport messages behind it, read one after another by this tree's dissector.
/// A message it cannot read ends its batch's count there, and a batch the stream stops inside is
/// not counted.
fn puts_per_batch(stream: &[u8]) -> Vec<usize> {
    let mut batches = Vec::new();
    let mut at = 0;
    while let Some(prefix) = stream.get(at..at + 2) {
        let len = usize::from(u16::from_le_bytes([prefix[0], prefix[1]]));
        let Some(batch) = stream.get(at + 2..at + 2 + len) else {
            break;
        };
        at += 2 + len;
        let mut puts = 0;
        let mut offset = 0;
        while offset < batch.len() {
            let Ok(message) = dissect_transport_message(&batch[offset..], 0) else {
                break;
            };
            puts += puts_in(&message);
            if message.span.end == 0 {
                break;
            }
            offset += message.span.end;
        }
        batches.push(puts);
    }
    batches
}

/// The bytes the dialling side wrote, in the order the tap forwarded them.
fn dialler_stream(recording: &Recording) -> Vec<u8> {
    recording
        .lock()
        .expect("recording lock")
        .iter()
        .filter(|(side, _)| *side == Side::FromDialer)
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect()
}

/// Run `exe` with the key stated as `batching`, its dialling session reaching the listener
/// through a tap, and read what that session put on the link. Also returns what it printed.
fn burst_through_a_tap(exe: &Path, libdir: &Path, batching: bool) -> (BurstReading, String) {
    let reservation = PortReservation::pick();
    let listen = reservation.port();
    let (tap, recording) = tap_proxy(listen);
    let out = Command::new(exe)
        .arg(format!("tcp/127.0.0.1:{listen}"))
        .arg(format!("tcp/127.0.0.1:{tap}"))
        .arg(batching.to_string())
        .arg(BURST.to_string())
        .env("LD_LIBRARY_PATH", libdir)
        .output_bounded()
        .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
    drop(reservation);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success() && stdout.contains("done"),
        "the batching probe {} exited {} with batching {batching}:\n{stdout}\n{}",
        exe.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    // The tap's pumps end when the program's sockets close; give them the moment that takes.
    std::thread::sleep(Duration::from_millis(200));
    let carrying: Vec<usize> = puts_per_batch(&dialler_stream(&recording))
        .into_iter()
        .filter(|&puts| puts > 0)
        .collect();
    let reading = BurstReading {
        batches: carrying.len(),
        puts: carrying.iter().sum(),
        most: carrying.iter().copied().max().unwrap_or(0),
    };
    (reading, stdout)
}

// wz-proves: none -- a config key's effect on the batches one session writes, claimed for no atom
/// A session with `transport/link/tx/queue/batching/enabled` off writes each put in a batch of
/// its own, and with it on lets a burst share batches, identically on wz and libzenohc.
#[test]
#[ignore = "opens sessions and reads a zenoh-c oracle; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn a_session_without_batching_writes_each_put_in_a_batch_of_its_own_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let arms = build_both_arms(&include);

    let mut failures: Vec<String> = Vec::new();
    for batching in [false, true] {
        let (upstream, ref_stdout) = burst_through_a_tap(&arms.on_ref, &arms.ref_libdir, batching);
        eprintln!("batching {batching}: libzenohc wrote {upstream:?}");
        assert!(
            upstream.shows(batching),
            "with batching {batching} the REFERENCE wrote {upstream:?}, which is not upstream's \
             rule for that value, so this machine's libzenohc cannot adjudicate wz's\n{ref_stdout}"
        );
        let (wz, wz_stdout) = burst_through_a_tap(&arms.on_wz, &arms.wz_libdir, batching);
        eprintln!("batching {batching}: wz wrote {wz:?}");
        if !wz.shows(batching) {
            failures.push(format!(
                "with batching {batching} wz wrote {wz:?} where libzenohc wrote {upstream:?}\n\
                 --- wz printed ---\n{wz_stdout}--- libzenohc printed ---\n{ref_stdout}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "wz's C ABI and libzenohc batch a session's puts differently for the same key:\n{}",
        failures.join("\n")
    );
}
