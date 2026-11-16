// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport/link/tx/queue/batching/time_limit`, read off the link a session writes as a
//! distribution over repeated runs: one C program, compiled once, linked against wz's cdylib and
//! against the real `libzenohc.so`, its dialling session writing through a tap.
//!
//! No single run shows this key. It bounds how long a link's writer holds back an open batch
//! while producers keep adding to it, and whether a writer holds back at all on a given pull is
//! decided by a race between threads. So the observation is extended from one run's wire to the
//! distribution of many runs', and the difference between two values is decided by a sequential
//! test at a stated error rate rather than read off one sample.
//!
//! ## Upstream's rule
//!
//! The key is each unicast link's backoff threshold
//! (`io/zenoh-transport/src/unicast/universal/link.rs` @
//! `batching_time_limit: transport.manager.config.queue_backoff,`, then
//! `io/zenoh-transport/src/common/pipeline.rs` @
//! `threshold: threshold.as_micros() as MicroSeconds,`). The writer pulls the open batch at once
//! when it can take the batch's lock; when a producer holds it, the writer backs off
//! (`io/zenoh-transport/src/common/pipeline.rs` @
//! `self.backoff.atomic.active.store(true, Ordering::Relaxed);`), and while it backs off a
//! producer's write does not wake it
//! (`io/zenoh-transport/src/common/pipeline.rs` @
//! `if !self.atomic_backoff.active.load(Ordering::Relaxed) {`). It pulls the batch once the
//! producers have stopped adding to it, once the batch is full, or once the batch has been open
//! for the threshold (`io/zenoh-transport/src/common/pipeline.rs` @
//! `if diff >= self.backoff.threshold {`). A threshold of zero pulls at the next look; a long one
//! lets a contended burst fill its batches. Under a burst that several producers contend for, a
//! longer threshold therefore writes the same messages in fewer batches.
//!
//! ## The leg
//!
//! The program opens a listening session with a subscriber, then a session that dials the
//! listener through this test's tap with the key stated. It puts until the subscriber hears one,
//! then `THREADS` threads each put `PER_THREAD` samples with congestion control `BLOCK` at once,
//! and it waits for the subscriber to hear all of them. The tap's record of what the dialling
//! session wrote is split into batches, and the batches that carry a put are counted: that count
//! is one run's reading. A run whose burst did not cross whole is not a reading, and fails.
//!
//! ## The test
//!
//! Each step runs the program twice, once with the key at `SHORT_MS` and once at `LONG_MS` (the
//! order alternates from step to step, so a drift of the host over the steps does not side with
//! one value), and compares the two runs' batch counts. A step is a SUCCESS when the short
//! threshold took more batches, a FAILURE when it took fewer, and a TIE otherwise; ties are set
//! aside, as a sign test sets them aside.
//!
//! - H0: the threshold does not order the batch counts; a step that is not a tie is a success
//!   with probability `p = 1/2`.
//! - H1: the longer threshold takes fewer batches; `p = 9/10`.
//! - Wald's sequential probability ratio test, `alpha = 0.01` (accepting H1 when H0 holds) and
//!   `beta = 0.01` (accepting H0 when H1 holds). After each step that is not a tie, the
//!   log-likelihood ratio moves by `log2(9/5)` on a success and `log2(1/5)` on a failure; it
//!   accepts H1 at `log2((1 - beta) / alpha) = log2(99)` and H0 at `log2(beta / (1 - alpha)) =
//!   log2(1/99)`. Eight successes in a row accept H1, three failures in a row accept H0.
//! - The stopping bound is `MAX_STEPS` steps, ties included. A test still between its bounds
//!   there is UNDECIDED, and undecided is not a pass.
//!
//! The logarithms are the tree's own fixed-point ones
//! (`wz_capture::zenoh_eprocess::log2_ratio`, Q64), the arithmetic the flow verdict's sequential
//! test is kept in.
//!
//! The reference is tested first and must accept H1: the positive control. A reference that
//! accepts H0 or stays undecided cannot adjudicate wz's, and the leg fails there with every
//! step's counts, which are the numbers a reader needs to tell an underpowered control from a
//! key with no effect on this host. wz must then accept H1 under the same test.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use wz_capture::zenoh_eprocess::log2_ratio;
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

/// The threads that put the burst at once: enough that one of them holds the batch's lock
/// whenever the writer looks often enough for the writer to back off.
const THREADS: usize = 4;

/// The samples each thread puts.
const PER_THREAD: usize = 5_000;

/// The short threshold, in milliseconds: the writer pulls at its next look.
const SHORT_MS: u64 = 0;

/// The long threshold, in milliseconds: far longer than a contended burst takes to fill a batch.
const LONG_MS: u64 = 100;

/// The most steps the test takes, ties included, before it is undecided.
const MAX_STEPS: usize = 40;

/// `alpha`, the chance of accepting H1 when H0 holds, as a fraction: one in a hundred.
const ALPHA: (u128, u128) = (1, 100);

/// `beta`, the chance of accepting H0 when H1 holds, as a fraction: one in a hundred.
const BETA: (u128, u128) = (1, 100);

/// The share of steps that are successes under H1: nine in ten.
const P1: (u128, u128) = (9, 10);

const PROBE: &str = r#"#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

#define MAX_THREADS 16

static atomic_int got;

static void on_sample(struct z_loaned_sample_t *sample, void *ctx) {
    (void)sample;
    (void)ctx;
    atomic_fetch_add(&got, 1);
}

static int open_with(z_owned_session_t *s, const char *role, const char *endpoint,
                     const char *time_limit) {
    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { return -100; }
    if (zc_config_insert_json5(z_config_loan_mut(&config), "scouting/multicast/enabled",
                               "false") != Z_OK) { return -101; }
    char value[256];
    snprintf(value, sizeof value, "[\"%s\"]", endpoint);
    if (zc_config_insert_json5(z_config_loan_mut(&config), role, value) != Z_OK) {
        return -102;
    }
    if (time_limit && zc_config_insert_json5(z_config_loan_mut(&config),
                                             "transport/link/tx/queue/batching/time_limit",
                                             time_limit) != Z_OK) {
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
    z_bytes_from_static_str(&payload, "t");
    z_put_options_t options;
    z_put_options_default(&options);
    options.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    return z_put(s, z_loan(ke), z_move(payload), &options);
}

struct producer {
    const z_loaned_session_t *session;
    int puts;
    int refused;
};

static void *produce(void *arg) {
    struct producer *p = arg;
    for (int i = 0; i < p->puts; i++) {
        if (put_one(p->session, "wz/time_limit/burst") != Z_OK) { p->refused++; }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: probe <listen-endpoint> <connect-endpoint> <time_limit_ms> "
                        "<threads> <per-thread>\n");
        return 2;
    }
    const int threads = atoi(argv[4]);
    const int per_thread = atoi(argv[5]);
    if (threads <= 0 || threads > MAX_THREADS || per_thread <= 0) { return 2; }
    z_owned_session_t a, b;
    z_owned_subscriber_t sub;
    int rc = open_with(&a, "listen/endpoints", argv[1], NULL);
    printf("listen=%d\n", rc);
    if (rc != Z_OK) { return 1; }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "wz/time_limit/**");
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
        put_one(z_loan(b), "wz/time_limit/warm");
        z_sleep_ms(20);
    }
    z_sleep_ms(200);
    int before = atomic_load(&got);
    printf("warm=%d\n", before > 0);

    pthread_t ids[MAX_THREADS];
    struct producer producers[MAX_THREADS];
    int started = 0;
    for (int t = 0; t < threads; t++) {
        producers[t].session = z_loan(b);
        producers[t].puts = per_thread;
        producers[t].refused = 0;
        if (pthread_create(&ids[t], NULL, produce, &producers[t]) != 0) { break; }
        started++;
    }
    int refused = 0;
    for (int t = 0; t < started; t++) {
        pthread_join(ids[t], NULL);
        refused += producers[t].refused;
    }
    const int total = started * per_thread;
    for (int i = 0; i < 500 && atomic_load(&got) - before < total; i++) { z_sleep_ms(20); }
    printf("burst threads=%d refused=%d delivered=%d\n", started, refused,
           atomic_load(&got) - before);

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
    std::fs::write(src_dir.join("wz_tx_time_limit.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_tx_time_limit",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!("the time limit probe does NOT link against wz's cdylib.\n{diag}")
    });

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let ref_libdir = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_tx_time_limit",
        &ref_dir,
        include,
        &src_dir,
        &ref_libdir,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the time limit probe does not link against the REAL libzenohc.so\n{diag}")
    });

    Arms {
        on_wz,
        wz_libdir,
        on_ref,
        ref_libdir,
        _dir: dir,
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

/// One run's reading: the batches of the dialling session's link that carried a put, and the
/// puts they carried in all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Burst {
    batches: usize,
    puts: usize,
}

/// Run `exe` with the key at `time_limit_ms`, its dialling session reaching the listener through
/// a tap, and read the batches that session wrote. A burst that did not cross whole fails here:
/// its batches would be a remnant's, not the burst's.
fn burst_through_a_tap(exe: &Path, libdir: &Path, time_limit_ms: u64) -> Burst {
    let reservation = PortReservation::pick();
    let listen = reservation.port();
    let (tap, recording) = tap_proxy(listen);
    let out = Command::new(exe)
        .arg(format!("tcp/127.0.0.1:{listen}"))
        .arg(format!("tcp/127.0.0.1:{tap}"))
        .arg(time_limit_ms.to_string())
        .arg(THREADS.to_string())
        .arg(PER_THREAD.to_string())
        .env("LD_LIBRARY_PATH", libdir)
        .output_bounded()
        .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
    drop(reservation);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let total = THREADS * PER_THREAD;
    // A warm-up sample still in flight when the burst began is counted with it, so the burst
    // crossed whole when at least its own samples arrived.
    let whole = format!("burst threads={THREADS} refused=0 delivered=");
    let delivered = stdout
        .lines()
        .find_map(|line| line.strip_prefix(whole.as_str()))
        .and_then(|count| count.trim().parse::<usize>().ok());
    assert!(
        out.status.success() && stdout.contains("done") && delivered >= Some(total),
        "the time limit probe {} did not deliver its burst whole with time_limit \
         {time_limit_ms}, exit {}:\n{stdout}\n{}",
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
    let burst = Burst {
        batches: carrying.len(),
        puts: carrying.iter().sum(),
    };
    assert!(
        burst.puts >= total,
        "with time_limit {time_limit_ms} the tap read {burst:?} for a burst of {total} puts, so \
         the batches read are not the burst's:\n{stdout}"
    );
    burst
}

/// Where a sequential test stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Between its bounds.
    Continue,
    /// H1 accepted: the longer threshold takes fewer batches.
    Ordered,
    /// H0 accepted: the threshold does not order the batch counts.
    Unordered,
}

/// Wald's sequential probability ratio test of the sign of a step, `p = 1/2` against `p = P1`, at
/// `ALPHA` and `BETA`, kept as a log-likelihood ratio in base 2 to 64 fractional bits.
#[derive(Debug, Clone, Default)]
struct SignTest {
    llr: i128,
    successes: usize,
    failures: usize,
    ties: usize,
    /// Every step's `(short threshold's batches, long threshold's batches)`, in order.
    steps: Vec<(usize, usize)>,
}

impl SignTest {
    /// `log2(P1 / (1/2))`, what a success adds.
    fn success_term() -> i128 {
        log2_ratio(2 * P1.0, P1.1)
    }

    /// `log2((1 - P1) / (1/2))`, what a failure adds.
    fn failure_term() -> i128 {
        log2_ratio(2 * (P1.1 - P1.0), P1.1)
    }

    /// `log2((1 - beta) / alpha)`, at or above which H1 is accepted.
    fn upper_bound() -> i128 {
        log2_ratio((BETA.1 - BETA.0) * ALPHA.1, BETA.1 * ALPHA.0)
    }

    /// `log2(beta / (1 - alpha))`, at or below which H0 is accepted.
    fn lower_bound() -> i128 {
        log2_ratio(BETA.0 * ALPHA.1, BETA.1 * (ALPHA.1 - ALPHA.0))
    }

    /// Take one step: the batch counts of a run at the short threshold and of one at the long.
    fn observe(&mut self, short: usize, long: usize) {
        self.steps.push((short, long));
        match short.cmp(&long) {
            std::cmp::Ordering::Greater => {
                self.successes += 1;
                self.llr += Self::success_term();
            }
            std::cmp::Ordering::Less => {
                self.failures += 1;
                self.llr += Self::failure_term();
            }
            std::cmp::Ordering::Equal => self.ties += 1,
        }
    }

    fn verdict(&self) -> Verdict {
        if self.llr >= Self::upper_bound() {
            Verdict::Ordered
        } else if self.llr <= Self::lower_bound() {
            Verdict::Unordered
        } else {
            Verdict::Continue
        }
    }

    /// The test's state and every step, for a failure message.
    fn report(&self) -> String {
        format!(
            "{:?} after {} step(s): {} success(es), {} failure(s), {} tie(s); log2 ratio {:.3} \
             against bounds {:.3} and {:.3}; (short, long) batches per step: {:?}",
            self.verdict(),
            self.steps.len(),
            self.successes,
            self.failures,
            self.ties,
            q64_bits(self.llr),
            q64_bits(Self::lower_bound()),
            q64_bits(Self::upper_bound()),
            self.steps
        )
    }
}

/// A Q64 logarithm in bits, for reading.
fn q64_bits(q64: i128) -> f64 {
    q64 as f64 / 2f64.powi(64)
}

/// Run the sign test on one library until it decides or reaches `MAX_STEPS`.
fn sign_test(exe: &Path, libdir: &Path) -> SignTest {
    let mut test = SignTest::default();
    for step in 0..MAX_STEPS {
        let (short, long) = if step % 2 == 0 {
            let short = burst_through_a_tap(exe, libdir, SHORT_MS);
            (short, burst_through_a_tap(exe, libdir, LONG_MS))
        } else {
            let long = burst_through_a_tap(exe, libdir, LONG_MS);
            (burst_through_a_tap(exe, libdir, SHORT_MS), long)
        };
        test.observe(short.batches, long.batches);
        eprintln!(
            "step {step}: {SHORT_MS} ms {short:?}, {LONG_MS} ms {long:?}; {:?}",
            test.verdict()
        );
        if test.verdict() != Verdict::Continue {
            break;
        }
    }
    test
}

// wz-proves: none -- a config key's effect on how many batches a burst takes, claimed for no atom
/// A session whose `transport/link/tx/queue/batching/time_limit` is longer writes a contended
/// burst in fewer batches, decided by the same sequential test on wz and libzenohc.
#[test]
#[ignore = "opens sessions and reads a zenoh-c oracle; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn a_longer_batching_time_limit_writes_a_contended_burst_in_fewer_batches_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let arms = build_both_arms(&include);

    let reference = sign_test(&arms.on_ref, &arms.ref_libdir);
    eprintln!("libzenohc: {}", reference.report());
    assert_eq!(
        reference.verdict(),
        Verdict::Ordered,
        "the REFERENCE does not show a longer time_limit writing the burst in fewer batches at \
         alpha = beta = 0.01, so this machine's libzenohc cannot adjudicate wz's: {}",
        reference.report()
    );

    let wz = sign_test(&arms.on_wz, &arms.wz_libdir);
    eprintln!("wz: {}", wz.report());
    assert_eq!(
        wz.verdict(),
        Verdict::Ordered,
        "libzenohc writes a contended burst in fewer batches under the longer time_limit and wz \
         does not show it at the same alpha and beta.\nwz: {}\nlibzenohc: {}",
        wz.report(),
        reference.report()
    );
}

// wz-proves: none -- the arithmetic of this file's sequential test, claimed for no atom
/// The sign test decides where its stated bounds say: eight successes in a row accept H1 and
/// seven do not, three failures in a row accept H0 and two do not, and a tie moves nothing.
#[test]
fn the_sign_test_decides_at_its_stated_bounds() {
    let mut test = SignTest::default();
    for _ in 0..7 {
        test.observe(10, 5);
    }
    assert_eq!(test.verdict(), Verdict::Continue, "{}", test.report());
    test.observe(7, 7);
    assert_eq!(test.verdict(), Verdict::Continue, "a tie moved the test");
    test.observe(10, 5);
    assert_eq!(test.verdict(), Verdict::Ordered, "{}", test.report());

    let mut test = SignTest::default();
    test.observe(5, 10);
    test.observe(5, 10);
    assert_eq!(test.verdict(), Verdict::Continue, "{}", test.report());
    test.observe(5, 10);
    assert_eq!(test.verdict(), Verdict::Unordered, "{}", test.report());

    // A failure costs what nearly three successes gain (2.32 bits against 0.85 each), so after
    // one, ten successes leave the ratio at 6.16 bits, under the 6.63 of `log2(99)`, and the
    // eleventh reaches 7.01.
    let mut test = SignTest::default();
    test.observe(5, 10);
    for _ in 0..10 {
        test.observe(10, 5);
    }
    assert_eq!(test.verdict(), Verdict::Continue, "{}", test.report());
    test.observe(10, 5);
    assert_eq!(test.verdict(), Verdict::Ordered, "{}", test.report());
}
