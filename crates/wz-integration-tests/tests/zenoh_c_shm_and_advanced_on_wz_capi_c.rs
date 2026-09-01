// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y543 — §5.27 `api-compat-c`: the SHARED-MEMORY and ADVANCED planes, RUN.
//!
//! ## Why these legs are separate from the other two files
//!
//! Every example driven here needs a zenoh-c built with BOTH
//! `Z_FEATURE_SHARED_MEMORY` and `Z_FEATURE_UNSTABLE_API`. The oracle
//! `install-zenoh-c.sh` provisions has neither, so against it these six programs
//! do not COMPILE and Layer C1cc could never have run them. `install-zenoh-c-shm.sh`
//! builds the other oracle and Layer C1ce measures against it — which is where
//! these legs belong.
//!
//! ## Linking is the weaker half of the claim, and these legs are the other half
//!
//! `scripts/lib/capi_c_coverage.py` reports how many of upstream's 29 examples
//! link. Linking is a real property — it is the linker, not wz, deciding — but a
//! symbol that exists and does nothing links exactly as well as one that works.
//! So each leg below compiles ONE upstream example ONCE and links it TWICE, at
//! wz's cdylib and at the real `libzenohc.so`, runs both against the SAME kind of
//! counterparty, and DIFFS the observable. An implementation that merely linked
//! would fail every one of them.
//!
//! Two counterparty shapes appear, and the choice is per leg rather than
//! uniform:
//!
//! - a fresh `wz-ap-demo --listen` per arm, when the C program PUBLISHES. The
//!   observable is the observer's `SUBSCRIBER FIRED` line, so the adjudicating
//!   party is a wz node reading what upstream's own program put on the wire.
//! - a real **zenoh-pico** CLI, when the C program SUBSCRIBES or QUERIES. pico
//!   shares no code with either side, so an agreement between the two arms is
//!   agreement on the WIRE rather than on a library.
//!
//! ## Two defects these legs found, both of which linked perfectly
//!
//! Written as history because both were invisible to the coverage number that
//! preceded them:
//!
//! 1. **The advanced subscriber received NOTHING on a `**` keyexpr.**
//!    `AdvancedSubscriber::declare_impl` derives `<base>/@adv/pub/**` for its
//!    heartbeat channel, which for a `**`-tailed base is the shape wz's own
//!    outbound gate refuses (it SIGABRTs a real zenoh-pico peer — R299 bug #3 /
//!    R300). That refusal came back through `?` and took the LIVE subscription
//!    with it, and `SharedSession::declare_advanced_subscriber` swallows a failed
//!    declare — so upstream's `z_advanced_sub.c`, whose own default key is
//!    `demo/example/**`, got no subscriber at all. The reference arm received
//!    every sample. Fixed by DEGRADING: the live subscription is the contract,
//!    the `@adv` recovery channels are an enhancement.
//!
//!    R311y544 FOLLOW-UP: the degradation was the right shape and the wrong
//!    diagnosis. The gate's premise — that `<base>/@adv/pub/**` SIGABRTs a real
//!    zenoh-pico — was never measured, and it is false: only a chunk of length
//!    ONE holds pico's `in_big_wild` window open, and `@adv` is four bytes. The
//!    gate is narrowed, so a `**`-tailed base now gets its heartbeat, history
//!    and recovery channels instead of a silently amputated recovery plane. See
//!    `layer3_keyexpr_canon` for the subprocess measurement and
//!    `apfull_advanced_pubsub_pico_interop` leg 3 for a live pico surviving the
//!    keyexpr on the wire.
//! 2. **A user subscription was handed zenoh's ADMIN namespace.** With (1) fixed,
//!    the wz arm received the 4 data samples AND 7 `@adv/pub/<zid>/<eid>/_`
//!    beacons; the reference arm received the 4 and none of the 7. A plain
//!    `z_sub.c` split the same way, so it was the keyexpr rule rather than an
//!    advanced-subscriber filter: wz was uniformly `@`-blind, where zenoh treats
//!    a chunk beginning with `@` as VERBATIM and unreachable by any wildcard
//!    (`commons/zenoh-keyexpr/src/key_expr/intersect/classical.rs:65-72`).
//!    `keyexpr_prefix`'s module note had carried that gap as "a re-openable
//!    stack-wide atom" for many rounds; this is the measurement that re-opened
//!    it.
//!
//! Both are asserted below, so neither can regress silently.
//!
//! ## The oracle is machine-local
//!
//! Absence is reported LOUDLY and the leg returns — a silent skip is a green
//! test that proved nothing. `WZ_C1CE_REQUIRE=1` makes Layer C1ce fail instead.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    compile_zenoh_c_example, graceful_terminate, read_captured, wait_for_substring,
    wait_for_tcp_accept_alive, wz_ap_demo_binary, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// How long a listener gets to bind and accept.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the exchange gets to reach the observing side's stdout.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a terminated child gets before it is killed outright.
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Which library an arm links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// wz's cdylib — the drop-in under test.
    Wz,
    /// The real `libzenohc.so` from the shared-memory oracle — the reference.
    Reference,
}

impl Arm {
    /// The arm's name, for messages.
    fn label(self) -> &'static str {
        match self {
            Arm::Wz => "wz",
            Arm::Reference => "reference",
        }
    }
}

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<(PathBuf, PathBuf, PathBuf)> {
    match zenoh_c_oracle() {
        Some(o) => Some(o),
        None => {
            eprintln!(
                "skip: the SHARED-MEMORY zenoh-c ORACLE is absent. These legs need a \
                 zenoh-c built with Z_FEATURE_SHARED_MEMORY and Z_FEATURE_UNSTABLE_API \
                 (`bash scripts/install-zenoh-c-shm.sh`, then WZ_ZENOH_C_PREFIX=\
                 target/zenoh-c-shm) AND a clone of its examples. Layer C1ce with \
                 WZ_C1CE_REQUIRE=1 fails instead of skipping."
            );
            None
        }
    }
}

/// Compile `example` for one arm, returning the binary and the libdir it needs
/// on `LD_LIBRARY_PATH`.
///
/// A link failure IS the drop-in claim being false on the wz arm, and an oracle
/// problem on the reference arm, so the two panics say different things.
fn arm_binary(
    example: &str,
    arm: Arm,
    dir: &Path,
    include: &Path,
    examples: &Path,
    libdir_ref: &Path,
) -> (PathBuf, PathBuf) {
    let (libdir, link) = match arm {
        Arm::Wz => (
            wz_capi_c_cdylib()
                .parent()
                .expect("cdylib has a parent")
                .to_path_buf(),
            "wz_capi_c",
        ),
        Arm::Reference => (libdir_ref.to_path_buf(), "zenohc"),
    };
    let exe = compile_zenoh_c_example(example, dir, include, examples, &libdir, link)
        .unwrap_or_else(|diag| match arm {
            Arm::Wz => panic!(
                "§5.27 api-compat-c: upstream {example}.c does NOT link against wz's \
                 C-ABI cdylib, so wz is not a binary drop-in for it.\n{diag}"
            ),
            Arm::Reference => panic!(
                "the REFERENCE arm did not build: upstream {example}.c against \
                 upstream's own libzenohc. That is an oracle problem, not a wz \
                 one.\n{diag}"
            ),
        });
    (exe, libdir)
}

/// Run a PUBLISHING example against a fresh `wz-ap-demo --listen` observer and
/// return what the observer logged.
///
/// A fresh observer per arm is not hygiene: `wz-ap-demo --listen` serves ONE
/// session, so a shared one makes the second arm's result depend on the first.
///
/// The examples driven this way (`z_pub_shm`, `z_advanced_pub`) never exit on
/// their own — they publish once a second until killed — so the observer's
/// capture is read WHILE they run and both children are terminated afterwards.
fn observe_publisher(
    program: &Path,
    libdir: &Path,
    key: &str,
    payload: &str,
    arm: Arm,
    settle: Duration,
) -> String {
    let label = arm.label();
    let stderr = tempfile::tempfile().expect("tempfile for observer stderr");
    let writer = stderr.try_clone().expect("dup observer stderr handle");
    let mut reader = stderr;

    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());
    let mut observer = ChildGuard::wrap(
        format!("wz-ap-demo --listen ({label})"),
        Command::new(wz_ap_demo_binary())
            .args(["--listen", &addr, "--key", "demo/example/**"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn the wz observer"),
    );
    drop(port);

    if let Err(capture) = wait_for_substring(&mut reader, "listening on", LISTEN_TIMEOUT) {
        panic!("the wz observer ({label}) never bound\n--- observer ---\n{capture}");
    }

    let mut prog_out = tempfile::tempfile().expect("program stdout capture");
    let prog_writer = prog_out.try_clone().expect("dup program stdout handle");
    let mut publisher = ChildGuard::wrap(
        format!("upstream publisher ({label})"),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(program)
            .args(["-e", &format!("tcp/{addr}"), "-k", key, "-p", payload])
            .env("LD_LIBRARY_PATH", libdir)
            .stdout(Stdio::from(prog_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(prog_writer))
            .spawn()
            .expect("spawn the upstream publisher"),
    );

    let observed = wait_for_substring(&mut reader, "SUBSCRIBER FIRED", EXCHANGE_TIMEOUT);
    // A settle window AFTER the first sample, and it is load-bearing rather than
    // padding: the callers assert the ABSENCE of `@adv` traffic, and the beacon
    // an advanced publisher emits arrives at its own cadence rather than with
    // the first data sample. Reading the capture the instant the first line lands
    // would let that assertion pass because nothing had had time to arrive —
    // which is exactly how the first draft of this file passed on the reference
    // arm while the wz arm was leaking.
    if observed.is_ok() {
        std::thread::sleep(settle);
    }
    let full = read_captured(&mut reader);
    graceful_terminate(publisher.child_mut(), TERMINATE_TIMEOUT);
    graceful_terminate(observer.child_mut(), TERMINATE_TIMEOUT);
    if observed.is_err() {
        panic!(
            "the wz observer never received a sample from the {label} arm\n\
             --- program stdout+stderr ---\n{}\n--- observer ---\n{full}",
            read_captured(&mut prog_out)
        );
    }
    full
}

/// The first `SUBSCRIBER FIRED` line's keyexpr and payload length.
fn fired(log: &str) -> Option<(String, usize)> {
    let line = log.lines().find(|l| l.contains("SUBSCRIBER FIRED"))?;
    let ke = line
        .split("keyexpr='")
        .nth(1)?
        .split('\'')
        .next()?
        .to_owned();
    let len = line
        .split("payload_len=")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((ke, len))
}

/// Every `SUBSCRIBER FIRED` keyexpr in the capture, in order.
fn fired_keyexprs(log: &str) -> Vec<String> {
    log.lines()
        .filter(|l| l.contains("SUBSCRIBER FIRED"))
        .filter_map(|l| Some(l.split("keyexpr='").nth(1)?.split('\'').next()?.to_owned()))
        .collect()
}

/// The example's own report lines — the `>> ` prefix upstream's handlers print —
/// with the frame chatter dropped, so two arms are compared on what they
/// RECEIVED rather than on their startup banners.
fn report_lines(log: &str) -> Vec<String> {
    log.lines()
        .filter(|l| l.trim_start().starts_with(">>"))
        .map(|l| l.trim().to_owned())
        .collect()
}

/// The `('<keyexpr>': ...)` and trailing `[<TAG>]` of one report line.
///
/// Two arms driven by a CONTINUOUS publisher cannot be compared line for line —
/// each one attaches at a different point in the publisher's counter, so
/// `[   0]` on one arm and `[   3]` on the other is a timing fact rather than a
/// disagreement. What must agree is the keyexpr and the tag the example computed
/// about the sample, so that is what this extracts.
fn keyexpr_and_tag(line: &str) -> Option<(String, String)> {
    let ke = line.split("('").nth(1)?.split('\'').next()?.to_owned();
    let tag = line.rsplit('[').next()?.split(']').next()?.to_owned();
    Some((ke, tag))
}

// R2245 removed `assert_arms_agree`, the two-arm stdout equality helper. Its
// caller count was measured, not assumed: leg 5 was the ONLY one, and leg 5 no
// longer has two comparable arms because upstream's own `z_get_shm.c` cannot
// run at the pin. Left in place it would be dead code, which `-D warnings`
// refuses and which reads as coverage that is not there. Leg 5's pin says what
// to restore, and this commit is where the four lines come back from.

/// LEG 1 — upstream's `z_pub_shm.c`, which allocates every payload out of an SHM
/// provider, publishes the same bytes on both arms.
///
/// The observable is the OBSERVER's, not the program's: `z_pub_shm.c` prints what
/// it intends to send, which is the same string either way and proves nothing.
/// What the wz node receives is the SHM chunk as it reached the wire — and the
/// length is the discriminator, because the example writes a short string into a
/// 1024-byte chunk and hands the WHOLE chunk to `z_bytes_from_shm_mut`. An
/// implementation that shortened the payload to the string would still print the
/// same line and still link.
// wz-proves: none -- the counterparty is a wz observer, so no FOREIGN
// implementation is on this wire. The claim it carries is the two-arm
// equivalence against the real libzenohc, which A4's vocabulary (pico /
// zenohd / zenoh-ext) has no class for.
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and needs the machine-local \
            SHARED-MEMORY zenoh-c oracle; run-ci Layer C1ce drives it"]
fn upstream_z_pub_shm_on_wz_capi_c_publishes_the_same_shm_chunk_on_both_arms() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled arms");
    let (on_wz, libdir_wz) = arm_binary(
        "z_pub_shm",
        Arm::Wz,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );
    let (on_ref, libdir_r) = arm_binary(
        "z_pub_shm",
        Arm::Reference,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );

    let ref_log = observe_publisher(
        &on_ref,
        &libdir_r,
        "demo/example/shm",
        "REF",
        Arm::Reference,
        Duration::from_millis(500),
    );
    let wz_log = observe_publisher(
        &on_wz,
        &libdir_wz,
        "demo/example/shm",
        "WZX",
        Arm::Wz,
        Duration::from_millis(500),
    );

    let (ref_ke, ref_len) = fired(&ref_log).expect("the reference arm's FIRED line parses");
    let (wz_ke, wz_len) = fired(&wz_log).expect("the wz arm's FIRED line parses");
    assert_eq!(
        wz_ke, ref_ke,
        "the two arms delivered DIFFERENT keyexprs from the same source"
    );
    assert_eq!(
        wz_len, ref_len,
        "the two arms delivered SHM payloads of different length ({wz_len} vs \
         {ref_len}). The example allocates a 1024-byte chunk and publishes all of \
         it, so a shorter payload means wz truncated the chunk to the string \
         written into it."
    );
}

/// LEG 2 — upstream's `z_advanced_pub.c` puts the same sample on both arms, and
/// the observer sees NO `@adv` traffic on either.
///
/// Two properties in one run, and the second is the one that regressed before it
/// was asserted. An advanced publisher declares its own `@adv/pub/<zid>/<eid>/_`
/// liveliness token and cache queryable, so the wire carries that namespace on
/// BOTH arms — the observer subscribes to `demo/example/**` and must not be
/// handed it, because a wildcard does not reach a chunk beginning with `@`.
/// Before R311y543 wz's matcher was `@`-blind and this observer logged the
/// beacons alongside the data.
// wz-proves: none -- as the leg above: the observer is a wz node, so the
// foreign half of this file's classifier does not apply to this test.
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and needs the machine-local \
            SHARED-MEMORY zenoh-c oracle; run-ci Layer C1ce drives it"]
fn upstream_z_advanced_pub_on_wz_capi_c_puts_the_same_sample_and_no_adv_leak() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled arms");
    let (on_wz, libdir_wz) = arm_binary(
        "z_advanced_pub",
        Arm::Wz,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );
    let (on_ref, libdir_r) = arm_binary(
        "z_advanced_pub",
        Arm::Reference,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );

    let ref_log = observe_publisher(
        &on_ref,
        &libdir_r,
        "demo/example/adv",
        "REF",
        Arm::Reference,
        Duration::from_secs(3),
    );
    let wz_log = observe_publisher(
        &on_wz,
        &libdir_wz,
        "demo/example/adv",
        "WZX",
        Arm::Wz,
        Duration::from_secs(3),
    );

    let (ref_ke, ref_len) = fired(&ref_log).expect("the reference arm's FIRED line parses");
    let (wz_ke, wz_len) = fired(&wz_log).expect("the wz arm's FIRED line parses");
    assert_eq!(wz_ke, ref_ke, "the two arms delivered DIFFERENT keyexprs");
    assert_eq!(
        wz_len, ref_len,
        "the two arms delivered payloads of different length ({wz_len} vs {ref_len}) \
         for equal-length inputs"
    );

    for (arm, log) in [("reference", &ref_log), ("wz", &wz_log)] {
        let leaked: Vec<String> = fired_keyexprs(log)
            .into_iter()
            .filter(|ke| ke.contains("/@"))
            .collect();
        assert!(
            leaked.is_empty(),
            "the {arm} arm's observer, subscribed to demo/example/**, was handed \
             zenoh's ADMIN namespace: {leaked:?}. A chunk beginning with `@` is \
             VERBATIM and no wildcard reaches it."
        );
    }
}

/// Drive a SUBSCRIBING example: the C program listens, a real zenoh-pico CLI
/// dials in and publishes, and the program's own stdout is the witness.
fn drive_subscriber(
    program: &Path,
    libdir: &Path,
    arm: Arm,
    pico_cli: &str,
    pico_args: impl Fn(&str) -> Vec<String>,
    settle: Duration,
) -> String {
    let label = arm.label();
    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    let mut sub = ChildGuard::wrap(
        format!("upstream subscriber ({label})"),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(program)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/capic/**"])
            .env("LD_LIBRARY_PATH", libdir)
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the upstream subscriber"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the {label} subscriber never accepted on {endpoint} — {why}; capture so \
             far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut driver = ChildGuard::wrap(
        format!("real zenoh-pico {pico_cli} ({label})"),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(zenoh_pico_cli_binary(pico_cli))
            .args(pico_args(&endpoint))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico driver"),
    );

    // The wait is on the CAPTURE, not on a sleep: the barrier is the first
    // report line the example prints.
    let captured = wait_for_substring(&mut sub_out, ">>", EXCHANGE_TIMEOUT);
    // A short settle AFTER the first line, so a leg asserting the ABSENCE of
    // extra lines gives them a chance to arrive rather than racing them.
    std::thread::sleep(settle);
    let full = read_captured(&mut sub_out);
    graceful_terminate(driver.child_mut(), TERMINATE_TIMEOUT);
    graceful_terminate(sub.child_mut(), TERMINATE_TIMEOUT);
    if captured.is_err() {
        panic!("the {label} subscriber printed no report line\n--- capture ---\n{full}");
    }
    full
}

/// LEG 3 — upstream's `z_sub_shm.c` reports the SAME buffer type on both arms.
///
/// This is the leg that measures the module note on [`wz_capi_c::shm`] rather
/// than restating it. The example asks `z_bytes_as_mut_loaned_shm` whether the
/// payload it received is backed by shared memory and prints `SHM (MUT)`,
/// `SHM (IMMUT)` or `RAW`. wz answers "not SHM" for every payload because it
/// negotiates no SHM transport — and against a publisher that negotiated none,
/// the REAL `libzenohc.so` answers the same. Both arms report `RAW`, which is
/// the equality this asserts; the claim would be a guess without it.
///
/// ## The driver is `z_pub`, not `z_put`, and that is not a preference
///
/// A one-shot `z_put` dials, publishes and exits, so it races the subscriber's
/// declaration reaching the freshly-dialed link — and the first draft of this
/// leg lost that race on the REFERENCE arm, which is the arm where a race says
/// nothing about wz. pico's `z_pub` publishes once a second until it is killed,
/// so the subscriber cannot miss it however late its declaration lands. That
/// removes the race by construction rather than by sleeping longer, and it is
/// why the comparison is over [`keyexpr_and_tag`] rather than raw lines: a
/// continuous publisher stamps a counter each arm joins at a different point of.
// wz-proves: api-compat-c pico->wz partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_pub CLI; needs the machine-local SHARED-MEMORY zenoh-c \
            oracle; run-ci Layer C1ce drives it"]
fn upstream_z_sub_shm_on_wz_capi_c_reports_the_same_buffer_type_on_both_arms() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled arms");
    let (on_wz, libdir_wz) = arm_binary(
        "z_sub_shm",
        Arm::Wz,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );
    let (on_ref, libdir_r) = arm_binary(
        "z_sub_shm",
        Arm::Reference,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );

    let payload = "PAYLOAD-FROM-REAL-PICO-ZPUB";
    let args = |endpoint: &str| {
        vec![
            "-e".to_string(),
            endpoint.to_string(),
            "-m".to_string(),
            "client".to_string(),
            "-k".to_string(),
            "demo/capic/shm".to_string(),
            "-v".to_string(),
            payload.to_string(),
        ]
    };
    let settle = Duration::from_millis(500);
    let ref_log = drive_subscriber(&on_ref, &libdir_r, Arm::Reference, "z_pub", args, settle);
    let wz_log = drive_subscriber(&on_wz, &libdir_wz, Arm::Wz, "z_pub", args, settle);

    let tags = |log: &str| -> Vec<(String, String)> {
        let mut seen: Vec<(String, String)> = report_lines(log)
            .iter()
            .filter_map(|l| keyexpr_and_tag(l))
            .collect();
        seen.dedup();
        seen
    };
    let wz_tags = tags(&wz_log);
    let ref_tags = tags(&ref_log);
    assert!(
        !wz_tags.is_empty(),
        "the wz arm reported nothing\n--- capture ---\n{wz_log}"
    );
    assert_eq!(
        wz_tags, ref_tags,
        "the two arms of the SAME compiled z_sub_shm.c disagree on what they \
         received. wz: {wz_tags:?}; the real libzenohc: {ref_tags:?}. The second \
         element of each pair is the BUFFER TYPE the example computed from \
         `z_bytes_as_mut_loaned_shm`."
    );
    assert!(
        report_lines(&wz_log).iter().any(|l| l.contains(payload)),
        "the wz arm reported no line carrying the payload the real pico published"
    );
}

/// LEG 4 — upstream's `z_advanced_sub.c` receives the SAME samples on both arms
/// from a REAL zenoh-pico advanced publisher, and neither is handed `@adv`.
///
/// The counterparty is foreign on purpose: pico's advanced publisher is a third
/// implementation of the `@adv` protocol, so an agreement between the two arms
/// here is agreement on the wire.
///
/// This leg is the one that found both R311y543 defects. Before the fix the wz
/// arm printed nothing at all (the heartbeat channel's derived keyexpr was
/// refused and took the live subscription down with it); with that fixed but the
/// matcher still `@`-blind it printed the 4 data samples plus 7 beacons where the
/// reference printed 4 and nothing else. Both halves are asserted, so neither can
/// come back quietly.
// wz-proves: api-compat-c pico->wz partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_advanced_pub CLI; needs the machine-local SHARED-MEMORY \
            zenoh-c oracle; run-ci Layer C1ce drives it"]
fn upstream_z_advanced_sub_on_wz_capi_c_receives_the_same_samples_from_real_pico() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled arms");
    let (on_wz, libdir_wz) = arm_binary(
        "z_advanced_sub",
        Arm::Wz,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );
    let (on_ref, libdir_r) = arm_binary(
        "z_advanced_sub",
        Arm::Reference,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );

    let payload = "ADV-FROM-REAL-PICO";
    let args = |endpoint: &str| {
        vec![
            "-e".to_string(),
            endpoint.to_string(),
            "-m".to_string(),
            "client".to_string(),
            "-k".to_string(),
            "demo/capic/adv".to_string(),
            "-v".to_string(),
            payload.to_string(),
        ]
    };
    // pico's advanced publisher puts once a second, so the settle window is
    // sized to admit the beacons that a regression would leak — an absence
    // assertion over a window too short to carry them would pass vacuously.
    let settle = Duration::from_secs(3);
    let ref_log = drive_subscriber(
        &on_ref,
        &libdir_r,
        Arm::Reference,
        "z_advanced_pub",
        args,
        settle,
    );
    let wz_log = drive_subscriber(&on_wz, &libdir_wz, Arm::Wz, "z_advanced_pub", args, settle);

    for (arm, log) in [("reference", &ref_log), ("wz", &wz_log)] {
        let data = report_lines(log)
            .into_iter()
            .filter(|l| l.contains(payload))
            .count();
        assert!(
            data > 0,
            "the {arm} arm's advanced subscriber received NO sample from the real \
             pico advanced publisher\n--- capture ---\n{log}"
        );
        let leaked: Vec<String> = report_lines(log)
            .into_iter()
            .filter(|l| l.contains("/@"))
            .collect();
        assert!(
            leaked.is_empty(),
            "the {arm} arm's advanced subscriber, on demo/capic/**, was handed \
             zenoh's ADMIN namespace: {leaked:?}"
        );
    }
}

/// LEG 5 — upstream's `z_get_shm.c` sends an SHM-allocated query payload that a
/// REAL zenoh-pico queryable reads and answers ON WZ'S ABI, and CANNOT RUN AT
/// ALL on upstream's own library at the pinned version.
///
/// ## The doubled witness this leg used to make, and why half of it is gone
///
/// It compared the two arms' stdout AND had a foreign queryable decode the
/// SHM-allocated payload. R2245 measured that the first half is unavailable at
/// zenoh-c 1.10.0: the REFERENCE arm aborts before it opens a session, so there
/// is nothing to compare against. The surviving half is not the weaker one —
/// the foreign queryable is still the party that decoded wz's SHM-allocated
/// bytes, and it shares no code with wz.
///
/// ## The upstream defect, derived from source and measured on the axis
///
/// `examples/z_get_shm.c` sizes its provider at exactly `strlen(payload)` and
/// then asks that same provider for exactly `strlen(payload)` bytes. Upstream's
/// own convention one file over is the opposite — `z_pub_shm.c` takes a 4096-byte
/// provider and allocates `total_size / 4` from it. And `z_get_shm.c` does not
/// check the result: `z_shm_provider_default_new` returns `Z_EINVAL` on failure
/// and leaves its out-parameter UNINITIALISED, so the next `z_loan` reads
/// uninitialised memory and the process dies on a signal rather than at the
/// `exit(-1)` every other call in that file gets.
///
/// The refusal is `commons/zenoh-shm/src/api/protocol_implementations/posix/posix_shm_provider_backend_talc.rs`
/// @ `Error initializing Talc backend!` — `talc.claim` over a span too small for
/// its own bookkeeping.
///
/// MEASURED on the payload-size axis, every size argv can carry, against the
/// same oracle this lane installs: 1 / 15 / 18 (the example's own shipped
/// default) / 1024 all abort in Talc init; 2048 / 4096 / 8192 / 16384 / 32768 /
/// 65536 / 100000 / 131071 all get past Talc and then fail the allocation. There
/// is no serviceable size. Upstream CI only BUILDS its examples, never runs
/// them, which is how this ships.
///
/// ## Why this is PINNED rather than skipped
///
/// A skip would report green over a claim nobody is checking. The reference arm
/// is therefore asserted to fail IN THE MEASURED WAY, so the day upstream fixes
/// it this test reds and whoever sees it restores the cross-arm comparison.
/// The control is intrinsic: same C source, same argv, same queryable, same
/// oracle installation — only the library differs, and the four sibling legs in
/// this file drive that same oracle green.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_queryable CLI; needs the machine-local SHARED-MEMORY \
            zenoh-c oracle; run-ci Layer C1ce drives it"]
fn upstream_z_get_shm_on_wz_capi_c_is_answered_by_real_pico_where_the_reference_arm_aborts() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled arms");
    let (on_wz, libdir_wz) = arm_binary(
        "z_get_shm",
        Arm::Wz,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );
    let (on_ref, libdir_r) = arm_binary(
        "z_get_shm",
        Arm::Reference,
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
    );

    let reply = "REPLY-FROM-REAL-PICO";
    let sent = "GET-SHM-PAYLOAD";

    // Returns the arm's EXIT STATUS as well as its output. R2245 moved the
    // success assertion out to the caller, because the two arms no longer make
    // the same claim: the wz arm must succeed, and the reference arm must fail
    // in one measured way. A closure that asserted success for both could only
    // express the claim that stopped being true.
    let run = |program: &Path, libdir: &Path, arm: Arm| -> (ExitStatus, String, String, String) {
        let label = arm.label();
        let reservation = PortReservation::pick();
        let port = reservation.port();
        let endpoint = format!("tcp/127.0.0.1:{port}");

        let mut qbl_out = tempfile::tempfile().expect("queryable stdout capture");
        let qbl_writer = qbl_out.try_clone().expect("dup queryable stdout handle");
        let mut queryable = ChildGuard::wrap(
            format!("real zenoh-pico z_queryable ({label})"),
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(zenoh_pico_cli_binary("z_queryable"))
                .args([
                    "-l",
                    &endpoint,
                    "-m",
                    "peer",
                    "-k",
                    "demo/capic/qshm",
                    "-v",
                    reply,
                ])
                .stdout(Stdio::from(qbl_writer))
                .stderr(Stdio::from(qbl_out.try_clone().expect("dup stderr handle")))
                .spawn()
                .expect("spawn the real zenoh-pico z_queryable"),
        );
        if let Err(why) = wait_for_tcp_accept_alive(queryable.child_mut(), port, LISTEN_TIMEOUT) {
            panic!(
                "the real zenoh-pico z_queryable never accepted on {endpoint} — {why}; \
                 capture so far:\n{}",
                read_captured(&mut qbl_out)
            );
        }
        drop(reservation);

        // `z_get_shm.c` terminates on its own once the reply channel closes, so
        // this arm is a plain wait rather than a capture race.
        let out = Command::new(program)
            .args([
                "-e",
                &format!("tcp/127.0.0.1:{port}"),
                "-m",
                "client",
                "-s",
                "demo/capic/qshm",
                "-p",
                sent,
            ])
            .env("LD_LIBRARY_PATH", libdir)
            .output()
            .unwrap_or_else(|e| panic!("failed to run the {label} z_get_shm: {e}"));
        let queryable_saw = read_captured(&mut qbl_out);
        graceful_terminate(queryable.child_mut(), TERMINATE_TIMEOUT);
        // BOTH streams, because the two arms fail in different places: the wz
        // arm would report on stdout, and the reference arm's Talc refusal is a
        // tracing line on stdout while the abort's panic lands on stderr.
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut both = stdout.clone();
        both.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status, stdout, both, queryable_saw)
    };

    let (ref_status, _ref_stdout, ref_both, _ref_queryable) =
        run(&on_ref, &libdir_r, Arm::Reference);
    let (wz_status, wz_stdout, wz_both, wz_queryable) = run(&on_wz, &libdir_wz, Arm::Wz);

    // ── THE PROOF: wz's ABI runs upstream's example end to end ──────────
    assert!(
        wz_status.success(),
        "upstream z_get_shm.c on wz's C ABI exited {:?}\n{wz_both}",
        wz_status.code(),
    );
    assert!(
        report_lines(&wz_stdout).iter().any(|l| l.contains(reply)),
        "the wz arm did not print the reply the real pico queryable sent: {wz_stdout:?}"
    );
    assert!(
        wz_queryable.contains(sent),
        "the real pico queryable did not read the SHM-allocated query payload \
         from the wz arm — it saw:\n{wz_queryable}"
    );

    // ── THE PIN: upstream's own library cannot run its own example ──────
    //
    // Asserted in BOTH halves on purpose. A status check alone would be
    // satisfied by any failure at all — a missing library, a busy port — and
    // this leg is claiming something much narrower. The marker is what makes it
    // that claim, and `arm_binary` above has already established the binary
    // built and linked, so "it never ran" cannot satisfy either half.
    assert!(
        !ref_status.success(),
        "the REFERENCE z_get_shm SUCCEEDED. Upstream has repaired \
         examples/z_get_shm.c (or the pin moved): restore the cross-arm stdout \
         comparison this leg carried before R2245, and delete this pin."
    );
    assert!(
        ref_both.contains("Error initializing Talc backend"),
        "the REFERENCE z_get_shm failed, but NOT in the way R2245 measured \
         (exit {:?}). This pin is about one upstream defect — a provider sized \
         at strlen(payload) that Talc will not claim — so a different failure \
         is a different problem and must be attributed, not absorbed here.\n\
         {ref_both}",
        ref_status.code(),
    );
}
