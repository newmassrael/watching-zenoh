// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y543 — §5.27 `api-compat-c`: the SHARED-MEMORY and ADVANCED planes, RUN.
//!
//! ## Why these legs are separate from the other two files
//!
//! The examples driven here split by what they need from a HEADER, and R2281
//! measured the split with `cc -fsyntax-only` rather than restating it: the
//! three `*_shm` legs need `Z_FEATURE_SHARED_MEMORY` and run on Layer C1cc,
//! whose oracle is the published archive — `unstable-shm`, both axes, as R2278
//! measured; the two `z_advanced_*` legs need only `Z_FEATURE_UNSTABLE_API` and
//! run on Layer C1ce against the `unstable` arm.
//!
//! This header used to say `install-zenoh-c.sh`'s oracle has NEITHER axis, so
//! C1cc could never host any of them. That reading was R311y540's and it was
//! wrong about the archive; the split above is what replaces it.
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
    zenoh_pico_cli_binary, zenoh_shm_example_binary, ChildGuard, PortReservation,
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
                "skip: no zenoh-c ORACLE is installed. The `*_shm` legs need a build \
                 carrying Z_FEATURE_SHARED_MEMORY (`bash scripts/install-zenoh-c.sh`, \
                 the published archive Layer C1cc runs against) and the z_advanced_* \
                 legs need Z_FEATURE_UNSTABLE_API (`bash \
                 scripts/install-zenoh-c-arm.sh unstable`, then \
                 WZ_ZENOH_C_PREFIX=target/zenoh-c-unstable, which is Layer C1ce's). \
                 A clone of the examples is needed either way. Layers C1cc / C1ce with \
                 WZ_C1CC_REQUIRE=1 / WZ_C1CE_REQUIRE=1 fail instead of skipping."
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
    drive_subscriber_against(
        program,
        libdir,
        arm,
        "demo/capic/**",
        &zenoh_pico_cli_binary(pico_cli),
        &format!("real zenoh-pico {pico_cli}"),
        pico_args,
        settle,
    )
}

/// [`drive_subscriber`] with the counterparty and the subscriber's key chosen: the C
/// program listens on `key`, and `driver` (named `driver_label` in messages) dials it
/// with `driver_args(endpoint)` and publishes. The program's own stdout is the
/// witness.
#[allow(clippy::too_many_arguments)]
fn drive_subscriber_against(
    program: &Path,
    libdir: &Path,
    arm: Arm,
    key: &str,
    driver: &Path,
    driver_label: &str,
    driver_args: impl Fn(&str) -> Vec<String>,
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
            .args(["-l", &endpoint, "-m", "peer", "-k", key])
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

    // The driver's own output is kept, so a subscriber that is handed nothing can
    // say what the publisher did: a driver that could not negotiate, or whose
    // session ended, reads here and nowhere else.
    let mut driver_out = tempfile::tempfile().expect("driver output capture");
    let driver_writer = driver_out.try_clone().expect("dup driver output handle");
    let mut driver = ChildGuard::wrap(
        format!("{driver_label} ({label})"),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(driver)
            .args(driver_args(&endpoint))
            // Read only by a driver that is a zenoh Rust program; a pico CLI has no
            // log filter to read.
            .env(
                "RUST_LOG",
                "zenoh=info,zenoh_shm=debug,zenoh_transport=debug",
            )
            .stdout(Stdio::from(driver_writer))
            .stderr(Stdio::from(
                driver_out.try_clone().expect("dup driver stderr handle"),
            ))
            .spawn()
            .expect("spawn the driver"),
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
        let driver_log = read_captured(&mut driver_out);
        panic!(
            "the {label} subscriber printed no report line\n--- capture ---\n{full}\n--- \
             {driver_label} ---\n{driver_log}"
        );
    }
    full
}

/// LEG 3 — upstream's `z_sub_shm.c` reports the SAME buffer type on both arms.
///
/// This is the leg that measures the module note on [`wz_capi_c::shm`] rather
/// than restating it. The example asks `z_bytes_as_mut_loaned_shm` whether the
/// payload it received is backed by shared memory and prints `SHM (MUT)`,
/// `SHM (IMMUT)` or `RAW`. Against a publisher that negotiated no shared memory
/// every payload arrives as bytes, and wz answers "not SHM" for it — as the REAL
/// `libzenohc.so` does. (R3052: wz's C ABI session does offer shared memory now, so
/// that answer comes from what the publisher sent and not from an offer wz never
/// made; leg 3b below is the one that sends it a shared-memory payload.) Both
/// arms report `RAW`, which is
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

/// LEG 3b — upstream's `z_sub_shm.c` reports the SAME buffer type on both arms for a
/// payload a SHARED-MEMORY publisher put on the wire as shared memory.
///
/// Leg 3 above cannot tell the arms apart on this question, because its publisher is
/// a zenoh-pico CLI, which negotiates no shared memory and so sends every payload as
/// bytes: both arms print `RAW` and agree for a reason that has nothing to do with
/// whether wz can receive a buffer. The counterparty here is upstream's own Rust
/// `z_pub_shm`, which publishes each payload as a chunk of its own provider and, to a
/// peer that negotiated shared memory, as a descriptor of it. The reference arm
/// negotiates and reports a shared-memory buffer type. An arm whose session offers no
/// shared memory is sent the same payload as bytes and reports `RAW`, which is how
/// this leg reads when wz's C ABI session declines the offer.
// wz-proves: api-compat-c zenoh->wz partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns upstream's own \
            z_pub_shm; needs the machine-local SHARED-MEMORY zenoh-c oracle and the \
            shared-memory zenohd build; run-ci Layer C1cc drives it"]
fn upstream_z_sub_shm_on_wz_capi_c_reports_the_same_buffer_type_for_a_shared_memory_publisher() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let Some(z_pub_shm) = zenoh_shm_example_binary("z_pub_shm") else {
        eprintln!(
            "skip: no z_pub_shm at target/zenohd-shm (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
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

    let args = |endpoint: &str| {
        vec![
            "-m".to_string(),
            "peer".to_string(),
            "-e".to_string(),
            endpoint.to_string(),
            "--no-multicast-scouting".to_string(),
            "--enable-shm".to_string(),
        ]
    };
    let settle = Duration::from_millis(1500);
    let drive = |program: &Path, libdir: &Path, arm: Arm| {
        drive_subscriber_against(
            program,
            libdir,
            arm,
            "demo/example/**",
            &z_pub_shm,
            "upstream z_pub_shm",
            args,
            settle,
        )
    };
    let ref_log = drive(&on_ref, &libdir_r, Arm::Reference);
    let wz_log = drive(&on_wz, &libdir_wz, Arm::Wz);

    let tags = |log: &str| -> Vec<(String, String)> {
        let mut seen: Vec<(String, String)> = report_lines(log)
            .iter()
            .filter_map(|l| keyexpr_and_tag(l))
            .collect();
        seen.dedup();
        seen
    };
    let (wz_tags, ref_tags) = (tags(&wz_log), tags(&ref_log));
    assert!(
        !ref_tags.is_empty(),
        "the reference arm reported nothing, so the publisher did not reach it and this leg \
         measured nothing\n--- reference ---\n{ref_log}"
    );
    assert!(
        ref_tags.iter().any(|(_, tag)| tag.starts_with("SHM")),
        "the reference arm did not report a shared-memory buffer: {ref_tags:?}, so the \
         publisher was not offered shared memory and the comparison below says nothing about \
         it\n--- reference ---\n{ref_log}"
    );
    assert_eq!(
        wz_tags, ref_tags,
        "the two arms of the SAME compiled z_sub_shm.c disagree on the buffer type of what a \
         shared-memory publisher sent. wz: {wz_tags:?}; the real libzenohc: {ref_tags:?}.\n--- wz \
         ---\n{wz_log}\n--- reference ---\n{ref_log}"
    );
}

/// Run a PUBLISHING example against upstream's own `z_sub_shm` and return what that
/// subscriber printed.
///
/// The subscriber is the Rust example that labels every sample it receives `SHM (MUT)`,
/// `SHM (IMMUT)` or `RAW` (`examples/examples/z_sub_shm.rs` @
/// `Ok(_shm_mut) => "SHM (MUT)",`), listening as a peer that offers shared memory. It is a third implementation of the protocol that shares no
/// code with either arm, which is why what it prints is the witness: a publisher that
/// only SAYS it sent a chunk and sent the bytes reads `RAW` here, and `wz-ap-demo`, the
/// observer LEG 1 uses, cannot tell the two apart because it negotiates no shared memory.
///
/// The publisher dials the subscriber, and the capture is read while both run, because
/// `z_pub_shm.c` publishes once a second until killed.
fn observe_with_z_sub_shm(
    z_sub_shm: &Path,
    program: &Path,
    libdir: &Path,
    arm: Arm,
    publisher_args: impl Fn(&str) -> Vec<String>,
    settle: Duration,
) -> String {
    let label = arm.label();
    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let mut sub_out = tempfile::tempfile().expect("subscriber output capture");
    let sub_writer = sub_out.try_clone().expect("dup subscriber output handle");
    let mut subscriber = ChildGuard::wrap(
        format!("upstream z_sub_shm ({label})"),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_sub_shm)
            .args([
                "-m",
                "peer",
                "-l",
                &endpoint,
                "-k",
                "demo/example/**",
                "--no-multicast-scouting",
                "--enable-shm",
            ])
            .env(
                "RUST_LOG",
                "zenoh=info,zenoh_shm=debug,zenoh_transport=debug",
            )
            .stdout(Stdio::from(sub_writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn upstream's z_sub_shm"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(subscriber.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "upstream's z_sub_shm ({label}) never accepted on {endpoint} -- {why}; capture so \
             far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut prog_out = tempfile::tempfile().expect("publisher output capture");
    let prog_writer = prog_out.try_clone().expect("dup publisher output handle");
    let mut publisher = ChildGuard::wrap(
        format!("upstream z_pub_shm.c ({label})"),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(program)
            .args(publisher_args(&endpoint))
            .env("LD_LIBRARY_PATH", libdir)
            .stdout(Stdio::from(prog_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(prog_writer))
            .spawn()
            .expect("spawn the publisher"),
    );

    let observed = wait_for_substring(&mut sub_out, "Received", EXCHANGE_TIMEOUT);
    // A settle window after the first sample, so the tags of a few more are read and a
    // sample that changed its buffer type between the first and the third would show.
    if observed.is_ok() {
        std::thread::sleep(settle);
    }
    let full = read_captured(&mut sub_out);
    graceful_terminate(publisher.child_mut(), TERMINATE_TIMEOUT);
    graceful_terminate(subscriber.child_mut(), TERMINATE_TIMEOUT);
    if observed.is_err() {
        panic!(
            "upstream's z_sub_shm never received a sample from the {label} arm\n\
             --- publisher stdout+stderr ---\n{}\n--- subscriber ---\n{full}",
            read_captured(&mut prog_out)
        );
    }
    full
}

/// The `(keyexpr, buffer type)` of every sample upstream's `z_sub_shm` printed, run-length
/// deduplicated so two arms that attached at different points of a continuous publisher
/// compare on what they received and not on how many.
fn received_tags(log: &str) -> Vec<(String, String)> {
    let mut seen: Vec<(String, String)> = log
        .lines()
        .filter(|l| l.contains("Received PUT ('"))
        .filter_map(keyexpr_and_tag)
        .collect();
    seen.dedup();
    seen
}

/// LEG 7 -- upstream's `z_pub_shm.c`, UNMODIFIED, puts its chunk on the wire as SHARED
/// MEMORY on wz's ABI, as on the real library: upstream's own `z_sub_shm` prints every
/// sample it receives from it as a shared-memory buffer on both arms.
///
/// This is the leg the sending half is for. Until R3059 `z_bytes_from_shm` copied the
/// chunk and every put was bytes, so the same example reached this subscriber as `RAW`
/// from wz and as `SHM` from the real library; LEG 1 could not see it because its
/// observer negotiates no shared memory. The reference arm is the control: if it reports
/// anything but a shared-memory buffer, the machine's oracle or the subscriber's offer is
/// not what this leg assumes, and the comparison says nothing.
///
/// What is compared is the key and the buffer type, not the payload line: the publisher
/// numbers its payloads, and two arms attach at different counts.
// wz-proves: api-compat-c wz->zenoh partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns upstream's own \
            z_sub_shm; needs the machine-local SHARED-MEMORY zenoh-c oracle and the \
            shared-memory zenohd build; run-ci Layer C1cc drives it"]
fn upstream_z_pub_shm_on_wz_capi_c_reaches_a_real_z_sub_shm_as_shared_memory() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let Some(z_sub_shm) = zenoh_shm_example_binary("z_sub_shm") else {
        eprintln!(
            "skip: no z_sub_shm at target/zenohd-shm (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
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

    let key = "demo/example/zenoh-c-pub-shm";
    let payload = "SHM-FROM-C";
    let settle = Duration::from_millis(2500);
    let args = |endpoint: &str| {
        vec![
            "-e".to_string(),
            endpoint.to_string(),
            "-k".to_string(),
            key.to_string(),
            "-p".to_string(),
            payload.to_string(),
            "--no-multicast-scouting".to_string(),
        ]
    };
    let ref_log =
        observe_with_z_sub_shm(&z_sub_shm, &on_ref, &libdir_r, Arm::Reference, args, settle);
    let wz_log = observe_with_z_sub_shm(&z_sub_shm, &on_wz, &libdir_wz, Arm::Wz, args, settle);

    let (wz_tags, ref_tags) = (received_tags(&wz_log), received_tags(&ref_log));
    assert!(
        !ref_tags.is_empty() && ref_tags.iter().all(|(_, tag)| tag.starts_with("SHM")),
        "the reference arm did not reach upstream's z_sub_shm as shared memory: {ref_tags:?}, \
         so the comparison below says nothing about it\n--- reference ---\n{ref_log}"
    );
    assert!(
        !wz_tags.is_empty(),
        "the wz arm reached upstream's z_sub_shm with nothing it could tag\n--- wz ---\n{wz_log}"
    );
    assert_eq!(
        wz_tags, ref_tags,
        "the two arms of the SAME compiled z_pub_shm.c reached upstream's z_sub_shm as \
         different buffer types. wz: {wz_tags:?}; the real libzenohc: {ref_tags:?}.\n--- wz \
         ---\n{wz_log}\n--- reference ---\n{ref_log}"
    );
    assert!(
        wz_log.contains(payload),
        "upstream's z_sub_shm printed nothing carrying the payload the wz arm sent\n{wz_log}"
    );
}

/// A publisher that puts a chunk of shared memory on a DECLARED keyexpr: `z_pub_shm.c`
/// with the publisher replaced by `z_declare_keyexpr` and `z_put`, which is the one
/// combination of the two choices (a key the wire names by id, a payload that lives in
/// shared memory) no upstream example makes. It is ours, and the same source is compiled
/// for both arms. Arguments: the endpoint to dial and the key to declare.
const DECLARED_KEY_SHM_PUBLISHER: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "zenoh.h"

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3) { return 2; }
    z_owned_config_t config;
    z_config_default(&config);
    char connect[512];
    snprintf(connect, sizeof connect, "[\"%s\"]", argv[1]);
    if (zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, connect) < 0) { return 3; }
    if (zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false") < 0) { return 3; }
    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) { printf("open failed\n"); return 4; }
    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, argv[2]) < 0) { return 5; }
    z_owned_keyexpr_t declared;
    if (z_declare_keyexpr(z_loan(s), &declared, z_loan(ke)) < 0) { printf("declare failed\n"); return 5; }
    z_owned_shm_provider_t provider;
    if (z_shm_provider_default_new(&provider, 4096) != Z_OK) { printf("provider failed\n"); return 6; }
    for (int idx = 0; idx < 1000; ++idx) {
        z_sleep_s(1);
        z_buf_layout_alloc_result_t alloc;
        z_shm_provider_alloc_gc_defrag_blocking(&alloc, z_loan(provider), 1024);
        if (alloc.status != ZC_BUF_LAYOUT_ALLOC_STATUS_OK) { printf("alloc failed\n"); return 7; }
        uint8_t *buf = z_shm_mut_data_mut(z_loan_mut(alloc.buf));
        snprintf((char *)buf, 1024, "[%4d] declared-key-shm", idx);
        z_owned_bytes_t payload;
        z_bytes_from_shm_mut(&payload, z_move(alloc.buf));
        if (z_put(z_loan(s), z_loan(declared), z_move(payload), NULL) < 0) { printf("put failed\n"); return 8; }
        printf("put %d\n", idx);
    }
    return 0;
}
"#;

/// LEG 8 -- a chunk put on a DECLARED keyexpr reaches upstream's `z_sub_shm` as shared
/// memory on both arms. LEG 7 is the literal key; this is the id the wire names instead,
/// which is a different message (the Push carries `(id, suffix)` and not the literal) built
/// by a different function, and a program that declares its keys and allocates its
/// payloads from a provider is not unusual.
///
/// The subscriber resolves the id from the declaration the publisher sent first, so the
/// key it prints is the declared literal on both arms, and a publish that named the key
/// wrongly, or sent the bytes, would differ from the reference in the tag or the key.
// wz-proves: api-compat-c wz->zenoh partial
#[test]
#[ignore = "compiles a C program with cc and spawns upstream's own z_sub_shm; needs the \
            machine-local SHARED-MEMORY zenoh-c oracle and the shared-memory zenohd build; \
            run-ci Layer C1cc drives it"]
fn a_chunk_put_on_a_declared_keyexpr_reaches_a_real_z_sub_shm_as_shared_memory_on_wz_capi_c() {
    let Some((include, libdir_ref, _examples)) = oracle_or_note() else {
        return;
    };
    let Some(z_sub_shm) = zenoh_shm_example_binary("z_sub_shm") else {
        eprintln!(
            "skip: no z_sub_shm at target/zenohd-shm (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled arms");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("source dir");
    std::fs::write(
        src_dir.join("declared_key_shm_pub.c"),
        DECLARED_KEY_SHM_PUBLISHER,
    )
    .expect("write the publisher source");
    let (on_wz, libdir_wz) = arm_binary(
        "declared_key_shm_pub",
        Arm::Wz,
        dir.path(),
        &include,
        &src_dir,
        &libdir_ref,
    );
    let (on_ref, libdir_r) = arm_binary(
        "declared_key_shm_pub",
        Arm::Reference,
        dir.path(),
        &include,
        &src_dir,
        &libdir_ref,
    );

    let key = "demo/example/declared-shm";
    let settle = Duration::from_millis(2500);
    let args = |endpoint: &str| vec![endpoint.to_string(), key.to_string()];
    let ref_log =
        observe_with_z_sub_shm(&z_sub_shm, &on_ref, &libdir_r, Arm::Reference, args, settle);
    let wz_log = observe_with_z_sub_shm(&z_sub_shm, &on_wz, &libdir_wz, Arm::Wz, args, settle);

    let (wz_tags, ref_tags) = (received_tags(&wz_log), received_tags(&ref_log));
    assert!(
        !ref_tags.is_empty() && ref_tags.iter().all(|(_, tag)| tag.starts_with("SHM")),
        "the reference arm did not reach upstream's z_sub_shm as shared memory on a declared \
         key: {ref_tags:?}, so the comparison below says nothing about it\n--- reference \
         ---\n{ref_log}"
    );
    assert_eq!(
        wz_tags, ref_tags,
        "the two arms of the SAME program put a chunk on a declared key and reached upstream's \
         z_sub_shm as different samples. wz: {wz_tags:?}; the real libzenohc: {ref_tags:?}.\n--- \
         wz ---\n{wz_log}\n--- reference ---\n{ref_log}"
    );
    assert!(
        wz_tags.iter().all(|(ke, _)| ke == key),
        "the key upstream's z_sub_shm resolved from wz's declaration is not the declared \
         one: {wz_tags:?}"
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

/// What `z_get_shm`-shaped programs ask of the real pico queryable in LEG 5 and
/// LEG 6, and what it answers.
const GET_SHM_REPLY: &str = "REPLY-FROM-REAL-PICO";
const GET_SHM_SENT: &str = "GET-SHM-PAYLOAD";

/// One run of a `z_get_shm`-shaped program against a fresh real zenoh-pico
/// `z_queryable`, returning the arm's EXIT STATUS, its stdout, stdout and stderr
/// together, and what the queryable printed.
///
/// R2245 kept the success assertion out of this function, because the two arms
/// did not make the same claim: a helper that asserted success for both could
/// only express the claim that stopped being true. LEG 5 expects a refusal and
/// LEG 6 expects a reply, from the same code.
fn run_get_shm_against_pico(
    program: &Path,
    libdir: &Path,
    arm: Arm,
) -> (ExitStatus, String, String, String) {
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
                GET_SHM_REPLY,
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
            GET_SHM_SENT,
        ])
        .env("LD_LIBRARY_PATH", libdir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run the {label} z_get_shm: {e}"));
    let queryable_saw = read_captured(&mut qbl_out);
    graceful_terminate(queryable.child_mut(), TERMINATE_TIMEOUT);
    // BOTH streams, because the two arms fail in different places: the wz arm
    // reports on stdout, and the reference arm's Talc refusal is a tracing line
    // on stdout while the abort's panic lands on stderr.
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut both = stdout.clone();
    both.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status, stdout, both, queryable_saw)
}

/// LEG 5 — upstream's `z_get_shm.c` CANNOT RUN on upstream's own library at the
/// pinned version, and, since R3058, cannot run on wz's ABI either.
///
/// ## What this leg used to claim, and why it no longer can
///
/// Until R3058 the wz arm ran this example to the end and a real zenoh-pico
/// queryable decoded its payload: wz's allocator served a pool sized exactly at
/// the payload, which upstream's cannot, so wz succeeded where the reference
/// aborted. That was a divergence in wz's favour and a divergence all the same.
/// The C ABI's provider is now the runtime's, carved by upstream's own
/// allocator, and it refuses the pool as the real library does. The witness
/// that a real pico queryable reads an SHM-allocated query payload moved to LEG
/// 6, which runs a program both libraries CAN run.
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
/// it this test reds and whoever sees it runs the example on both arms. The wz
/// arm is asserted to fail at the allocation the example checks, so a wz pool
/// more permissive than upstream's reds here too. The control is intrinsic:
/// same C source, same argv, same queryable, same oracle installation — only
/// the library differs, and the sibling legs in this file drive that same
/// oracle green.
// wz-proves: none -- a pin: it asserts that an upstream defect is still there and that wz refuses the same pool, and no atom's cross-implementation proof rests on a refusal (LEG 6 carries the pico witness)
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_queryable CLI; needs the machine-local SHARED-MEMORY \
            zenoh-c oracle; run-ci Layer C1cc drives it"]
fn upstream_z_get_shm_on_wz_capi_c_runs_on_neither_arm_at_the_pinned_version() {
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

    let (ref_status, _ref_stdout, ref_both, ref_queryable) =
        run_get_shm_against_pico(&on_ref, &libdir_r, Arm::Reference);
    let (wz_status, _wz_stdout, wz_both, wz_queryable) =
        run_get_shm_against_pico(&on_wz, &libdir_wz, Arm::Wz);

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
         examples/z_get_shm.c (or the pin moved): run the example itself on both \
         arms and diff them as LEG 6 does its derived program, and delete this pin."
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

    // ── THE WZ HALF: wz refuses where the library refuses ───────────────
    //
    // R3058. The wz arm used to RUN this example to the end, because its
    // allocator served a pool sized exactly at the payload. A pool the real
    // library cannot make is not one wz may serve: a program that works on wz
    // and aborts on zenoh-c is not behaving as a drop-in. The refusal is the
    // same, the MANNER is not and is not meant to be: upstream's out-parameter
    // is left uninitialised, so its next call reads garbage and dies on a
    // signal, while wz leaves a gravestone, which the example's own allocation
    // check then reports (named divergence, `z_shm_provider_default_new`).
    assert!(
        !wz_status.success(),
        "wz's C ABI RAN upstream's z_get_shm.c to the end, which the real \
         library cannot. Its provider accepted a pool sized exactly at the \
         payload, so it is more permissive than upstream's Talc pool again.\n\
         {wz_both}"
    );
    assert!(
        wz_both.contains("Unexpected failure during SHM buffer allocation"),
        "wz's z_get_shm failed, but not at the allocation the example checks \
         (exit {:?}), so the refusal is not the pool's:\n{wz_both}",
        wz_status.code(),
    );
    for (arm, saw) in [("reference", &ref_queryable), ("wz", &wz_queryable)] {
        assert!(
            !saw.contains(GET_SHM_SENT),
            "the {arm} arm got as far as sending the query, so it did not fail \
             at the provider this leg pins:\n{saw}"
        );
    }
}

/// The one call LEG 6 changes in upstream's `z_get_shm.c`, and what it becomes.
const UPSTREAM_PROVIDER_CALL: &str = "z_shm_provider_default_new(&provider, value_len);";
/// 4096 is `z_pub_shm.c`'s own provider size, upstream's convention one file over.
const SIZED_PROVIDER_CALL: &str = "z_shm_provider_default_new(&provider, 4096);";

/// LEG 6 — a query payload ALLOCATED IN SHARED MEMORY reaches a REAL zenoh-pico
/// queryable, which answers it, identically on wz's ABI and on the real library.
///
/// ## Why this is a derived program and not upstream's example
///
/// LEG 5 pins that `z_get_shm.c` cannot run on either library, because it sizes
/// its provider at exactly the payload. What that example was FOR is a
/// different claim: that a payload allocated out of a provider and handed to
/// `z_get` is delivered. This leg keeps every byte of upstream's source except
/// the one call that sizes the pool, which becomes 4096, the size `z_pub_shm.c`
/// uses. The replacement is asserted to happen exactly once, so an upstream that
/// rewrites the file fails here by name instead of silently testing a different
/// program; and the SAME derived source is compiled for both arms.
///
/// ## What it witnesses, and what it does not
///
/// The foreign queryable shares no code with either library and is the party
/// that decodes the payload, so its seeing the bytes is agreement on the wire.
/// It does not witness that the payload travelled as a SHARED-MEMORY reference:
/// `z_bytes_from_shm` copies on wz today, and a pico peer has no segment to map
/// either way, so the bytes cross as bytes on both arms. That half is the send
/// plane's to witness against a peer that can map the segment.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_queryable CLI; needs the machine-local SHARED-MEMORY \
            zenoh-c oracle; run-ci Layer C1cc drives it"]
fn a_shm_allocated_query_payload_reaches_a_real_pico_queryable_identically_on_wz_capi_c_and_libzenohc(
) {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the derived program");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("derived source dir");
    let upstream =
        std::fs::read_to_string(examples.join("z_get_shm.c")).expect("upstream's z_get_shm.c");
    assert_eq!(
        upstream.matches(UPSTREAM_PROVIDER_CALL).count(),
        1,
        "upstream's z_get_shm.c no longer sizes its provider with `{UPSTREAM_PROVIDER_CALL}` \
         exactly once, so the derivation this leg rests on has changed: read the file and \
         decide whether LEG 5 and this leg still say what upstream does."
    );
    std::fs::write(
        src_dir.join("z_get_shm_sized.c"),
        upstream.replace(UPSTREAM_PROVIDER_CALL, SIZED_PROVIDER_CALL),
    )
    .expect("write the derived source");
    // The example includes its argument parser from its own directory, and the
    // compile helper uses ONE directory for both the source and the includes.
    std::fs::copy(examples.join("parse_args.h"), src_dir.join("parse_args.h"))
        .expect("copy upstream's parse_args.h");

    let (on_wz, libdir_wz) = arm_binary(
        "z_get_shm_sized",
        Arm::Wz,
        dir.path(),
        &include,
        &src_dir,
        &libdir_ref,
    );
    let (on_ref, libdir_r) = arm_binary(
        "z_get_shm_sized",
        Arm::Reference,
        dir.path(),
        &include,
        &src_dir,
        &libdir_ref,
    );

    let (ref_status, ref_stdout, ref_both, ref_queryable) =
        run_get_shm_against_pico(&on_ref, &libdir_r, Arm::Reference);
    let (wz_status, wz_stdout, wz_both, wz_queryable) =
        run_get_shm_against_pico(&on_wz, &libdir_wz, Arm::Wz);

    // The ORACLE first: two identical failures diff clean.
    assert!(
        ref_status.success()
            && report_lines(&ref_stdout)
                .iter()
                .any(|l| l.contains(GET_SHM_REPLY))
            && ref_queryable.contains(GET_SHM_SENT),
        "the REFERENCE arm did not run the derived program to a reply (exit {:?}), so \
         this machine's oracle cannot serve as one for it:\n{ref_both}",
        ref_status.code(),
    );

    assert!(
        wz_status.success(),
        "the derived z_get_shm on wz's C ABI exited {:?}\n{wz_both}",
        wz_status.code(),
    );
    assert!(
        wz_queryable.contains(GET_SHM_SENT),
        "the real pico queryable did not read the SHM-allocated query payload \
         from the wz arm — it saw:\n{wz_queryable}"
    );
    // The PROGRAM's own lines, not the whole of stdout: the real library writes
    // its tracing there too, and measured against this pico peer it logs
    // `Unknown interest` at ERROR from its client routing, which wz's session
    // has no counterpart of. That line is the library's diagnostics and not the
    // program's output, and the sibling legs compare `report_lines` for the
    // same reason.
    let sending = "Sending Query 'demo/capic/qshm'...";
    for (arm, stdout) in [("reference", &ref_stdout), ("wz", &wz_stdout)] {
        assert!(
            stdout.lines().any(|l| l == sending),
            "the {arm} arm never reached the send the leg is about:\n{stdout}"
        );
    }
    assert_eq!(
        report_lines(&wz_stdout),
        report_lines(&ref_stdout),
        "§5.27 api-compat-c: the derived z_get_shm reported different replies on wz's \
         C ABI and on libzenohc against the same real pico queryable.\n\
         --- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
    );
}
