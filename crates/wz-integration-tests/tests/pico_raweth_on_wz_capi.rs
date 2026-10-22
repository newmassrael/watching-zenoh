// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt items 911 and 913 — zenoh-pico's raw Ethernet transport, between the real
//! library and wz's pico drop-in.
//!
//! ## Upstream's scenario, run across the two libraries
//!
//! zenoh-pico ships one scenario for the transport, `tests/raweth.py`: a `z_sub -n 10` and a
//! `z_pub -n 10` in peer mode, each listening on a `reth/` endpoint of its own MAC on `lo`
//! with the other's MAC as its whitelist, run as root because an `AF_PACKET` socket needs
//! `CAP_NET_RAW`; the subscriber must print the publisher's ten puts
//! (`vendor/zenoh-pico/tests/raweth.py` @ `>> [Subscriber] Received ('demo/example/zenoh-pico-pub': '[   9] Pub from Pico!')`).
//! The legs below run that scenario with its endpoints and its expected lines, the real
//! programs first and then with one side on wz: upstream's `z_sub.c` on wz hearing the real
//! `z_pub`, and the real `z_sub` hearing upstream's `z_pub.c` on wz. A third leg has
//! upstream's `z_info.c`, once on each library, report the real publisher as a member, and
//! the two reports must be the same line for line.
//!
//! ## The privilege
//!
//! Each program runs under `sudo -n`, as upstream's scenario runs it, and nothing else does:
//! the harness itself stays unprivileged. A host without non-interactive sudo cannot run the
//! legs, and each says so and returns; Layer M runs them only after probing for it, and fails
//! instead under `WZ_M_REQUIRE`.
//!
//! ## The reference, and its two patches
//!
//! At the pin the real library cannot run its own scenario: MEASURED, its z_sub dies of
//! SIGSEGV at the publisher's first frame (the raweth reads hand the receive an address slice
//! with no buffer), and with that fixed its z_pub still never puts (the step past the write
//! filter names the UDP group's transport type alone). `scripts/build-zenoh-pico-cli.sh`
//! builds this arm with exactly those two fixed, each to what pico already does for its UDP
//! group, and `THIRD_PARTY.md` records both. With them the scenario passes on the real library,
//! and that run is each leg's calibration.
//!
//! ## The calibration
//!
//! The scenario on the real library alone runs first in each leg. Raw frames on `lo` depend on
//! the host, and a run where the reference fails says the host cannot carry the scenario, not
//! that the drop-in is wrong.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    compile_pico_example_against_wz_capi_in, graceful_terminate, read_captured, wait_for_substring,
    zenoh_pico_reth_cli_binary, ChildGuard, PicoHeaderArm,
};

/// The subscriber's endpoint in upstream's scenario: its own MAC on `lo`, hearing only the
/// publisher's.
const SUB_ENDPOINT: &str = "reth/30:03:8c:c8:00:a2#iface=lo;whitelist=30:03:8c:c8:00:a1,";
/// The publisher's endpoint: its own MAC, hearing only the subscriber's.
const PUB_ENDPOINT: &str = "reth/30:03:8c:c8:00:a1#iface=lo;whitelist=30:03:8c:c8:00:a2,";

/// How many puts the scenario makes, and the key and text of each.
const PUTS: usize = 10;
const PUT_KEY: &str = "demo/example/zenoh-pico-pub";

/// How long a program of the scenario is given: the publisher puts once a second.
const SCENARIO_BOUND: Duration = Duration::from_secs(40);

/// The line the subscriber prints for put `i` (`vendor/zenoh-pico/tests/raweth.py` @
/// `>> [Subscriber] Received ('demo/example/zenoh-pico-pub': '[   0] Pub from Pico!')`).
fn received_line(i: usize) -> String {
    format!(">> [Subscriber] Received ('{PUT_KEY}': '[{i:>4}] Pub from Pico!')")
}

/// Whether this process may run a program as root without a password, which the scenario
/// needs and a host need not grant.
fn may_sudo() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output_bounded()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// `true` when the legs can run; otherwise a loud note, and a panic when Layer M armed the
/// requirement.
fn privileged_or_note() -> bool {
    if may_sudo() {
        return true;
    }
    let note = "this host has no non-interactive sudo, and a raweth program needs CAP_NET_RAW";
    if std::env::var_os("WZ_M_REQUIRE").is_some_and(|v| v == "1") {
        panic!("{note}, but WZ_M_REQUIRE=1 says this job provisions it");
    }
    eprintln!("skip: {note}");
    false
}

/// The longest a program of a leg may live, whatever the leg does: past it the program is
/// ended by `timeout` running beside it as root.
const LIFETIME_BOUND: &str = "150";

/// A program run as root, ended with the leg however the leg ends.
///
/// `ChildGuard` ends its child with SIGKILL, which ends `sudo` alone: sudo relays the signals
/// it can catch to the program it runs, and SIGKILL is not one, so the program would live on
/// as root and hold the leg's MAC for the legs after it. MEASURED: a leg that panicked left
/// its root `z_pub` running, and the next leg's calibration on the real library heard
/// nothing. So the guard first sends SIGTERM, which sudo relays, and the program is run under
/// `timeout`, which ends it at [`LIFETIME_BOUND`] if nothing else does.
struct Privileged(ChildGuard);

impl Privileged {
    fn child_mut(&mut self) -> &mut std::process::Child {
        self.0.child_mut()
    }
}

impl Drop for Privileged {
    fn drop(&mut self) {
        if let Ok(None) = self.0.child_mut().try_wait() {
            graceful_terminate(self.0.child_mut(), Duration::from_secs(5));
        }
    }
}

/// `exe` run as root with `args`, as upstream's scenario runs it, its output captured.
fn spawn_privileged(label: &str, exe: &Path, args: &[&str]) -> (Privileged, File) {
    let capture = tempfile::tempfile().expect("a capture file");
    let child = Command::new("sudo")
        .args(["-n", "timeout", "--kill-after=5", LIFETIME_BOUND])
        .args(["stdbuf", "-oL", "-eL"])
        .arg(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
        .stderr(Stdio::from(capture.try_clone().expect("dup stderr")))
        .spawn()
        .unwrap_or_else(|e| panic!("{label}: cannot start {}: {e}", exe.display()));
    (Privileged(ChildGuard::wrap(label, child)), capture)
}

/// Upstream's example `name`, compiled against wz's raweth build into `dir`.
fn on_wz(name: &str, dir: &Path) -> PathBuf {
    compile_pico_example_against_wz_capi_in(name, dir, PicoHeaderArm::RawEth)
        .unwrap_or_else(|diag| panic!("{name}.c does not build against wz's drop-in\n{diag}"))
}

/// Whether `child` ended with status 0 within `bound`.
fn ended_well_within(child: &mut std::process::Child, bound: Duration) -> bool {
    let deadline = std::time::Instant::now() + bound;
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return false,
        }
    }
    false
}

/// Upstream's scenario with `sub` as the subscriber and `publisher` as the publisher: the
/// subscriber, given `-n 10`, ends with status 0 once it has received ten samples, and must
/// have printed each of the ten puts. These are upstream's own two checks
/// (`vendor/zenoh-pico/tests/raweth.py` @ `if z_sub_status == z_sub_expected_status:`), and the
/// end of the program is what the leg waits on.
fn scenario(sub: (&str, &Path), publisher: (&str, &Path)) {
    let n = PUTS.to_string();
    let (mut sub_child, mut heard) =
        spawn_privileged(sub.0, sub.1, &["-n", &n, "-m", "peer", "-l", SUB_ENDPOINT]);
    if let Err(printed) = wait_for_substring(&mut heard, "Press CTRL-C", SCENARIO_BOUND) {
        graceful_terminate(sub_child.child_mut(), Duration::from_secs(5));
        panic!("{} never declared its subscriber\n{printed}", sub.0);
    }
    let (mut pub_child, mut said) = spawn_privileged(
        publisher.0,
        publisher.1,
        &["-n", &n, "-m", "peer", "-l", PUB_ENDPOINT],
    );
    let ended = ended_well_within(sub_child.child_mut(), SCENARIO_BOUND);
    // The guards end whichever of the two is still running.
    drop(pub_child);
    drop(sub_child);
    let printed = read_captured(&mut heard);
    assert!(
        ended,
        "{} did not end well after ten puts of {} over raw Ethernet\n--- {} ---\n{printed}\n\
         --- {} ---\n{}",
        sub.0,
        publisher.0,
        sub.0,
        publisher.0,
        read_captured(&mut said)
    );
    for i in 0..PUTS {
        assert!(
            printed.contains(&received_line(i)),
            "{} missed put {i} of {}\n{printed}",
            sub.0,
            publisher.0
        );
    }
}

/// The real zenoh-pico `z_pub` over raw Ethernet is heard by upstream's `z_sub.c` on wz.
///
/// # Control
///
/// Upstream's scenario on the real library alone, first.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "opens raw Ethernet sockets on lo under sudo; run by run-ci Layer M"]
fn upstream_zsub_on_wz_hears_the_real_pico_zpub_on_a_raweth_multicast_group() {
    if !privileged_or_note() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir for the compiled example");
    let real_pub = zenoh_pico_reth_cli_binary("z_pub");
    scenario(
        (
            "real zenoh-pico z_sub",
            &zenoh_pico_reth_cli_binary("z_sub"),
        ),
        ("real zenoh-pico z_pub", &real_pub),
    );
    scenario(
        ("z_sub.c on wz-capi-pico", &on_wz("z_sub", dir.path())),
        ("real zenoh-pico z_pub", &real_pub),
    );
}

/// Upstream's `z_pub.c` on wz over raw Ethernet is heard by the real zenoh-pico `z_sub`.
///
/// # Control
///
/// Upstream's scenario on the real library alone, first.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "opens raw Ethernet sockets on lo under sudo; run by run-ci Layer M"]
fn the_real_pico_zsub_hears_upstream_zpub_on_wz_on_a_raweth_multicast_group() {
    if !privileged_or_note() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir for the compiled example");
    let real_sub = zenoh_pico_reth_cli_binary("z_sub");
    scenario(
        ("real zenoh-pico z_sub", &real_sub),
        (
            "real zenoh-pico z_pub",
            &zenoh_pico_reth_cli_binary("z_pub"),
        ),
    );
    scenario(
        ("real zenoh-pico z_sub", &real_sub),
        ("z_pub.c on wz-capi-pico", &on_wz("z_pub", dir.path())),
    );
}

/// Every `transport{...}` and `link{...}` line `z_info` printed.
fn reported_lines(printed: &str) -> std::collections::BTreeSet<String> {
    printed
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("transport{") || line.starts_with("link{"))
        .map(str::to_owned)
        .collect()
}

/// Run `z_info` (`exe`) on the subscriber's endpoint until it has reported a multicast
/// transport and a link, and return every such line it printed.
fn zinfo_reports(label: &str, exe: &Path) -> std::collections::BTreeSet<String> {
    let (mut child, mut printed) =
        spawn_privileged(label, exe, &["-m", "peer", "-l", SUB_ENDPOINT]);
    let deadline = std::time::Instant::now() + SCENARIO_BOUND;
    let lines = loop {
        let lines = reported_lines(&read_captured(&mut printed));
        let has_member = lines
            .iter()
            .any(|l| l.starts_with("transport{") && l.contains("is_multicast=true"));
        let has_link = lines.iter().any(|l| l.starts_with("link{"));
        if has_member && has_link {
            break lines;
        }
        if std::time::Instant::now() >= deadline {
            graceful_terminate(child.child_mut(), Duration::from_secs(5));
            panic!(
                "{label} reported no member over raw Ethernet with its link\n{}",
                read_captured(&mut printed)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    graceful_terminate(child.child_mut(), Duration::from_secs(5));
    lines
}

/// Upstream's `z_info.c` reports the real publisher of the scenario as a member, once on the
/// real library and once on wz's, and wz's report is the real one, line for line: the
/// member's zid and role, `is_multicast=true`, and its link as pico labels a raweth member's,
/// with the raweth link's MTU and flags.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "opens raw Ethernet sockets on lo under sudo; run by run-ci Layer M"]
fn upstream_zinfo_on_wz_reports_a_raweth_multicast_member_as_the_real_library_does() {
    if !privileged_or_note() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir for the compiled example");
    let (mut member, _member_out) = spawn_privileged(
        "real zenoh-pico z_pub (the member)",
        &zenoh_pico_reth_cli_binary("z_pub"),
        &["-m", "peer", "-l", PUB_ENDPOINT],
    );
    let real = zinfo_reports(
        "real zenoh-pico z_info",
        &zenoh_pico_reth_cli_binary("z_info"),
    );
    let wz = zinfo_reports("z_info.c on wz-capi-pico", &on_wz("z_info", dir.path()));
    graceful_terminate(member.child_mut(), Duration::from_secs(5));
    eprintln!("the real library reported: {real:#?}");
    assert_eq!(
        wz, real,
        "z_info.c on wz reports the raweth member otherwise than on the real library"
    );
}
