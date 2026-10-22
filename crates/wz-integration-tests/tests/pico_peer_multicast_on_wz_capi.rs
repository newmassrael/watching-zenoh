// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 913 — upstream's own multicast peer test, `tests/z_test_peer_multicast.c`,
//! run against wz's pico drop-in.
//!
//! The program is upstream's and unmodified: four sessions in one process, each opened with
//! `mode=peer` and `listen=udp/224.0.0.224:7447#iface=lo`, each declaring a subscriber and a
//! queryable on `test/**`, publishing five times and getting five times on a key of its own,
//! and each asserting that its subscriber and its queryable heard at least fifteen times, five
//! from each of the other three. So a pass needs every session to have joined the group, every
//! put to reach the other three, and every get to reach their queryables and END on their
//! finals: the program reads each get's replies with `z_recv` until the channel closes, which it
//! does when the last member's final has come.
//!
//! ## What the harness adds, and why it is not a change to the program
//!
//! The program starts its four sessions with `_z_task_init` and joins them with
//! `_z_task_join`, which are pico's own system layer and not its API: a drop-in for the API
//! owes neither, and wz's does not export them. The harness compiles one C file that defines
//! the two on POSIX threads, as pico's unix system layer does
//! (`vendor/zenoh-pico/src/system/unix/system.c`), and then `#include`s upstream's file
//! verbatim, so every line of the test is upstream's.
//!
//! ## The calibration
//!
//! The same program against the real `libzenohpico.so` runs first. Multicast on the loopback
//! interface depends on the host, and a run where the reference fails says the environment
//! cannot carry the test, not that the drop-in is wrong.
//!
//! ## What a pass is read from
//!
//! Its exit status is not enough: a session that cannot open prints `Unable to open session!`
//! and returns from its thread before the asserts, and a header set that misses one of the
//! test's switches compiles a stub `main` that prints `Missing config token` and exits 0. So
//! each run is read for both, and for the receive lines each session prints.
//!
//! ## Across the two implementations
//!
//! Upstream's test runs four sessions of ONE library, so it cannot tell a wz group from a
//! wz-only dialect. Three legs below put the real zenoh-pico CLI on the same group as wz's
//! drop-in: the real `z_pub` heard by upstream's `z_sub.c` on wz, upstream's `z_pub.c` on wz
//! heard by the real `z_sub`, and upstream's `z_info.c`, once on each library, reporting the
//! same real publisher. The last is a difference of two runs: every `transport{...}` and
//! `link{...}` line the real library prints about the member must be the line wz prints, so
//! the labels (the joined endpoint as `src`, the member's address as `dst`, the UDP link's
//! fixed properties) are pico's own and not a reading of them.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    compile_pico_example_against_wz_capi, compile_pico_source, graceful_terminate,
    group_declarations, project_root, read_captured, wait_for_substring, zenoh_pico_cli_binary,
    zenoh_pico_include_dirs, zenoh_pico_library_dir, ChildGuard, PicoHeaderArm,
};

/// The program sleeps 5 s, puts for 5 s, gets for 5 s and sleeps 5 s more in each of its
/// four threads, and its `main` waits 20 s before joining them: about 25 s when every get
/// ends on its finals, and 70 s or more if every get waits out its 10 s timeout instead.
const RUN_BOUND: Duration = Duration::from_secs(150);

/// Longer than a run whose gets end on their finals takes, shorter than one whose five gets
/// per session each wait out the 10 s timeout: what tells the two apart.
const ENDS_ON_FINALS: Duration = Duration::from_secs(55);

/// How many sessions the program opens, and how many times each hears each of the others.
const SESSIONS: usize = 4;
const PER_PEER: usize = 5;

/// Upstream's test, in the vendored tree.
fn upstream_test() -> PathBuf {
    let src = project_root().join("vendor/zenoh-pico/tests/z_test_peer_multicast.c");
    assert!(
        src.is_file(),
        "upstream zenoh-pico test {} missing; run `git submodule update --init vendor/zenoh-pico`",
        src.display()
    );
    src
}

/// The C file wz's run compiles: pico's two task functions on POSIX threads, then upstream's
/// test, included whole.
fn with_task_functions(dir: &Path) -> PathBuf {
    let wrapper = dir.join("z_test_peer_multicast.c");
    let text = format!(
        "#include <pthread.h>\n\
         #include \"zenoh-pico.h\"\n\
         \n\
         z_result_t _z_task_init(_z_task_t *task, z_task_attr_t *attr, void *(*fun)(void *), void *arg) {{\n\
         \x20   return pthread_create(task, attr, fun, arg) == 0 ? _Z_RES_OK : _Z_ERR_GENERIC;\n\
         }}\n\
         \n\
         z_result_t _z_task_join(_z_task_t *task) {{\n\
         \x20   return pthread_join(*task, NULL) == 0 ? _Z_RES_OK : _Z_ERR_GENERIC;\n\
         }}\n\
         \n\
         #include \"{}\"\n",
        upstream_test().display()
    );
    std::fs::write(&wrapper, text).expect("write the harness C file");
    wrapper
}

/// Run `exe` to its end and return what it printed, checked for a stub, a session that did
/// not open, and the receive lines of every session.
fn run_and_read(label: &str, exe: &Path) -> String {
    let started = std::time::Instant::now();
    let out = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(exe)
        .output_within(RUN_BOUND)
        .unwrap_or_else(|e| panic!("{label}: cannot start {}: {e}", exe.display()));
    let took = started.elapsed();
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !printed.contains("Missing config token"),
        "{label}: the program compiled to its stub main; the header set misses one of its \
         switches\n{printed}"
    );
    assert!(
        !printed.contains("Unable to"),
        "{label}: a session failed a call before the asserts\n{printed}"
    );
    assert!(
        out.status.success(),
        "{label}: exited {:?}\n{printed}",
        out.status
    );
    for id in 0..SESSIONS {
        for (what, line) in [
            ("subscriber", format!(">> [Subscriber {id}] Received")),
            ("queryable", format!(" >> [Queryable {id}] Received")),
        ] {
            let heard = printed.matches(&line).count();
            assert!(
                heard >= (SESSIONS - 1) * PER_PEER,
                "{label}: session {id}'s {what} heard {heard} times, fewer than {} \
                 (five from each of the other three)\n{printed}",
                (SESSIONS - 1) * PER_PEER
            );
        }
        // Each get is answered: the other three reply on the same key, and the get's default
        // consolidation keeps one reply per key, so a session reads one per get. MEASURED on the
        // real library first: five per session, where the replies of three would be fifteen.
        let replies = printed
            .matches(&format!(">> [Query {id}] Received"))
            .count();
        assert!(
            replies >= PER_PEER,
            "{label}: session {id}'s five gets were answered {replies} times; each is answered \
             once its replies are consolidated\n{printed}"
        );
    }
    assert!(
        took < ENDS_ON_FINALS,
        "{label}: the run took {took:?}, the time of gets that waited out their timeout rather \
         than ending on the members' finals\n{printed}"
    );
    printed
}

/// The calibration: upstream's test against upstream's library, on this host.
// wz-proves: none -- the calibration: upstream's program on upstream's library says whether this host carries a loopback group, and runs no wz code
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_peer_multicast_test_passes_against_real_pico() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled test");
    let exe = compile_pico_source(
        &upstream_test(),
        dir.path(),
        &zenoh_pico_include_dirs(),
        &zenoh_pico_library_dir(),
        "zenohpico",
    )
    .unwrap_or_else(|diag| {
        panic!("upstream's test does not build against upstream's library\n{diag}")
    });
    run_and_read("z_test_peer_multicast on libzenohpico", &exe);
}

/// The claim: the same program against wz's pico drop-in.
// wz-proves: none -- upstream's own self-asserting test against wz; all four group members are wz, so no foreign party speaks
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_peer_multicast_test_passes_against_wz_capi_pico() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled test");
    let arm = PicoHeaderArm::MultiThreaded;
    let cdylib = arm.wz_cdylib();
    let libdir = cdylib.parent().expect("the cdylib has a directory");
    let exe = compile_pico_source(
        &with_task_functions(dir.path()),
        dir.path(),
        &arm.include_dirs(),
        libdir,
        "wz_capi_pico",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "upstream's z_test_peer_multicast.c does not build against wz's pico drop-in, so the \
             drop-in is not one for it\n{diag}"
        )
    });
    run_and_read("z_test_peer_multicast on wz-capi-pico", &exe);
}

/// The group the cross legs share: a port of its own, so a leg never hears upstream's test
/// above, and the loopback interface, as upstream's test joins.
const CROSS_GROUP: &str = "udp/224.0.0.225:7449#iface=lo";

/// How long a member waits to hear another: two of pico's 2.5 s JOIN intervals and the
/// one-second cadence of `z_pub`, with room.
const HEARD_WITHIN: Duration = Duration::from_secs(30);

/// The cross group's address, joined by the recorder on the loopback interface.
const CROSS_ADDR: ([u8; 4], u16) = ([224, 0, 0, 225], 7449);

/// Every datagram sent to the cross group while `exe` ran with `args`, read by a socket of this
/// test's own that joins it on loopback. `SO_REUSEADDR` is load-bearing: the program binds the
/// same port, and without the option the second socket on a multicast port receives nothing.
fn recorded_on_group(label: &str, exe: &Path, args: &[&str]) -> Vec<Vec<u8>> {
    let raw = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .expect("open a UDP socket");
    raw.set_reuse_address(true).expect("SO_REUSEADDR");
    raw.bind(&std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, CROSS_ADDR.1).into())
        .expect("bind the group's port");
    let socket: std::net::UdpSocket = raw.into();
    socket
        .join_multicast_v4(&CROSS_ADDR.0.into(), &std::net::Ipv4Addr::LOCALHOST)
        .expect("join the group on loopback");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("a read timeout, so a silent group cannot hang this test");
    let (mut child, _out) = spawn_on_group(label, exe, args);
    let mut datagrams = Vec::new();
    let mut buf = [0u8; 65_535];
    let until = std::time::Instant::now() + Duration::from_secs(6);
    while std::time::Instant::now() < until {
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            datagrams.push(buf[..n].to_vec());
        }
    }
    graceful_terminate(child.child_mut(), Duration::from_secs(5));
    datagrams
}

/// Upstream's `z_sub.c`, `z_queryable.c` and `z_liveliness.c` put the same declarations on the
/// group on wz's drop-in as on the real library, which sends a session's declarations over
/// whatever transport it holds (`vendor/zenoh-pico/src/net/primitives.c` @
/// `z_result_t _z_send_declare(`), its multicast declarations switch left at its default 0.
///
/// # Control
///
/// The reference must put something on the group for each program, or there is nothing to
/// compare: each set is required to name the program's key.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_examples_on_wz_declare_on_a_group_as_the_real_library_does() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled examples");
    let mut differ = Vec::new();
    for (example, key, args) in [
        ("z_sub", "demo/mc/**", ["-k", "demo/mc/**"]),
        ("z_queryable", "demo/mc/q", ["-k", "demo/mc/q"]),
        ("z_liveliness", "demo/mc/token", ["-k", "demo/mc/token"]),
    ] {
        let real = group_declarations(&recorded_on_group(
            &format!("real zenoh-pico {example}"),
            &zenoh_pico_cli_binary(example),
            &args,
        ));
        let wz = group_declarations(&recorded_on_group(
            &format!("{example}.c on wz-capi-pico"),
            &on_wz(example, dir.path()),
            &args,
        ));
        assert!(
            real.iter().any(|d| d.contains(key)),
            "the real {example} declared nothing on {key}: {real:#?}"
        );
        if wz != real {
            differ.push(format!("{example}: real {real:?}, wz {wz:?}"));
        }
    }
    assert!(
        differ.is_empty(),
        "upstream's examples on wz declare on the group otherwise than on the real library:\n{}",
        differ.join("\n")
    );
}

/// A process of `exe` on the cross group, its output captured to a file it shares with the
/// returned reader.
fn spawn_on_group(label: &str, exe: &Path, args: &[&str]) -> (ChildGuard, File) {
    let capture = tempfile::tempfile().expect("a capture file");
    let child = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(exe)
        .args(["-m", "peer", "-l", CROSS_GROUP])
        .args(args)
        .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
        .stderr(Stdio::from(capture.try_clone().expect("dup stderr")))
        .spawn()
        .unwrap_or_else(|e| panic!("{label}: cannot start {}: {e}", exe.display()));
    (ChildGuard::wrap(label, child), capture)
}

/// Upstream's example `name`, compiled against wz's drop-in into `dir`.
fn on_wz(name: &str, dir: &Path) -> PathBuf {
    compile_pico_example_against_wz_capi(name, dir)
        .unwrap_or_else(|diag| panic!("{name}.c does not build against wz's drop-in\n{diag}"))
}

/// A subscriber on the group hears a publisher on it: `sub` with `-n 1` exits on its first
/// sample, and its line names the publisher's key and payload.
fn subscriber_hears_publisher(sub: (&str, &Path), publisher: (&str, &Path)) {
    let key = "demo/mc/cross";
    let payload = "FROM-THE-OTHER-LIBRARY";
    let (mut sub_child, mut heard) = spawn_on_group(sub.0, sub.1, &["-k", "demo/mc/**", "-n", "1"]);
    let (mut pub_child, mut said) =
        spawn_on_group(publisher.0, publisher.1, &["-k", key, "-v", payload]);
    let outcome = wait_for_substring(&mut heard, payload, HEARD_WITHIN);
    graceful_terminate(pub_child.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub_child.child_mut(), Duration::from_secs(5));
    let printed = outcome.unwrap_or_else(|printed| {
        panic!(
            "{} never heard {} on {CROSS_GROUP}\n--- {} ---\n{printed}\n--- {} ---\n{}",
            sub.0,
            publisher.0,
            sub.0,
            publisher.0,
            read_captured(&mut said)
        )
    });
    assert!(
        printed.contains(&format!(">> [Subscriber] Received ('{key}': '")),
        "{} heard the payload on another key\n{printed}",
        sub.0
    );
}

/// The real zenoh-pico `z_pub` on the group is heard by upstream's `z_sub.c` on wz.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_zsub_on_wz_hears_the_real_pico_zpub_on_a_group() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled example");
    subscriber_hears_publisher(
        ("z_sub.c on wz-capi-pico", &on_wz("z_sub", dir.path())),
        ("real zenoh-pico z_pub", &zenoh_pico_cli_binary("z_pub")),
    );
}

/// Upstream's `z_pub.c` on wz on the group is heard by the real zenoh-pico `z_sub`.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn the_real_pico_zsub_hears_upstream_zpub_on_wz_on_a_group() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled example");
    subscriber_hears_publisher(
        ("real zenoh-pico z_sub", &zenoh_pico_cli_binary("z_sub")),
        ("z_pub.c on wz-capi-pico", &on_wz("z_pub", dir.path())),
    );
}

/// Every `transport{...}` and `link{...}` line `z_info` printed, from its listing and from
/// its events alike: a member already admitted when the listing ran is reported there, one
/// admitted after it by an event, and the two print the same line.
fn reported_lines(printed: &str) -> std::collections::BTreeSet<String> {
    printed
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("transport{") || line.starts_with("link{"))
        .map(str::to_owned)
        .collect()
}

/// Run `z_info` (`exe`) on the group until it has reported a multicast transport and a
/// link, and return every such line it printed.
fn zinfo_reports(label: &str, exe: &Path) -> std::collections::BTreeSet<String> {
    let (mut child, mut printed) = spawn_on_group(label, exe, &[]);
    let deadline = std::time::Instant::now() + HEARD_WITHIN;
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
                "{label} reported no member of {CROSS_GROUP} with its link\n{}",
                read_captured(&mut printed)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    graceful_terminate(child.child_mut(), Duration::from_secs(5));
    lines
}

/// Upstream's `z_info.c` reports a real pico member of the group, once on the real library
/// and once on wz's, and wz's report is the real one, line for line: the member's zid and
/// role, `is_multicast=true`, and its link from the joined endpoint to the member's address
/// with the UDP multicast link's MTU and flags.
///
/// # Control
///
/// Labelling a member's link `src` with this node's own locator (wz-capi-pico's `link_of`
/// reading `src` whatever its group) reds the comparison on the `link{` line.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_zinfo_on_wz_reports_a_group_member_as_the_real_library_does() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled example");
    let (mut member, _member_out) = spawn_on_group(
        "real zenoh-pico z_pub (the member)",
        &zenoh_pico_cli_binary("z_pub"),
        &["-k", "demo/mc/info", "-v", "member"],
    );
    let real = zinfo_reports("real zenoh-pico z_info", &zenoh_pico_cli_binary("z_info"));
    let wz = zinfo_reports("z_info.c on wz-capi-pico", &on_wz("z_info", dir.path()));
    graceful_terminate(member.child_mut(), Duration::from_secs(5));
    assert_eq!(
        wz, real,
        "z_info.c on wz reports the group's member otherwise than on the real library"
    );
}
