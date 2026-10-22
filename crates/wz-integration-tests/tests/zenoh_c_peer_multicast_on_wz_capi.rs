// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 913 — a zenoh-c session that lists a multicast group in `listen/endpoints`
//! joins it, as zenoh's runtime opens a multicast transport for one, and reports each member of
//! the group as zenoh-c reports it.
//!
//! ## Two legs, each a program run twice
//!
//! A stock zenohd joins the group and is its member. A zenoh-c program then joins the same
//! group, once linked against the real `libzenohc.so` and once against wz's drop-in, and what
//! the two print about the member must be the same, block for block.
//!
//! - **Events.** Upstream's `z_info.c`, unmodified. It lists the transports and links at its
//!   open, which is before any member has joined, and then prints each connectivity event. For
//!   a member zenoh announces the TRANSPORT and no link (MEASURED: the real library printed
//!   `[Transport Event] Opened:` and a multicast `Transport` block, and no `[Link Event]`), so
//!   this leg holds wz to announcing a member the same way.
//! - **Listing.** Upstream's `z_info.c` again, its `print_transport` and `print_link` included
//!   verbatim, under a `main` of this file's that waits until a multicast transport is listed
//!   and then lists the transports and the links. This is where the member's link is read: its
//!   `src`, `dst`, group, MTU, flags and reliability.
//!
//! ## The one field masked
//!
//! A link's `src` is this node's own locator on the group, the address its datagrams leave
//! from: the port is the one the operating system gave that run's socket, so it differs between
//! the two runs for no reason of either library's. Its port is masked, and nothing else: the
//! address and the scheme are still compared, so a `src` labelled with the group or the endpoint
//! reds.

use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, graceful_terminate, group_declarations,
    read_captured, wait_for_substring, wz_capi_c_cdylib, zenoh_c_oracle, zenohd_binary, ChildGuard,
};

/// The group: a port of its own, so a leg never hears another file's, on the loopback
/// interface.
const GROUP: &str = "udp/224.0.0.226:7451#iface=lo";

/// How long a run waits to report the member: two of zenoh's 2.5 s JOIN intervals, with room.
const REPORTED_WITHIN: Duration = Duration::from_secs(30);

/// The listing program: upstream's `z_info.c` included whole, its own `main` renamed out of the
/// way, and a `main` that lists once the group has a member. `{upstream}` is the path of
/// upstream's file.
const LISTING_PROBE: &str = r#"#define main upstream_z_info_main
#include "{upstream}"
#undef main

static void count_multicast(z_loaned_transport_t* transport, void* ctx) {
    if (z_transport_is_multicast(transport)) {
        ++*(int*)ctx;
    }
}

int main(int argc, char** argv) {
    z_owned_config_t config;
    parse_args(argc, argv, &config);
    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("Unable to open session!\n");
        return 1;
    }
    int members = 0;
    for (int i = 0; i < 250 && members == 0; i++) {
        z_owned_closure_transport_t count;
        z_closure(&count, count_multicast, NULL, &members);
        z_info_transports(z_loan(s), z_move(count));
        if (members == 0) {
            z_sleep_ms(100);
        }
    }
    printf("transports:\n");
    z_owned_closure_transport_t transports;
    z_closure(&transports, print_transport, NULL, NULL);
    z_info_transports(z_loan(s), z_move(transports));
    printf("links:\n");
    z_owned_closure_link_t links;
    z_closure(&links, print_link, NULL, NULL);
    z_info_links(z_loan(s), z_move(links), NULL);
    z_drop(z_move(s));
    return members > 0 ? 0 : 2;
}
"#;

/// The oracle's include, examples and library directories, or `None` with a loud note.
fn oracle_or_note() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let oracle = zenoh_c_oracle();
    if oracle.is_none() {
        eprintln!(
            "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers, examples and \
             libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX)."
        );
    }
    oracle.map(|(include, libdir, examples)| (include, examples, libdir))
}

/// Every `Transport` and `Link` block a program printed, each as one line, the port of a link's
/// `src` masked.
fn reported_blocks(printed: &str) -> BTreeSet<String> {
    let mut blocks = BTreeSet::new();
    let mut current: Option<Vec<String>> = None;
    for line in printed.lines() {
        let trimmed = line.trim();
        if let Some(block) = current.as_mut().filter(|_| line.starts_with("    ")) {
            let field = match trimmed.strip_prefix("src: ") {
                Some(src) => format!(
                    "src: {}:*",
                    src.rsplit_once(':').map_or(src, |(host, _port)| host)
                ),
                None => trimmed.to_owned(),
            };
            block.push(field);
            continue;
        }
        if let Some(block) = current.take() {
            blocks.insert(block.join("; "));
        }
        if trimmed == "Transport" || trimmed == "Link" {
            current = Some(vec![trimmed.to_owned()]);
        }
    }
    if let Some(block) = current {
        blocks.insert(block.join("; "));
    }
    blocks
}

/// Whether `blocks` holds a multicast transport.
fn holds_a_member(blocks: &BTreeSet<String>) -> bool {
    blocks
        .iter()
        .any(|b| b.starts_with("Transport") && b.contains("is_multicast: true"))
}

/// The arguments every run joins the group with.
const ON_THE_GROUP: [&str; 5] = ["-m", "peer", "-l", GROUP, "--no-multicast-scouting"];

/// Run upstream's `z_info` (`exe`) on the group until it has announced a member, a little
/// longer for any event that would follow the transport's, and return every block it printed.
fn announced(label: &str, exe: &Path) -> BTreeSet<String> {
    let mut capture: File = tempfile::tempfile().expect("a capture file");
    let child = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(exe)
        .args(ON_THE_GROUP)
        .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
        .stderr(Stdio::from(capture.try_clone().expect("dup stderr")))
        .spawn()
        .unwrap_or_else(|e| panic!("{label}: cannot start {}: {e}", exe.display()));
    let mut child = ChildGuard::wrap(label, child);
    let deadline = Instant::now() + REPORTED_WITHIN;
    while !holds_a_member(&reported_blocks(&read_captured(&mut capture))) {
        if Instant::now() >= deadline {
            graceful_terminate(child.child_mut(), Duration::from_secs(5));
            panic!(
                "{label} announced no member of {GROUP}\n{}",
                read_captured(&mut capture)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(1));
    graceful_terminate(child.child_mut(), Duration::from_secs(5));
    reported_blocks(&read_captured(&mut capture))
}

/// Run the listing program (`exe`) on the group to its end and return every block it printed.
fn listed(label: &str, exe: &Path) -> BTreeSet<String> {
    let out = Command::new(exe)
        .args(ON_THE_GROUP)
        .output_within(REPORTED_WITHIN + Duration::from_secs(10))
        .unwrap_or_else(|e| panic!("{label}: cannot run {}: {e}", exe.display()));
    let printed = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{label} exited {:?}: no member of {GROUP} was listed\n{printed}",
        out.status
    );
    reported_blocks(&printed)
}

/// The two builds of one program: on libzenohc, then on wz's drop-in.
struct Arms {
    real: PathBuf,
    wz: PathBuf,
}

/// Compile `name` from `src_dir` against each library, into a directory per arm under `dir`.
fn both_arms(name: &str, src_dir: &Path, dir: &Path, include: &Path, libdir: &Path) -> Arms {
    let real_dir = dir.join(format!("{name}-real"));
    let wz_dir = dir.join(format!("{name}-wz"));
    std::fs::create_dir_all(&real_dir).expect("a directory per arm");
    std::fs::create_dir_all(&wz_dir).expect("a directory per arm");
    let real = compile_zenoh_c_example(name, &real_dir, include, src_dir, libdir, "zenohc")
        .unwrap_or_else(|diag| panic!("{name}.c does not build against libzenohc\n{diag}"));
    let cdylib = wz_capi_c_cdylib();
    let wz_libdir = cdylib.parent().expect("the cdylib has a directory");
    let wz = compile_zenoh_c_example(name, &wz_dir, include, src_dir, wz_libdir, "wz_capi_c")
        .unwrap_or_else(|diag| panic!("{name}.c does not build against wz's drop-in\n{diag}"));
    Arms { real, wz }
}

/// A stock zenohd on the group, the member both arms report, returned once it says it is on
/// the group (`Zenoh can be reached at: <group>`), so neither arm starts before it: a run whose
/// reference arm heard no member before this wait was added is the reason it is here.
fn zenohd_member() -> (ChildGuard, File) {
    let mut log: File = tempfile::tempfile().expect("a capture file");
    let member = Command::new(zenohd_binary())
        .args([
            "-l",
            GROUP,
            "--rest-http-port",
            "none",
            "--no-multicast-scouting",
        ])
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log.try_clone().expect("dup stdout")))
        .stderr(Stdio::from(log.try_clone().expect("dup stderr")))
        .spawn()
        .expect("spawn zenohd on the group");
    let member = ChildGuard::wrap("zenohd (the member)", member);
    if let Err(printed) = wait_for_substring(&mut log, "Zenoh can be reached at", REPORTED_WITHIN) {
        panic!("zenohd never came up on {GROUP}\n{printed}");
    }
    (member, log)
}

/// A zenohd on the group is announced to upstream's `z_info.c` by the same events on wz as on
/// libzenohc: its transport, multicast, and no link.
///
/// # Control
///
/// Announcing a member's link as well (wz-capi-c's link listener forwarding a multicast
/// snapshot) reds the comparison with a `Link` block only wz printed; announcing the member
/// as the listing reports it (`as_announced` keeping `is_shm`) reds it on `is_shm: true`.
// wz-proves: api-compat-c zenohd->wz partial
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_zinfo_on_wz_announces_a_zenohd_group_member_as_libzenohc_does() {
    let Some((include, examples, libdir)) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let dir = tempfile::tempdir().expect("tempdir for the compiled programs");
    let arms = both_arms("z_info", &examples, dir.path(), &include, &libdir);
    let (mut member, _member_log) = zenohd_member();
    let by_real = announced("z_info.c on libzenohc", &arms.real);
    let by_wz = announced("z_info.c on wz-capi-c", &arms.wz);
    graceful_terminate(member.child_mut(), Duration::from_secs(5));
    assert_eq!(
        by_wz, by_real,
        "z_info.c on wz announces the group's member otherwise than on libzenohc"
    );
}

/// A zenohd on the group is listed by upstream's `print_transport` and `print_link` the same on
/// wz as on libzenohc: its multicast transport, and its link from this node's locator on the
/// group to the member's, with its group, MTU, flags and reliability.
///
/// # Control
///
/// Reporting a member's link without its group (wz-capi-c's `z_link_group` writing the empty
/// string for every link) reds the comparison on the `Link` block.
// wz-proves: api-compat-c zenohd->wz partial
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_zinfo_printers_on_wz_list_a_zenohd_group_member_as_libzenohc_does() {
    let Some((include, examples, libdir)) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let dir = tempfile::tempdir().expect("tempdir for the compiled programs");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("the probe's directory");
    let upstream = examples.join("z_info.c");
    std::fs::write(
        src_dir.join("zc_group_listing.c"),
        LISTING_PROBE.replace("{upstream}", &upstream.display().to_string()),
    )
    .expect("write the listing program");
    let arms = both_arms("zc_group_listing", &src_dir, dir.path(), &include, &libdir);
    let (mut member, _member_log) = zenohd_member();
    let by_real = listed("the listing on libzenohc", &arms.real);
    let by_wz = listed("the listing on wz-capi-c", &arms.wz);
    graceful_terminate(member.child_mut(), Duration::from_secs(5));
    assert!(
        by_real.iter().any(|b| b.starts_with("Link")),
        "the real library listed no link for the member, so there is nothing to compare\n\
         {by_real:#?}"
    );
    assert_eq!(
        by_wz, by_real,
        "the listing on wz reports the group's member otherwise than on libzenohc"
    );
}

/// A process of `exe` on the group with `args`, its output captured to the returned file.
fn spawn_on_group(label: &str, exe: &Path, args: &[&str]) -> (ChildGuard, File) {
    let capture: File = tempfile::tempfile().expect("a capture file");
    let child = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(exe)
        .args(ON_THE_GROUP)
        .args(args)
        .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
        .stderr(Stdio::from(capture.try_clone().expect("dup stderr")))
        .spawn()
        .unwrap_or_else(|e| panic!("{label}: cannot start {}: {e}", exe.display()));
    (ChildGuard::wrap(label, child), capture)
}

/// One program on the group: its label, its build, its arguments.
type OnGroup<'a> = (&'a str, &'a Path, &'a [&'a str]);

/// Run `watcher` and `speaker` on the group until `watcher` prints `heard`, and return what it
/// printed; panic with both outputs when it does not within [`REPORTED_WITHIN`].
fn heard_on_group(watcher: OnGroup<'_>, speaker: OnGroup<'_>, heard: &str) -> String {
    let (mut watching, mut watched) = spawn_on_group(watcher.0, watcher.1, watcher.2);
    let (mut speaking, mut said) = spawn_on_group(speaker.0, speaker.1, speaker.2);
    let outcome = wait_for_substring(&mut watched, heard, REPORTED_WITHIN);
    graceful_terminate(speaking.child_mut(), Duration::from_secs(5));
    graceful_terminate(watching.child_mut(), Duration::from_secs(5));
    outcome.unwrap_or_else(|printed| {
        panic!(
            "{} never printed {heard:?} with {} on {GROUP}\n--- {} ---\n{printed}\n--- {} ---\n{}",
            watcher.0,
            speaker.0,
            watcher.0,
            speaker.0,
            read_captured(&mut said)
        )
    })
}

/// The key the pub/sub legs use, and the subscription that covers it.
const PUT_KEY: &str = "demo/mc/zc";
const SUB_KEY: &str = "demo/mc/**";

/// Upstream's `z_pub.c` and `z_sub.c` on one group, one on each library, both ways: a put of
/// libzenohc is heard by wz's subscriber, and a put of wz's by libzenohc's.
///
/// # Control
///
/// The calibration is the same pair on libzenohc alone, which says whether this host carries a
/// zenoh group at all.
// wz-proves: api-compat-c zenoh-c->wz partial
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_zpub_and_zsub_cross_between_libzenohc_and_wz_on_a_group() {
    let Some((include, examples, libdir)) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let dir = tempfile::tempdir().expect("tempdir for the compiled programs");
    let zpub = both_arms("z_pub", &examples, dir.path(), &include, &libdir);
    let zsub = both_arms("z_sub", &examples, dir.path(), &include, &libdir);
    let pub_args: &[&str] = &["-k", PUT_KEY, "-p", "FROM-THE-OTHER-LIBRARY"];
    let sub_args: &[&str] = &["-k", SUB_KEY];
    let heard = format!("('{PUT_KEY}': '[");
    for (watcher, speaker) in [
        (
            ("z_sub.c on libzenohc", zsub.real.as_path()),
            ("z_pub.c on libzenohc", zpub.real.as_path()),
        ),
        (
            ("z_sub.c on wz-capi-c", zsub.wz.as_path()),
            ("z_pub.c on libzenohc", zpub.real.as_path()),
        ),
        (
            ("z_sub.c on libzenohc", zsub.real.as_path()),
            ("z_pub.c on wz-capi-c", zpub.wz.as_path()),
        ),
    ] {
        heard_on_group(
            (watcher.0, watcher.1, sub_args),
            (speaker.0, speaker.1, pub_args),
            &heard,
        );
    }
}

/// The group's address, joined by the recorder on the loopback interface.
const GROUP_ADDR: ([u8; 4], u16) = ([224, 0, 0, 226], 7451);

/// Every datagram sent to the group while `exe` ran with `args`, read by a socket of this
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
    raw.bind(&std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, GROUP_ADDR.1).into())
        .expect("bind the group's port");
    let socket: std::net::UdpSocket = raw.into();
    socket
        .join_multicast_v4(&GROUP_ADDR.0.into(), &std::net::Ipv4Addr::LOCALHOST)
        .expect("join the group on loopback");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("a read timeout, so a silent group cannot hang this test");
    let (mut child, _out) = spawn_on_group(label, exe, args);
    let mut datagrams = Vec::new();
    let mut buf = [0u8; 65_535];
    let until = Instant::now() + Duration::from_secs(6);
    while Instant::now() < until {
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            datagrams.push(buf[..n].to_vec());
        }
    }
    graceful_terminate(child.child_mut(), Duration::from_secs(5));
    datagrams
}

/// The declarations and interests a program put on the group, from its datagrams.
fn declared_on_group(label: &str, exe: &Path, args: &[&str]) -> BTreeSet<String> {
    group_declarations(&recorded_on_group(label, exe, args))
}

/// A subscriber on a group is announced on it as zenoh announces one: upstream's `z_sub.c` puts
/// the same declarations on the group on wz as on libzenohc (zenoh announces a session's
/// subscriber on each group it holds, `zenoh/src/net/routing/hat/peer/pubsub.rs` @
/// `// HACK(regions): if we have a multicast group, we use it to propagate subscribers to upstream gateways.`).
///
/// MEASURED before this leg: a libzenohc publisher with a matching listener does NOT report a
/// libzenohc subscriber on the same group as matching, so the announcement is visible on the
/// wire alone, and that is where this leg reads it.
///
/// # Control
///
/// The reference must announce something, or there is nothing to compare: its set is required
/// to name the subscription.
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_zsub_on_wz_announces_its_subscriber_on_a_group_as_libzenohc_does() {
    let Some((include, examples, libdir)) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let dir = tempfile::tempdir().expect("tempdir for the compiled programs");
    let zsub = both_arms("z_sub", &examples, dir.path(), &include, &libdir);
    let sub_args: &[&str] = &["-k", SUB_KEY];
    let by_real = declared_on_group("z_sub.c on libzenohc", &zsub.real, sub_args);
    let by_wz = declared_on_group("z_sub.c on wz-capi-c", &zsub.wz, sub_args);
    eprintln!("libzenohc declared on the group: {by_real:#?}");
    assert!(
        by_real.iter().any(|d| d.contains(SUB_KEY)),
        "libzenohc's z_sub.c announced no subscription on the group: {by_real:#?}"
    );
    assert_eq!(
        by_wz, by_real,
        "z_sub.c on wz announces its subscriber on the group otherwise than on libzenohc"
    );
}
