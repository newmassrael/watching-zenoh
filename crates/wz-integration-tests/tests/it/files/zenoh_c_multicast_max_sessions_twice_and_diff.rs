// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport/multicast/max_sessions` -- how many members a session holds on a multicast group,
//! one config document handed to upstream's `z_sub.c` linked against the real `libzenohc.so` and
//! against wz's cdylib.
//!
//! ## Upstream's rule
//!
//! A multicast transport ignores the Join of a new member once it holds `max_sessions` of them
//! (`io/zenoh-transport/src/multicast/rx.rs` @
//! `if zread!(self.peers).len() >= self.manager.config.multicast.max_sessions {`), and it reads
//! no frame from a member it does not hold (the same file @
//! `if let Some(peer) = zread!(self.peers).get(&locator) {`). So a subscriber whose group is held
//! to one member hears the first member that joins and never the second.
//!
//! ## The leg
//!
//! The subject is upstream's `z_sub.c`, unmodified, given the document with `-c`: a peer on one
//! loopback group, no scouting, and the cap. Two members are upstream's `z_pub.c` on the real
//! library, each publishing on a key of its own. The first starts, and once the subject has heard
//! it the second starts; the subject then has several of zenoh's join intervals to hear the
//! second. The same document without the cap is the control on each library: the second member
//! is heard, so its silence under the cap is the key's.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, graceful_terminate, read_captured,
    wait_for_substring, wz_capi_c_cdylib, zenoh_c_oracle, zenoh_c_shared_library, ChildGuard,
};

/// The group: a port of its own, so this leg never hears another file's, on the loopback
/// interface.
const GROUP: &str = "udp/224.0.0.228:7458#iface=lo";

/// How long a member gets to be heard when it is expected to be: several of zenoh's 2.5 s JOIN
/// intervals, with room.
const HEARD_WITHIN: Duration = Duration::from_secs(30);

/// How long the subject listens for the second member when the cap is expected to keep it out:
/// the second member joins within one JOIN interval and publishes once a second, so an admitted
/// member is heard well inside it.
const KEPT_OUT_FOR: Duration = Duration::from_secs(12);

/// How long a terminated child gets before it is killed outright.
const TERMINATE_WITHIN: Duration = Duration::from_secs(5);

/// The keys of the two members, and the subscription that covers both.
const FIRST_KEY: &str = "demo/max-sessions/first";
const SECOND_KEY: &str = "demo/max-sessions/second";
const SUB_KEY: &str = "demo/max-sessions/**";

/// The arguments each member joins the group with.
const ON_THE_GROUP: [&str; 5] = ["-m", "peer", "-l", GROUP, "--no-multicast-scouting"];

/// The oracle's include and examples directories, or `None` with a loud note.
fn oracle_or_note() -> Option<(PathBuf, PathBuf)> {
    let oracle = zenoh_c_oracle();
    if oracle.is_none() {
        eprintln!(
            "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers, examples and \
             libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX)."
        );
    }
    oracle.map(|(include, _libdir, examples)| (include, examples))
}

/// The two builds of one upstream example: on libzenohc, then on wz's drop-in.
struct Arms {
    real: PathBuf,
    wz: PathBuf,
}

/// Compile upstream's `name` against each library, into a directory per arm under `dir`.
fn both_arms(name: &str, examples: &Path, dir: &Path, include: &Path) -> Arms {
    let real_dir = dir.join(format!("{name}-real"));
    let wz_dir = dir.join(format!("{name}-wz"));
    std::fs::create_dir_all(&real_dir).expect("a directory per arm");
    std::fs::create_dir_all(&wz_dir).expect("a directory per arm");
    let reference = zenoh_c_shared_library().expect("the oracle resolved before the arms");
    let libdir = reference.parent().expect("libzenohc.so has a directory");
    let real = compile_zenoh_c_example(name, &real_dir, include, examples, libdir, "zenohc")
        .unwrap_or_else(|diag| panic!("{name}.c does not build against libzenohc\n{diag}"));
    let cdylib = wz_capi_c_cdylib();
    let wz_libdir = cdylib.parent().expect("the cdylib has a directory");
    let wz = compile_zenoh_c_example(name, &wz_dir, include, examples, wz_libdir, "wz_capi_c")
        .unwrap_or_else(|diag| panic!("{name}.c does not build against wz's drop-in\n{diag}"));
    Arms { real, wz }
}

/// The subject's document: a peer on the group with no scouting, and the cap when `cap` states
/// one.
fn subject_document(cap: Option<usize>) -> String {
    let transport = match cap {
        Some(cap) => format!(", transport: {{ multicast: {{ max_sessions: {cap} }} }}"),
        None => String::new(),
    };
    format!(
        r#"{{ mode: "peer", listen: {{ endpoints: ["{GROUP}"] }},
  scouting: {{ multicast: {{ enabled: false }} }}{transport} }}"#
    )
}

/// `exe` started with `args`, its output captured to the returned file.
fn spawn_captured(label: &str, exe: &Path, args: &[&str]) -> (ChildGuard, File) {
    let capture: File = tempfile::tempfile().expect("a capture file");
    let child = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(exe)
        .args(args)
        .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
        .stderr(Stdio::from(capture.try_clone().expect("dup stderr")))
        .spawn()
        .unwrap_or_else(|e| panic!("{label}: cannot start {}: {e}", exe.display()));
    (ChildGuard::wrap(label, child), capture)
}

/// Run the subject (`z_sub.c` built on one library) with `document` and the two members on the
/// real library, and return whether the subject heard the second member within `window` of its
/// start. Panics, with every output, when the subject never hears the first: the group itself is
/// then not carrying.
fn second_member_heard(
    label: &str,
    zsub: &Path,
    zpub: &Path,
    document: &Path,
    window: Duration,
) -> bool {
    let doc = document.to_str().expect("the document path is text");
    let (mut subject, mut said) = spawn_captured(label, zsub, &["-c", doc, "-k", SUB_KEY]);
    let first_args: Vec<&str> = ON_THE_GROUP
        .iter()
        .copied()
        .chain(["-k", FIRST_KEY, "-p", "FIRST"])
        .collect();
    let (mut first, mut first_log) = spawn_captured("the first member", zpub, &first_args);
    // What `z_sub.c` prints for a sample of each member.
    let first_heard = format!("('{FIRST_KEY}': '");
    let second_heard = format!("('{SECOND_KEY}': '");
    if let Err(printed) = wait_for_substring(&mut said, &first_heard, HEARD_WITHIN) {
        let first_text = read_captured(&mut first_log);
        graceful_terminate(first.child_mut(), TERMINATE_WITHIN);
        graceful_terminate(subject.child_mut(), TERMINATE_WITHIN);
        panic!(
            "{label} never heard the first member on {GROUP}\n--- {label} ---\n{printed}\n\
             --- the first member ---\n{first_text}"
        );
    }
    let second_args: Vec<&str> = ON_THE_GROUP
        .iter()
        .copied()
        .chain(["-k", SECOND_KEY, "-p", "SECOND"])
        .collect();
    let (mut second, _second_log) = spawn_captured("the second member", zpub, &second_args);
    let outcome = wait_for_substring(&mut said, &second_heard, window);
    graceful_terminate(second.child_mut(), TERMINATE_WITHIN);
    graceful_terminate(first.child_mut(), TERMINATE_WITHIN);
    graceful_terminate(subject.child_mut(), TERMINATE_WITHIN);
    outcome.is_ok()
}

/// A group held to one member by the document hears its first member and not its second, on wz
/// as on libzenohc, and the same document without the cap hears both on each.
///
/// # Control
///
/// The document without `max_sessions` (upstream's 1000) runs on each library first: the second
/// member is heard, so the cap is what keeps it out where it is.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn a_group_held_to_one_member_by_max_sessions_ignores_the_second_on_wz_and_libzenohc() {
    let Some((include, examples)) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let dir = tempfile::tempdir().expect("tempdir for the compiled programs");
    let zsub = both_arms("z_sub", &examples, dir.path(), &include);
    let zpub = both_arms("z_pub", &examples, dir.path(), &include);
    let open_doc = dir.path().join("open.json5");
    std::fs::write(&open_doc, subject_document(None)).expect("write the document");
    let capped_doc = dir.path().join("capped.json5");
    std::fs::write(&capped_doc, subject_document(Some(1))).expect("write the document");

    // The ORACLE first, both documents: libzenohc hears the second member without the cap and
    // not with it, or the comparison below is not about the key.
    assert!(
        second_member_heard(
            "z_sub.c on libzenohc, no cap",
            &zsub.real,
            &zpub.real,
            &open_doc,
            HEARD_WITHIN,
        ),
        "libzenohc's subscriber never heard the second member without a cap, so this host's \
         group cannot show the key"
    );
    let by_real = second_member_heard(
        "z_sub.c on libzenohc, max_sessions 1",
        &zsub.real,
        &zpub.real,
        &capped_doc,
        KEPT_OUT_FOR,
    );
    assert!(
        !by_real,
        "libzenohc's subscriber heard the second member under max_sessions 1, so the rule this \
         leg compares against is not what it assumes"
    );

    assert!(
        second_member_heard(
            "z_sub.c on wz-capi-c, no cap",
            &zsub.wz,
            &zpub.real,
            &open_doc,
            HEARD_WITHIN,
        ),
        "wz's subscriber never heard the second member without a cap, where libzenohc's did"
    );
    let by_wz = second_member_heard(
        "z_sub.c on wz-capi-c, max_sessions 1",
        &zsub.wz,
        &zpub.real,
        &capped_doc,
        KEPT_OUT_FOR,
    );
    assert_eq!(
        by_wz, by_real,
        "under max_sessions 1 wz's subscriber heard the second member ({by_wz}) where \
         libzenohc's did not"
    );
}
