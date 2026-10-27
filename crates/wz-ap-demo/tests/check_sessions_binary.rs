// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `--check-sessions <file>` reaches the BINARY: the verdict `--sessions` would
//! give on the same document, for the build that answers, and nothing started.
//!
//! # Why a process test
//!
//! The unit witnesses in `sessions.rs` judge a document, and they would all pass
//! if `main` never read the flag. The seam is argv -> exit status, and only
//! running the binary witnesses it. The cases below are the three answers the
//! flag gives (accepted 0, refused 2, unreadable 3), the one property that makes
//! it a check and not a start (a document that would listen exits at once and
//! prints no READY line), and that its refusals are the lines `--sessions` prints
//! for the same document, so a caller reads one vocabulary.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(20);

/// `(exit code, stderr)` of one run. A run that has not exited by the deadline
/// fails the test: a check that starts a session would never exit.
fn run(args: &[&str]) -> (Option<i32>, String) {
    let out = output(args);
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The whole output of one run, under [`run`]'s deadline.
fn output(args: &[&str]) -> std::process::Output {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let out = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
            .args(&args)
            .env("RUST_LOG", "info")
            .output()
            .expect("the demo binary runs");
        let _ = tx.send(out);
    });
    rx.recv_timeout(DEADLINE)
        .expect("the run did not exit, so it started what it was asked only to check")
}

/// A directory of this test's own, removed with it.
struct Dir(PathBuf);

impl Dir {
    fn new(case: &str) -> Dir {
        let path = std::env::temp_dir().join(format!(
            "wz-ap-demo-check-sessions-{case}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("a directory of this test's own");
        Dir(path)
    }

    fn write(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("the document is written");
        path.display().to_string()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A document the rules accept: a listener and a client. With `--sessions` this
/// would run until signalled.
const ACCEPTED: &str = r#"{
    zid: "a1b2c3d4",
    sessions: [
        { name: "inbound", mode: "peer", transport: "unicast", zid: "ee02",
          listen: { endpoints: ["tcp/127.0.0.1:0"] } },
        { name: "to_router", mode: "client", transport: "unicast", zid: "ee01",
          connect: { endpoints: ["tcp/127.0.0.1:7447"] } },
    ],
}"#;

/// The document the `--sessions` witness refuses: two sessions inheriting one
/// zid, a per-session limit an AP cannot apply, and `auto` for an interface.
const REFUSED: &str = r#"{
    zid: "a1b2c3d4",
    sessions: [
        { name: "to_router", mode: "client", transport: "unicast",
          connect: { endpoints: ["tcp/127.0.0.1:7447"] }, limits: { tx_queue: 4 } },
        { name: "listener", mode: "peer", transport: "unicast",
          listen: { endpoints: ["tcp/127.0.0.1:0"] } },
        { name: "group", mode: "peer", transport: "multicast",
          group: { endpoint: "udp/224.0.0.224:7446#iface=auto" } },
    ],
}"#;

/// An accepted document exits 0 at once, says how many sessions it holds, and
/// starts none of them.
#[test]
fn an_accepted_document_exits_zero_and_starts_nothing() {
    let dir = Dir::new("accepted");
    let path = dir.write("ok.json5", ACCEPTED);
    let (code, stderr) = run(&["--check-sessions", &path]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains(&format!("--check-sessions {path}: accepted, 2 session(s)")),
        "{stderr}"
    );
    assert!(
        !stderr.contains("wz-ap-demo session ") && !stderr.contains("READY"),
        "an accepted document started a session\n{stderr}"
    );
}

/// A refused document exits 2 with every refusal by its key path, and they are
/// the sentences `--sessions` prints for the same document.
#[test]
fn a_refused_document_exits_two_with_the_sessions_sentences() {
    let dir = Dir::new("refused");
    let path = dir.write("refused.json5", REFUSED);
    let (code, stderr) = run(&["--check-sessions", &path]);
    assert_eq!(code, Some(2), "{stderr}");
    for key in [
        "sessions[0].limits: ",
        "sessions[1].zid: sessions[1] (`listener`) and sessions[0] (`to_router`)",
        "sessions[2].group.endpoint: `auto` is not a word",
    ] {
        assert!(
            stderr.contains(&format!("--check-sessions {path}: {key}")),
            "missing {key:?}\n{stderr}"
        );
    }
    // The control: `--sessions` refuses the same document with the same
    // sentences after its own flag name, so the two read as one vocabulary. A
    // refused document starts nothing there either, so this run exits at once.
    let (code_start, stderr_start) = run(&["--sessions", &path]);
    assert_eq!(code_start, Some(2), "{stderr_start}");
    let sentences = |text: &str, flag: &str| -> Vec<String> {
        let marker = format!("{flag} {path}: ");
        text.lines()
            .filter_map(|l| l.split_once(&marker).map(|(_, rest)| rest.to_string()))
            .collect()
    };
    let checked = sentences(&stderr, "--check-sessions");
    assert_eq!(checked.len(), 3, "{stderr}");
    assert_eq!(checked, sentences(&stderr_start, "--sessions"));
}

/// `--device-requires` judges the document as `--check-sessions` does and, for an
/// accepted one, prints its requirement as one JSON line on stdout and starts
/// nothing: the listener and the dial of `ACCEPTED` are both required, with the
/// document the run reads.
#[test]
fn device_requires_answers_an_accepted_document_and_refuses_as_the_check() {
    let dir = Dir::new("device-requires");
    let path = dir.write("ok.json5", ACCEPTED);
    let out = output(&["--device-requires", &path]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "{\"requires\": [\"entropy\", \"filesystem\", \"sockets-tcp\", \"threads\"], \
         \"may_require\": [\"interface-list\", \"wall-clock\"], \"unknown\": []}\n"
    );
    assert!(
        !stderr.contains("wz-ap-demo session ") && !stderr.contains("READY"),
        "the answer started a session\n{stderr}"
    );
    let refused = dir.write("refused.json5", REFUSED);
    let out = output(&["--device-requires", &refused]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains(&format!(
        "--device-requires {refused}: sessions[0].limits: "
    )));
}

/// A file that cannot be read is a third answer, not a refusal of the document.
#[test]
fn an_unreadable_file_exits_three() {
    let dir = Dir::new("unreadable");
    let missing = dir.0.join("absent.json5").display().to_string();
    let (code, stderr) = run(&["--check-sessions", &missing]);
    assert_eq!(code, Some(3), "{stderr}");
    assert!(
        stderr.contains(&format!("--check-sessions: cannot read {missing}")),
        "{stderr}"
    );
}

/// The flag takes a file and nothing beside it, and a command line carrying both
/// document flags is refused rather than reading one of them.
#[test]
fn the_flag_stands_alone() {
    let dir = Dir::new("alone");
    let path = dir.write("ok.json5", ACCEPTED);
    let (code, stderr) = run(&["--check-sessions", &path, "--key", "demo/**"]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("takes no other argument (also given: --key demo/**)"),
        "{stderr}"
    );
    let (code, stderr) = run(&["--check-sessions"]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--check-sessions needs a file"), "{stderr}");
    let (code, stderr) = run(&["--sessions", &path, "--check-sessions", &path]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("(also given: --check-sessions "),
        "{stderr}"
    );
}
