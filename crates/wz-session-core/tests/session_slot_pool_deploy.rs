// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The generated session-slot table says what the deploy file says (Round 3278).
//!
//! A deploy file's `session_pool:` names the SCE document whose `slot-count` is
//! MAX_SESSIONS and whose `slot-size` is the byte ceiling of one session slot
//! (`scripts/lib/deploy_sessions.py` documents the keys). SCE emits the two as
//! `session_slot_pool_mcu::SLOT_COUNT` / `SLOT_SIZE`, committed under `out/`.
//! This test closes the loop the deploy file and the generated file leave open
//! between them: it asks the validator's own report (the numbers an editor of
//! the deploy file shows) what the machine's table is, and requires every number
//! to be the one the generated constant holds. A deploy file edited to a table
//! the generated code does not have, a document edited and not regenerated, and
//! a report that misreads the document all fail here, each naming the number.
//!
//! The report is read by RUNNING the validator, so the test needs `python3` with
//! PyYAML on the host, exactly as `scripts/validate-deploy.sh` does. This crate's
//! tests also run where neither is a given (the macOS and Windows portability
//! legs run the whole crate), so what the test does about a host without them is
//! the repository's arming-flag rule, not a choice of its own:
//!
//! - the capability is MEASURED first, by asking `python3` to `import yaml`, so
//!   "cannot read the deploy file here" is told apart from every way the
//!   validator can fail once it runs (a refusal, a report that is not JSON, an
//!   input it could not read): those FAIL on every host, armed or not;
//! - a host that lacks it SKIPS, loudly (a line on stderr that libtest does not
//!   capture, naming what was missing), unless `WZ_DEPLOY_REPORT_REQUIRE` is set,
//!   when it FAILS: a comparison that could not read its input must not pass for
//!   one that matched, on the lane that is meant to run it;
//! - the lane that owns the capability arms it: Layer C1g, on the hosted Linux
//!   job that provides python3 and PyYAML. libtest prints a skip as `ok`, so the
//!   count guard there cannot tell a skip from a pass; the flag is what can.
//!
//! The decision is [`decide`], a function of two facts, with its own tests that
//! need no Python.
//!
//! Nothing in the crate uses the generated table yet. Host-test level: no board
//! runs it.

use std::ffi::OsStr;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use wz_session_core::session_slot_pool_mcu as generated;

/// The deploy file whose machine declares the table, and the machine.
const DEPLOY_FILE: &str = "deploy/mcu_client_and_group.yaml";
const MACHINE: &str = "mcu_node";

/// The arming flag: set, this test FAILS on a host that cannot read the deploy
/// file instead of skipping. [`required`] reads it under this exact name.
const FLAG: &str = "WZ_DEPLOY_REPORT_REQUIRE";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether this host can run the validator.
#[derive(Debug, PartialEq, Eq)]
enum Capability {
    Present,
    /// Why not, in the words of whatever refused.
    Absent(String),
}

/// What the test does about the capability.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Run,
    /// The comparison did not happen; the text is the notice.
    Skip(String),
    /// The comparison could not happen on a host that must run it.
    Fail(String),
}

/// The capability from the outcome of `python3 -c "import yaml"`: the exit code
/// and stderr of the run, or the error that stopped it from starting. Of a
/// traceback only its last line, the exception, goes into the reason.
fn capability(probe: std::io::Result<(Option<i32>, String)>) -> Capability {
    match probe {
        Ok((Some(0), _)) => Capability::Present,
        Ok((code, stderr)) => Capability::Absent(format!(
            "python3 cannot import yaml (PyYAML): `python3 -c \"import yaml\"` exited {code:?}: {}",
            stderr.trim().lines().last().unwrap_or("no output")
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Capability::Absent("python3 is not on PATH".to_string())
        }
        Err(e) => Capability::Absent(format!("python3 could not be started: {e}")),
    }
}

/// Armed when [`FLAG`] is set to anything but nothing or `0`: the reading the
/// repository's Python gates give their own flags.
fn armed(value: Option<&OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty() && v != "0")
}

/// The one decision: a host with the capability runs the comparison, one
/// without it fails if it is armed and skips, saying so, if it is not.
fn decide(capability: Capability, required: bool) -> Verdict {
    match (capability, required) {
        (Capability::Present, _) => Verdict::Run,
        (Capability::Absent(why), true) => Verdict::Fail(format!(
            "{FLAG} is set and the deploy file cannot be read here: {why}. The generated \
             session-slot table is compared with the deploy file through the validator and \
             there is no other reader, so a lane that armed this flag was asking for the \
             comparison, not for a skip"
        )),
        (Capability::Absent(why), false) => Verdict::Skip(format!(
            "{FLAG} is unset and the deploy file was not read, so the generated session-slot \
             table was not compared with it: {why}; set {FLAG}=1 to make that a failure"
        )),
    }
}

/// The validator's report as JSON, or why what it printed is not one. The
/// capability was measured before it ran, so EVERY failure here is a real one
/// and no flag softens it: a refusal (exit 1), an input it could not read (exit
/// 2, including its own "yaml module unavailable" after `import yaml` worked),
/// and output that is not JSON.
fn read_report(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> Result<Value, String> {
    if code != Some(0) {
        return Err(format!(
            "deploy_sessions.py --report exited {code:?} (0 is a machine with no refusal, 2 an input it could not read)\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(stdout),
            String::from_utf8_lossy(stderr),
        ));
    }
    serde_json::from_slice(stdout).map_err(|e| format!("the report is not JSON: {e}"))
}

/// Whether the arming flag is set. The read is on one line with the name, which
/// is the shape `scripts/lib/armed_skip_guard.py` recognises as a consumer; a
/// value that is not UTF-8 still arms (`var_os`, never `var().ok()`).
fn required() -> bool {
    armed(std::env::var_os("WZ_DEPLOY_REPORT_REQUIRE").as_deref())
}

/// The skip notice, written to the stderr handle itself: libtest drops what a
/// passing test `eprintln!`s, and a skip nobody can see is the silent pass the
/// flag exists to prevent. [`report`] also `eprintln!`s it, which is the spelling
/// `scripts/lib/silent_skip_gate.py` reads as a skip site, so a run with
/// `--nocapture` shows it twice.
fn announce(notice: &str) {
    let _ = writeln!(std::io::stderr(), "skip: {notice}");
}

/// The validator's report of [`MACHINE`], parsed, or `None` when this host
/// cannot read the deploy file and is not armed (a notice was printed). Panics
/// when it is armed and cannot, and on every failure of the validator itself.
fn report() -> Option<Value> {
    let probe = Command::new("python3")
        .args(["-c", "import yaml"])
        .output()
        .map(|o| {
            (
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        });
    match decide(capability(probe), required()) {
        Verdict::Run => {}
        Verdict::Skip(notice) => {
            announce(&notice);
            eprintln!("skip: {notice}");
            return None;
        }
        Verdict::Fail(why) => panic!("{why}"),
    }
    let root = repo_root();
    let output = Command::new("python3")
        .arg(root.join("scripts/lib/deploy_sessions.py"))
        .arg("--report")
        .arg(root.join(DEPLOY_FILE))
        .arg(MACHINE)
        .output()
        .expect("python3 ran a moment ago and must run the validator");
    match read_report(output.status.code(), &output.stdout, &output.stderr) {
        Ok(report) => Some(report),
        Err(why) => panic!("{why}"),
    }
}

/// Every way `report` disagrees with the generated constants, one line each; an
/// empty list is agreement.
fn drift(report: &Value) -> Vec<String> {
    let mut found = Vec::new();
    let pool = &report["pool"];
    if pool.is_null() {
        return vec![format!("machine {MACHINE} declares no session_pool")];
    }
    let mut expect = |what: &str, got: &Value, want: u64| {
        if got.as_u64() != Some(want) {
            found.push(format!(
                "{what}: the deploy file's table has {got}, the generated file {want}"
            ));
        }
    };
    expect(
        "max_sessions / SLOT_COUNT",
        &pool["max_sessions"],
        generated::SLOT_COUNT as u64,
    );
    expect(
        "slot_bytes / SLOT_SIZE",
        &pool["slot_bytes"],
        generated::SLOT_SIZE as u64,
    );
    expect(
        "total_bytes / SLOT_COUNT * SLOT_SIZE",
        &pool["total_bytes"],
        (generated::SLOT_COUNT * generated::SLOT_SIZE) as u64,
    );
    if pool["generated"] != Value::Bool(true) {
        found.push("the table is the inline form, which generates nothing".to_string());
    }
    found
}

/// The numbers of the deploy file's table ARE the generated constants.
#[test]
fn the_generated_table_holds_the_deploy_files_numbers() {
    let Some(report) = report() else { return };
    let found = drift(&report);
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// The comparison is not vacuous: each number changed on its own is named, so a
/// drift of any one of them is what fails the test above. The starting point is
/// built from the generated constants, not read from the deploy file, so this
/// control stays green when the deploy file and the generated file have drifted
/// apart (which is when the test above must be the one that is red).
#[test]
fn a_changed_number_is_named_by_the_comparison() {
    let slots = generated::SLOT_COUNT as u64;
    let size = generated::SLOT_SIZE as u64;
    let report = serde_json::json!({
        "pool": {
            "generated": true,
            "max_sessions": slots,
            "slot_bytes": size,
            "total_bytes": slots * size,
        }
    });
    assert!(drift(&report).is_empty(), "the constructed report agrees");
    for (key, name) in [
        ("max_sessions", "max_sessions / SLOT_COUNT"),
        ("slot_bytes", "slot_bytes / SLOT_SIZE"),
        ("total_bytes", "total_bytes / SLOT_COUNT * SLOT_SIZE"),
    ] {
        let mut changed = report.clone();
        let was = changed["pool"][key].as_u64().expect("a number");
        changed["pool"][key] = Value::from(was + 1);
        let found = drift(&changed);
        assert_eq!(
            found.len(),
            1,
            "{key} +1 must be one disagreement: {found:?}"
        );
        assert!(found[0].starts_with(name), "{key} +1 named {:?}", found[0]);
    }
    let mut inline = report.clone();
    inline["pool"]["generated"] = Value::Bool(false);
    assert_eq!(drift(&inline).len(), 1);
    let mut none = report;
    none["pool"] = Value::Null;
    assert_eq!(drift(&none).len(), 1);
}

/// The limits a peer's tables are bounded by (S9a) are the numbers the deploy file
/// states: each key the validator reports for the machine equals the constant the
/// table is compiled with, so an editor that raises `remote_decls` to 32 while the
/// code holds 16 is a red test and not a table that is silently smaller than the
/// file says.
#[test]
fn the_peer_table_limits_are_the_deploy_files_numbers() {
    use wz_session_core::caps;
    let Some(report) = report() else { return };
    let limits = &report["limits"];
    let mut drift = Vec::new();
    for (key, constant) in [
        ("peer_keyexpr_aliases", caps::MAX_PEER_KEYEXPR_ALIASES),
        ("remote_decls", caps::MAX_REMOTE_DECLS),
        ("pending_replies", caps::MAX_PENDING_REPLIES),
        ("pending_finals", caps::MAX_PENDING_FINALS),
        ("reply_payload_bytes", caps::MAX_REPLY_PAYLOAD_BYTES),
    ] {
        if limits[key].as_u64() != Some(constant as u64) {
            drift.push(format!(
                "limits.{key}: the deploy file states {}, the code is compiled with {constant}",
                limits[key]
            ));
        }
    }
    assert!(drift.is_empty(), "{}", drift.join("\n"));
}

/// The numbers the admin node's buffer and tables are compiled with (S9b) are the
/// deploy file's: the reply buffer, the locators a node reports and the links one
/// `sessions[]` row lists. (That the reply buffer is not larger than the reply
/// payload bound its replies are staged under is `caps.rs`'s own compile-time
/// assert, and the validator refuses the same order in a deploy file.)
#[test]
fn the_admin_limits_are_the_deploy_files_numbers() {
    use wz_session_core::caps;
    let Some(report) = report() else { return };
    let process = &report["process"];
    let mut drift = Vec::new();
    for (key, constant) in [
        ("admin_reply_bytes", caps::MAX_ADMIN_REPLY_BYTES),
        ("admin_locators", caps::MAX_ADMIN_LOCATORS),
        ("admin_session_links", caps::MAX_ADMIN_SESSION_LINKS),
    ] {
        if process[key].as_u64() != Some(constant as u64) {
            drift.push(format!(
                "session_pool.process.{key}: the deploy file states {}, the code is compiled with {constant}",
                process[key]
            ));
        }
    }
    assert!(drift.is_empty(), "{}", drift.join("\n"));
}

/// The numbers the shell's connect table and multicast reply queue are compiled with
/// (S9c) are the deploy file's: the rows of the connect table, which the list a
/// host writes is held in too, and the room of a multicast pump's reply queue.
#[test]
fn the_shell_limits_are_the_deploy_files_numbers() {
    use wz_session_core::caps;
    let Some(report) = report() else { return };
    let process = &report["process"];
    let mut drift = Vec::new();
    for (key, constant) in [
        ("connect_endpoints", caps::MAX_STATIC_CONNECT),
        ("multicast_replies", caps::MAX_MULTICAST_REPLIES),
    ] {
        if process[key].as_u64() != Some(constant as u64) {
            drift.push(format!(
                "session_pool.process.{key}: the deploy file states {}, the code is compiled with {constant}",
                process[key]
            ));
        }
    }
    assert!(drift.is_empty(), "{}", drift.join("\n"));
}

/// Every session the machine declares takes pools that fit the generated slot,
/// by the report's own sums and by this crate's constant, and the slot is a whole
/// number of the alignment SCE carries into the slot type.
#[test]
fn every_declared_session_fits_the_generated_slot() {
    let Some(report) = report() else { return };
    let sessions = report["sessions"].as_array().expect("sessions");
    assert!(!sessions.is_empty(), "the deploy file declares sessions");
    assert!(
        sessions.len() <= generated::SLOT_COUNT,
        "{} sessions declared, {} slots",
        sessions.len(),
        generated::SLOT_COUNT
    );
    for s in sessions {
        let bytes = s["pool_bytes"].as_u64().expect("pool_bytes");
        assert!(
            bytes <= generated::SLOT_SIZE as u64,
            "session {}: its pools take {bytes} bytes, the generated slot holds {}",
            s["name"],
            generated::SLOT_SIZE
        );
    }
    assert_eq!(generated::SLOT_SIZE % generated::ALIGNMENT as usize, 0);
}

// ---- the decision is held to its own witnesses, which need no Python ----------

/// The three ways a host can lack the capability, as `capability` is given them:
/// `import yaml` fails, `python3` is not there, `python3` cannot be started.
fn absent_hosts() -> Vec<(&'static str, Capability)> {
    use std::io::{Error, ErrorKind};
    vec![
        (
            "yaml missing",
            capability(Ok((
                Some(1),
                "Traceback (most recent call last):\n  File \"<string>\", line 1, in <module>\n\
                 ModuleNotFoundError: No module named 'yaml'\n"
                    .to_string(),
            ))),
        ),
        (
            "python3 absent",
            capability(Err(Error::from(ErrorKind::NotFound))),
        ),
        (
            "python3 not startable",
            capability(Err(Error::from(ErrorKind::PermissionDenied))),
        ),
        ("python3 killed", capability(Ok((None, String::new())))),
    ]
}

/// A host that lacks the capability skips when the flag is unset and FAILS when
/// it is set, and the text of each names the flag and what was missing, so the
/// skip is a line someone can act on and the failure says what the lane lost.
#[test]
fn a_host_that_cannot_read_the_deploy_file_skips_unarmed_and_fails_armed() {
    for (name, absent) in absent_hosts() {
        let Capability::Absent(why) = &absent else {
            panic!("{name}: the probe's failure is an absence");
        };
        let why = why.clone();
        assert!(!why.is_empty(), "{name}: the absence says why");
        match decide(absent, false) {
            Verdict::Skip(notice) => {
                assert!(notice.contains(FLAG), "{name}: the notice names the flag");
                assert!(notice.contains(&why), "{name}: it names {why:?}");
                assert_eq!(notice.lines().count(), 1, "{name}: the notice is one line");
            }
            other => panic!("{name} unarmed must skip, got {other:?}"),
        }
    }
    for (name, absent) in absent_hosts() {
        let Capability::Absent(why) = &absent else {
            unreachable!("checked above");
        };
        let why = why.clone();
        match decide(absent, true) {
            Verdict::Fail(message) => {
                assert!(message.contains(FLAG), "{name}: the failure names the flag");
                assert!(message.contains(&why), "{name}: it names {why:?}");
            }
            other => panic!("{name} armed must fail, got {other:?}"),
        }
    }
}

/// The capability is read from what the probe printed and nothing else: exit 0
/// is the only presence, and a host that has it runs the comparison armed or not.
#[test]
fn a_host_that_can_read_the_deploy_file_runs_armed_or_not() {
    assert_eq!(
        capability(Ok((Some(0), String::new()))),
        Capability::Present
    );
    assert_eq!(decide(Capability::Present, false), Verdict::Run);
    assert_eq!(decide(Capability::Present, true), Verdict::Run);
    for (name, absent) in absent_hosts() {
        assert_ne!(absent, Capability::Present, "{name} is not a presence");
    }
}

/// The flag arms on any value but nothing or `0`, so a flag exported as empty or
/// zero does not arm and `1` (what the lane sets) does.
#[test]
fn the_flag_arms_on_anything_but_nothing_or_zero() {
    assert!(!armed(None));
    assert!(!armed(Some(OsStr::new(""))));
    assert!(!armed(Some(OsStr::new("0"))));
    assert!(armed(Some(OsStr::new("1"))));
    assert!(armed(Some(OsStr::new("yes"))));
}

/// A failure of the validator ITSELF is not a missing capability: `read_report`
/// takes no flag, so none of these can be skipped on any host. Exit 2 with the
/// validator's own "yaml module unavailable" is among them on purpose: it comes
/// after `import yaml` worked, so it contradicts the probe and is a defect.
#[test]
fn a_real_failure_of_the_validator_fails_on_every_host() {
    let refusal = b"deploy_sessions: machine `mcu_node`: more sessions than slots\n";
    let unavailable = b"deploy_sessions: python3 yaml module unavailable\n";
    for (name, code, stdout, stderr) in [
        ("a refusal", Some(1), &b""[..], &refusal[..]),
        ("an unreadable input", Some(2), &b""[..], &unavailable[..]),
        ("a signal", None, &b""[..], &b""[..]),
        ("not JSON", Some(0), &b"not json"[..], &b""[..]),
        ("empty", Some(0), &b""[..], &b""[..]),
    ] {
        assert!(
            read_report(code, stdout, stderr).is_err(),
            "{name} must be an error"
        );
    }
    let report = read_report(Some(0), br#"{"pool": null}"#, b"").expect("a JSON report");
    assert!(report["pool"].is_null());
    let err = read_report(Some(1), b"", refusal).expect_err("a refusal");
    assert!(
        err.contains("more sessions than slots"),
        "the text is kept: {err}"
    );
}

/// The flag [`required`] reads is the one the notices name: the read is on a
/// line of its own with the name spelled out, which is also what
/// `scripts/lib/armed_skip_guard.py` looks for to count it a consumer.
#[test]
fn the_flag_is_read_under_the_name_the_notices_give() {
    let source = include_str!("session_slot_pool_deploy.rs");
    let read = format!("std::env::var_os(\"{FLAG}\")");
    assert_eq!(source.matches(&read).count(), 1, "one read of {FLAG}");
}
