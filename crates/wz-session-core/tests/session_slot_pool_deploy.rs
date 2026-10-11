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
//! PyYAML on the host, exactly as `scripts/validate-deploy.sh` does. A host
//! without them FAILS the test: a comparison that could not read its input must
//! not pass for one that matched.
//!
//! Nothing in the crate uses the generated table yet. Host-test level: no board
//! runs it.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use wz_session_core::session_slot_pool_mcu as generated;

/// The deploy file whose machine declares the table, and the machine.
const DEPLOY_FILE: &str = "deploy/mcu_client_and_group.yaml";
const MACHINE: &str = "mcu_node";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The validator's report of [`MACHINE`], parsed. Panics, never skips, when the
/// validator cannot run or prints something that is not JSON.
fn report() -> Value {
    let root = repo_root();
    let output = Command::new("python3")
        .arg(root.join("scripts/lib/deploy_sessions.py"))
        .arg("--report")
        .arg(root.join(DEPLOY_FILE))
        .arg(MACHINE)
        .output()
        .expect(
            "python3 must be on PATH: the deploy validator is how this test reads the deploy file",
        );
    assert!(
        output.status.code() == Some(0),
        "deploy_sessions.py --report exited {:?} (0 is a machine with no refusal, 2 an input it could not read)\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("the report is JSON")
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
    let report = report();
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

/// Every session the machine declares takes pools that fit the generated slot,
/// by the report's own sums and by this crate's constant, and the slot is a whole
/// number of the alignment SCE carries into the slot type.
#[test]
fn every_declared_session_fits_the_generated_slot() {
    let report = report();
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
