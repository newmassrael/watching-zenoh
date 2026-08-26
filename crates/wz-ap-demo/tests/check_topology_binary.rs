// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// R2072 (open-debt item 496) — `--check-topology` reaches the BINARY.
//
// ## Why a process test and not another unit test
//
// The unit witnesses in `args::stock_config_tests` judge `check_topology`, and
// they would all still pass if `main` never called it. That is precisely the
// class open-debt item 479 names — code that can answer a question while no
// shipping surface asks it — and item 496 was that class's newest instance:
// R2070b shipped `validate_topology` with no caller outside its own tests.
// Closing 496 with a function that only unit tests reach would re-open it one
// layer up, so the seam that must be witnessed is argv -> exit status, and only
// running the binary witnesses that.
//
// Deterministic by construction: two small files on disk, no socket, no network
// name, no clock. The verdict is a property of the documents, so this test
// reproduces on a machine with nothing listening.

#![cfg(feature = "zenoh-config")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A router listening on a routable literal, and a peer that dials exactly it.
const RTR: &str = r#"{ id: "rtr", mode: "router", listen: { endpoints: ["tcp/10.0.0.9:7447"] } }"#;
const EDGE_TO_RTR: &str =
    r#"{ id: "edge", mode: "peer", connect: { endpoints: ["tcp/10.0.0.9:7447"] } }"#;
/// The same peer, one digit off — nothing in the set answers it.
const EDGE_TO_NOWHERE: &str =
    r#"{ id: "edge", mode: "peer", connect: { endpoints: ["tcp/10.0.0.8:7447"] } }"#;

/// A directory of this test's own, named after the case so two cases cannot
/// read each other's files, and removed on the way out.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(case: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("wz-check-topology-{}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp directory for this case");
        Fixture { dir }
    }

    fn write(&self, name: &str, source: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, source).expect("the fixture file");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(paths: &[&Path]) -> Output {
    run_with_external(paths, &[])
}

/// R2117 (open-debt item 498) — the same run, plus the listeners this
/// deployment does not manage.
fn run_with_external(paths: &[&Path], external: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"));
    for path in paths {
        cmd.arg("--check-topology").arg(path);
    }
    for endpoint in external {
        cmd.arg("--check-topology-external").arg(endpoint);
    }
    cmd.output().expect("the demo binary runs")
}

/// The binary answers a deployment that can work with 0, and the one-digit
/// variant that cannot with 2.
///
/// The pair is the whole point, and it is stated in ONE test so neither half
/// can be read without the other: a wiring that always exited 0 would pass the
/// first assertion, and one that always exited 2 would pass the second.
#[test]
fn the_binary_answers_a_working_deployment_with_zero_and_a_broken_one_with_two() {
    let fixture = Fixture::new("verdict");
    let rtr = fixture.write("rtr.json5", RTR);
    let good = fixture.write("edge-good.json5", EDGE_TO_RTR);
    let bad = fixture.write("edge-bad.json5", EDGE_TO_NOWHERE);

    let out = run(&[&rtr, &good]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "a router and the peer that dials it is a deployment that works: {stderr}"
    );
    assert!(
        stderr.contains("2 node(s) can form the network they describe"),
        "{stderr}"
    );

    let out = run(&[&rtr, &bad]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(2),
        "nothing here listens on 10.0.0.8: {stderr}"
    );
    assert!(
        stderr.contains(r#"edge connects to "tcp/10.0.0.8:7447""#),
        "{stderr}"
    );
    // And it started nothing on the way to saying so. A run that had opened a
    // session would have logged one, and the whole value of this flag is that
    // the answer costs no startup.
    assert!(!stderr.contains("Established"), "{stderr}");
}

/// A path the binary cannot open is named, and the remaining node is NOT judged
/// without it.
///
/// The absent file here is the router, so a binary that skipped it would report
/// a dangling dial about a deployment that is fine — three findings caused by a
/// typo in a path. The negative assertion is the one that carries this test.
#[test]
fn the_binary_names_a_file_it_cannot_open_rather_than_judging_the_rest() {
    let fixture = Fixture::new("unreadable");
    let edge = fixture.write("edge.json5", EDGE_TO_RTR);
    let absent = fixture.dir.join("rtr.json5");

    let out = run(&[&edge, &absent]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("cannot read"), "{stderr}");
    assert!(stderr.contains("rtr.json5"), "{stderr}");
    assert!(
        !stderr.contains("which no node here listens on"),
        "the set was judged without a file that could not be read: {stderr}"
    );
}

/// R2117 (open-debt item 498) — THE FRAGMENT REACHES THE BINARY, AND SO DOES
/// THE PRICE OF DECLARING ONE.
///
/// # Why this is a process test too
///
/// The unit witnesses in `zenoh_config` judge `validate_topology_with_external`
/// and would all still pass if `main`'s argv never carried the flag to it —
/// item 479's class, and the reason item 496 needed this file in the first
/// place. The seam is argv -> exit status.
///
/// # Why one test and not three
///
/// The three assertions are one claim: widening is USABLE and it is not FREE.
/// Split apart, a build that accepted the flag and ignored it would pass the
/// first, and one that reported every declaration would pass the third.
#[test]
fn the_binary_takes_a_declared_outside_listener_and_charges_for_a_stray_one() {
    let fixture = Fixture::new("external");
    // A peer dialling a router that is NOT among these files. Read as closed,
    // this is the state item 498 filed: a working deployment reported broken.
    let edge = fixture.write("edge.json5", EDGE_TO_RTR);

    let out = run(&[&edge]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(2),
        "the closed reading must still refuse a bare fragment: {stderr}"
    );

    // Declared, the same files are a deployment that works -- and the report
    // SAYS what it assumed rather than reading like a closed set.
    let out = run_with_external(&[&edge], &["tcp/10.0.0.9:7447"]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "a declared outside listener answers this dial: {stderr}"
    );
    assert!(
        stderr.contains("EXTERNAL edge -> \"tcp/10.0.0.9:7447\""),
        "a green verdict over a fragment must name its assumption: {stderr}"
    );

    // And a declaration nothing dials is charged for, so widening cannot
    // quietly silence the next typo.
    let out = run_with_external(&[&edge], &["tcp/10.0.0.9:7447", "tcp/10.0.0.7:7447"]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(r#""tcp/10.0.0.7:7447" was declared external"#),
        "the stray declaration must be named: {stderr}"
    );
}

/// R2117 (open-debt item 498) — the widening with no set to widen is refused
/// rather than ignored.
///
/// The rule this file's sibling flags already follow: an operator who typed a
/// flag and got the demo's ordinary startup instead has been told nothing.
#[test]
fn the_binary_refuses_a_declared_listener_with_no_deployment_to_check() {
    let out = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
        .arg("--check-topology-external")
        .arg("tcp/10.0.0.9:7447")
        .output()
        .expect("the demo binary runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("there is no set"),
        "the refusal must say what is missing: {stderr}"
    );
    assert!(!stderr.contains("Established"), "{stderr}");
}
