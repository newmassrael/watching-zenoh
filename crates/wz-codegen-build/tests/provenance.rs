// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Witnesses for the sce-codegen provenance verdict.
//!
//! The gate exists because a stale `sce-codegen` does not report "stale" — it
//! emits confidently from the templates it was built against, and the resulting
//! red names something else entirely. So the thing that must be proven here is
//! not that a correct binary passes; it is that each WRONG state is separated
//! from the right one, and in particular that the two cheaper questions this
//! replaced (does it exist, is it newer) cannot produce these verdicts.
//!
//! Every fixture is a real git repository, because the token is defined by what
//! git says and a hand-built fake would be a second implementation drifting
//! from the first.

use std::path::Path;
use std::process::Command;

use wz_codegen_build::{sce_codegen_provenance, sce_codegen_stamp, Provenance};

/// Run git in `dir`, asserting success — a fixture that half-built is worse
/// than one that failed loudly.
fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A fixture SCE checkout: an initialised repository with one commit, and the
/// `target/release` directory the stamp lives in. No stamp is written.
fn sce_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path();
    git(p, &["init", "--quiet"]);
    std::fs::write(p.join("README"), b"fixture\n").expect("write README");
    git(p, &["add", "README"]);
    git(
        p,
        &[
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "user.name=fixture",
            "commit",
            "--quiet",
            "-m",
            "seed",
        ],
    );
    std::fs::create_dir_all(p.join("target/release")).expect("mkdir target/release");
    dir
}

fn want_of(verdict: &Provenance) -> String {
    match verdict {
        Provenance::Mismatch { want, .. } => want.clone(),
        other => panic!("expected a Mismatch carrying the wanted token, got {other:?}"),
    }
}

/// No git checkout at all is UNVERIFIABLE, and specifically not a Mismatch.
/// The distinction is the whole reason the enum has three arms: a source
/// tarball cannot be graded, and inventing either verdict for it would be a
/// claim about evidence that does not exist.
#[test]
fn a_directory_without_git_is_unverifiable() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("target/release")).expect("mkdir");
    assert_eq!(
        sce_codegen_provenance(dir.path()),
        Provenance::Unverifiable,
        "a checkout with no .git must not be graded"
    );
}

/// An UNSTAMPED binary is a Mismatch, not a pass. This is the case every
/// binary built before the gate landed is in, and it is exactly the state the
/// old existence test called fine.
#[test]
fn an_unstamped_build_does_not_pass() {
    let dir = sce_fixture();
    match sce_codegen_provenance(dir.path()) {
        Provenance::Mismatch { have, want } => {
            assert_eq!(have, None, "nothing was stamped, so nothing is claimed");
            assert!(
                !want.is_empty(),
                "the wanted token must still be computable"
            );
        }
        other => panic!("an unstamped build must not pass: {other:?}"),
    }
}

/// A stamp from another revision is refused, and the verdict carries BOTH
/// tokens — the operator's first question after "it is stale" is "stale
/// against what", and a message that cannot answer it sends them to git log.
#[test]
fn a_foreign_stamp_is_refused_and_names_both_sides() {
    let dir = sce_fixture();
    let foreign =
        "0000000000000000000000000000000000000000-1111111111111111111111111111111111111111";
    std::fs::write(sce_codegen_stamp(dir.path()), format!("{foreign}\n")).expect("write stamp");

    match sce_codegen_provenance(dir.path()) {
        Provenance::Mismatch { have, want } => {
            assert_eq!(have.as_deref(), Some(foreign));
            assert_ne!(want, foreign);
            let text = Provenance::Mismatch {
                have: Some(foreign.to_owned()),
                want,
            }
            .explain();
            assert!(
                text.contains(foreign),
                "the message must name what was built"
            );
            assert!(
                text.contains("scripts/build-sce.sh"),
                "the message must name the one command that repairs it"
            );
        }
        other => panic!("a foreign stamp must be refused: {other:?}"),
    }
}

/// The round trip: stamping with the token the tree produces is what makes the
/// verdict Matches. This is the only state `build-sce.sh` can leave behind.
///
/// It is also the test that caught the gate's first real defect. The stamp
/// lives under `target/`, INSIDE the checkout being graded, so while the token
/// counted `target/` the act of writing the stamp made the checkout dirty and
/// moved the token out from under itself — `have` and `want` differed by their
/// digest on a checkout nothing else had touched, and the verdict could never
/// be `Matches`. Real vendor/sce gitignores `target/` and hid it; this fixture
/// does not, which is why it is built without one.
#[test]
fn the_tokens_the_tree_produces_are_what_pass() {
    let dir = sce_fixture();
    let want = want_of(&sce_codegen_provenance(dir.path()));
    std::fs::write(sce_codegen_stamp(dir.path()), format!("{want}\n")).expect("write stamp");
    assert_eq!(sce_codegen_provenance(dir.path()), Provenance::Matches);
}

/// THE RECORD MUST NOT MOVE THE THING IT RECORDS.
///
/// Stated separately from the round trip above, because the round trip proves
/// the pair agrees once and this proves WHY it can: nothing a build writes
/// under `target/` — the stamp, the binary, an incremental cache — is part of
/// the source state that determines the binary. If any of it counted, the token
/// would be a function of its own output and no consumer could ever settle.
#[test]
fn build_output_under_target_is_not_part_of_the_token() {
    let dir = sce_fixture();
    let before = want_of(&sce_codegen_provenance(dir.path()));

    std::fs::write(sce_codegen_stamp(dir.path()), "irrelevant\n").expect("write stamp");
    std::fs::write(
        dir.path().join("target/release/sce-codegen"),
        b"\x7fELF-ish",
    )
    .expect("write a binary");
    std::fs::create_dir_all(dir.path().join("target/debug/incremental")).expect("mkdir");

    assert_eq!(
        want_of(&sce_codegen_provenance(dir.path())),
        before,
        "writing build output must leave the source token untouched"
    );
}

/// THE DISCRIMINATOR AGAINST A REV-ONLY TOKEN.
///
/// `vendor/sce` is a working checkout, so an edit to a template changes what
/// the binary must be while HEAD does not move. A token that was just the
/// revision — and equally, R114's mtime comparison, and the plain existence
/// test before it — reports this state as fine. Both edits below leave HEAD
/// alone, and each must change the token: a MODIFIED tracked file, and a NEW
/// untracked one, because `git diff HEAD` is blind to the second and a path
/// listing alone is blind to the first.
#[test]
fn an_edit_that_leaves_head_alone_still_moves_the_token() {
    let dir = sce_fixture();
    let p = dir.path();
    let head = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(p)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("spawn git")
            .stdout,
    )
    .expect("utf8");
    let head = head.trim().to_owned();

    let clean = want_of(&sce_codegen_provenance(p));

    std::fs::write(p.join("README"), b"fixture, edited\n").expect("edit README");
    let modified = want_of(&sce_codegen_provenance(p));

    std::fs::write(p.join("NEW_TEMPLATE"), b"a template nobody committed\n").expect("add file");
    let untracked = want_of(&sce_codegen_provenance(p));

    for (label, token) in [
        ("clean", &clean),
        ("modified", &modified),
        ("untracked", &untracked),
    ] {
        assert!(
            token.starts_with(&head),
            "{label}: HEAD did not move, so every token must still carry it"
        );
    }
    assert_ne!(
        clean, modified,
        "a modified tracked file must move the token"
    );
    assert_ne!(
        modified, untracked,
        "a new untracked file must move the token too"
    );
}
