// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

use wz_codegen_build::{
    oracle_store_root_in, sce_codegen_build_in, sce_codegen_provenance, sce_codegen_stamp,
    sce_codegen_store_entry, toolchain_channel, vendored_source_token, Provenance, SceCodegenBuild,
    SCE_CODEGEN_RECIPE,
};

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
    init_sce_fixture(dir.path());
    dir
}

/// [`sce_fixture`] at a directory the caller chose.
fn init_sce_fixture(p: &Path) {
    std::fs::create_dir_all(p).expect("mkdir fixture");
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

// ---------------------------------------------------------------------------
// The machine's oracle store. A build of a clean source state is kept there
// (scripts/build-sce.sh), and a consumer takes it only when the entry for the
// tree's state holds a binary stamped with that state; anything less leaves it
// on the checkout's build, which it grades as before.
// ---------------------------------------------------------------------------

/// A checkout whose recipe and toolchain a store entry's name reads: a
/// `scripts/build-sce.sh` of the given text and a `rust-toolchain.toml` naming
/// `channel`.
fn recipe_checkout(recipe: &str, channel: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let recipe_path = dir.path().join(SCE_CODEGEN_RECIPE);
    std::fs::create_dir_all(recipe_path.parent().expect("a directory")).expect("mkdir");
    std::fs::write(&recipe_path, recipe).expect("write recipe");
    std::fs::write(
        dir.path().join("rust-toolchain.toml"),
        format!("[toolchain]\nchannel = \"{channel}\"\n"),
    )
    .expect("write toolchain");
    dir
}

/// The source token of a fixture checkout, which has one.
fn token_of(sce_workspace: &Path) -> String {
    vendored_source_token(sce_workspace).expect("a fixture checkout has a token")
}

/// Fill a store entry the way `sce_codegen_store_publish` leaves it: the
/// binary, then the stamp naming `token`.
fn fill_entry(entry: &Path, token: &str) -> SceCodegenBuild {
    let build = SceCodegenBuild::in_dir(entry);
    std::fs::create_dir_all(entry).expect("mkdir entry");
    std::fs::write(&build.binary, b"#!/bin/sh\n").expect("write binary");
    std::fs::write(&build.stamp, format!("{token}\n")).expect("write stamp");
    build
}

/// The store is the variable's, else the cache home's, else the home's, and a
/// value that is empty or relative is passed over: the order of `store_root`
/// in scripts/lib/oracle_store.py and the rule of `sce_codegen_store_root`.
#[test]
fn the_store_is_the_variable_then_the_cache_home_then_the_home() {
    let base = std::env::temp_dir();
    let (s, x, h) = (base.join("s"), base.join("x"), base.join("h"));
    let (s, x, h) = (s.as_os_str(), x.as_os_str(), h.as_os_str());
    let store_in = |cache: &Path| cache.join("watching-zenoh").join("oracles");
    let home_store = store_in(&base.join("h").join(".cache"));

    assert_eq!(
        oracle_store_root_in(Some(s), Some(x), Some(h)),
        Some(base.join("s"))
    );
    assert_eq!(
        oracle_store_root_in(None, Some(x), Some(h)),
        Some(store_in(&base.join("x")))
    );
    assert_eq!(
        oracle_store_root_in(Some(OsStr::new("")), Some(OsStr::new("")), Some(h)),
        Some(home_store.clone()),
        "an empty value counts as unset"
    );
    assert_eq!(
        oracle_store_root_in(Some(OsStr::new("rel")), Some(OsStr::new("rel")), Some(h)),
        Some(home_store),
        "a relative value is passed over"
    );
    assert_eq!(
        oracle_store_root_in(None, None, Some(OsStr::new("rel"))),
        None
    );
    assert_eq!(oracle_store_root_in(None, None, None), None);
}

/// The toolchain is the name on the first `channel = "<name>"` line, and a
/// name that could leave the store's directory is no name.
#[test]
fn the_toolchain_is_the_first_channel_line_and_a_plain_name() {
    let checkout = recipe_checkout("recipe\n", "1.97.0");
    assert_eq!(
        toolchain_channel(checkout.path()).as_deref(),
        Some("1.97.0")
    );

    let file = checkout.path().join("rust-toolchain.toml");
    std::fs::write(&file, "channel = \"a\"\nchannel = \"b\"\n").expect("write");
    assert_eq!(toolchain_channel(checkout.path()).as_deref(), Some("a"));
    std::fs::write(&file, "channel = \"../up\"\n").expect("write");
    assert_eq!(
        toolchain_channel(checkout.path()),
        None,
        "a path is not a name"
    );
    std::fs::write(&file, "channel = \"\"\n").expect("write");
    assert_eq!(toolchain_channel(checkout.path()), None, "an empty name");
    std::fs::write(&file, "[toolchain]\n").expect("write");
    assert_eq!(toolchain_channel(checkout.path()), None, "no channel line");
    std::fs::remove_file(&file).expect("remove");
    assert_eq!(toolchain_channel(checkout.path()), None, "no file");
}

/// An entry that holds a build of the tree's state is what a consumer runs, and
/// its stamp grades Matches. The name carries the source token and ends with the
/// toolchain.
#[test]
fn an_entry_holding_the_build_of_this_state_is_what_a_consumer_runs() {
    let ws = sce_fixture();
    let checkout = recipe_checkout("recipe\n", "1.97.0");
    let store = tempfile::tempdir().expect("tempdir");
    let entry =
        sce_codegen_store_entry(store.path(), checkout.path(), ws.path()).expect("a store key");
    let token = token_of(ws.path());
    let base = store.path().join("sce-codegen");
    assert_eq!(entry.parent(), Some(base.as_path()));
    let name = entry.file_name().and_then(OsStr::to_str).expect("a name");
    assert!(
        name.starts_with(&format!("{token}-")),
        "{name} names another state"
    );
    assert!(
        name.ends_with("-1.97.0"),
        "{name} does not end with the toolchain"
    );

    let stored = fill_entry(&entry, &token);
    let taken = sce_codegen_build_in(Some(store.path()), checkout.path(), ws.path());
    assert_eq!(taken, stored);
    assert_eq!(taken.provenance(ws.path()), Provenance::Matches);
}

/// HALF-WRITTEN IS NOT TAKEN. A binary whose stamp is not there yet, a stamp
/// whose binary is not, and a stamp naming another state each leave the
/// consumer on the checkout's build, as does having no store at all.
#[test]
fn an_entry_that_does_not_hold_the_build_is_not_taken() {
    let ws = sce_fixture();
    let checkout = recipe_checkout("recipe\n", "1.97.0");
    let store = tempfile::tempdir().expect("tempdir");
    let entry =
        sce_codegen_store_entry(store.path(), checkout.path(), ws.path()).expect("a store key");
    let in_checkout = SceCodegenBuild::in_dir(&ws.path().join("target/release"));
    let taken = || sce_codegen_build_in(Some(store.path()), checkout.path(), ws.path());

    let stored = SceCodegenBuild::in_dir(&entry);
    std::fs::create_dir_all(&entry).expect("mkdir entry");
    std::fs::write(&stored.binary, b"#!/bin/sh\n").expect("write binary");
    assert_eq!(taken(), in_checkout, "a binary with no stamp yet was taken");

    std::fs::remove_file(&stored.binary).expect("remove binary");
    std::fs::write(&stored.stamp, format!("{}\n", token_of(ws.path()))).expect("write stamp");
    assert_eq!(taken(), in_checkout, "a stamp with no binary was taken");

    std::fs::write(&stored.binary, b"#!/bin/sh\n").expect("write binary");
    std::fs::write(
        &stored.stamp,
        "0000000000000000000000000000000000000000-1111111111111111111111111111111111111111\n",
    )
    .expect("write stamp");
    assert_eq!(
        taken(),
        in_checkout,
        "a stamp naming another state was taken"
    );

    assert_eq!(
        sce_codegen_build_in(None, checkout.path(), ws.path()),
        in_checkout,
        "with no store the checkout's build is the one"
    );
}

/// ANOTHER STATE IS ANOTHER ENTRY. An edit that leaves HEAD alone moves the
/// name, the old state's entry is not taken for the new one, and the build left
/// is refused, which is what sends `sce_codegen_ensure` to build again.
#[test]
fn another_source_state_is_another_entry_and_is_built_again() {
    let ws = sce_fixture();
    let checkout = recipe_checkout("recipe\n", "1.97.0");
    let store = tempfile::tempdir().expect("tempdir");
    let entry =
        || sce_codegen_store_entry(store.path(), checkout.path(), ws.path()).expect("a store key");
    let before = entry();
    fill_entry(&before, &token_of(ws.path()));

    std::fs::write(
        ws.path().join("NEW_TEMPLATE"),
        b"a template nobody committed\n",
    )
    .expect("add file");
    assert_ne!(entry(), before, "an edit must move the entry");
    let taken = sce_codegen_build_in(Some(store.path()), checkout.path(), ws.path());
    assert_eq!(
        taken,
        SceCodegenBuild::in_dir(&ws.path().join("target/release"))
    );
    assert!(
        matches!(
            taken.provenance(ws.path()),
            Provenance::Mismatch { have: None, .. }
        ),
        "the build left for an edited state must be refused"
    );
}

/// The recipe and the toolchain name the entry too: a binary built by another
/// build-sce.sh or with another compiler is never taken for this one, and a
/// checkout with no recipe names no entry.
#[test]
fn the_recipe_and_the_toolchain_name_the_entry_too() {
    let ws = sce_fixture();
    let store = tempfile::tempdir().expect("tempdir");
    let entry = |checkout: &Path| sce_codegen_store_entry(store.path(), checkout, ws.path());
    let one = recipe_checkout("recipe one\n", "1.97.0");
    let two = recipe_checkout("recipe two\n", "1.97.0");
    let newer = recipe_checkout("recipe one\n", "1.98.0");
    let same = recipe_checkout("recipe one\n", "1.97.0");

    assert!(entry(one.path()).is_some());
    assert_ne!(
        entry(one.path()),
        entry(two.path()),
        "the recipe is not in the name"
    );
    assert_ne!(
        entry(one.path()),
        entry(newer.path()),
        "the toolchain is not in the name"
    );
    assert_eq!(
        entry(one.path()),
        entry(same.path()),
        "one recipe, one name"
    );

    std::fs::remove_file(one.path().join(SCE_CODEGEN_RECIPE)).expect("remove recipe");
    assert_eq!(entry(one.path()), None, "no recipe, no name");
}

/// The shell door (`scripts/lib/sce-codegen-oracle.sh`) against this crate: one
/// entry, one binary, and `sce_codegen_ensure` building only when the store
/// does not hold the build. Linux only: the library leans on GNU coreutils
/// (`realpath -m`) and util-linux (`flock`), which is where the lanes that
/// source it run.
#[cfg(target_os = "linux")]
mod shell {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Output;
    use std::time::{Duration, SystemTime};

    use wz_codegen_build::checkout_root;

    /// Run `script` in bash, in `cwd`, with the shell door sourced and `store`
    /// as the oracle store; `args` are `$2` on.
    fn bash(
        cwd: &Path,
        store: &Path,
        script: &str,
        args: &[&OsStr],
        env: &[(&str, &OsStr)],
    ) -> Output {
        let mut cmd = Command::new("bash");
        cmd.arg("-c")
            .arg(format!("source \"$1\" && {script}"))
            .arg("bash")
            .arg(checkout_root().join("scripts/lib/sce-codegen-oracle.sh"))
            .args(args)
            .current_dir(cwd)
            .env("WZ_ORACLE_STORE", store)
            .env_remove("WZ_ARTIFACT_ROOT")
            .env_remove("WZ_SCE_ORACLE_REQUIRE");
        for (name, value) in env {
            cmd.env(name, value);
        }
        cmd.output().expect("spawn bash")
    }

    fn said(out: &Output) -> String {
        format!(
            "exit {:?}\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    fn printed_path(out: &Output) -> PathBuf {
        assert!(out.status.success(), "{}", said(out));
        PathBuf::from(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
    }

    fn executable(path: &Path) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    /// TWO CONSUMERS, ONE PATH. The shell names the entry this crate names, and
    /// what the shell publishes is the binary both doors then run.
    #[test]
    fn the_shell_door_names_and_takes_what_this_crate_does() {
        let ws = sce_fixture();
        let store = tempfile::tempdir().expect("tempdir");
        let scratch = tempfile::tempdir().expect("tempdir");
        let checkout = checkout_root();
        let entry =
            sce_codegen_store_entry(store.path(), &checkout, ws.path()).expect("a store key");

        let out = bash(
            ws.path(),
            store.path(),
            "sce_codegen_store_entry \"$2\"",
            &[ws.path().as_os_str()],
            &[],
        );
        assert_eq!(printed_path(&out), entry);

        let built = scratch.path().join("built");
        std::fs::write(&built, b"#!/bin/sh\n").expect("write binary");
        executable(&built);
        let token = token_of(ws.path());
        let out = bash(
            ws.path(),
            store.path(),
            "sce_codegen_store_publish \"$2\" \"$3\" \"$4\" && sce_codegen_binary \"$5\"",
            &[
                built.as_os_str(),
                entry.as_os_str(),
                OsStr::new(&token),
                ws.path().as_os_str(),
            ],
            &[],
        );
        let stored = SceCodegenBuild::in_dir(&entry);
        assert_eq!(printed_path(&out), stored.binary);
        assert_eq!(
            sce_codegen_build_in(Some(store.path()), &checkout, ws.path()),
            stored
        );
        let left: Vec<_> = std::fs::read_dir(&entry)
            .expect("read entry")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".part"))
            .collect();
        assert!(left.is_empty(), "the publisher left {left:?} behind");
    }

    /// A tree laid out the way `sce_codegen_ensure` reads one from its working
    /// directory: `vendor/sce` a fixture checkout, `scripts/build-sce.sh` a
    /// stand-in that records its run and publishes the entry it is handed, and a
    /// `cargo` on PATH so the build is not refused as unavailable.
    struct EnsureTree {
        root: tempfile::TempDir,
        store: tempfile::TempDir,
    }

    impl EnsureTree {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            init_sce_fixture(&root.path().join("vendor/sce"));
            let scripts = root.path().join("scripts");
            std::fs::create_dir_all(&scripts).expect("mkdir scripts");
            std::fs::write(
                scripts.join("build-sce.sh"),
                "set -eu\n\
                 : >\"$STAND_IN_MARKER\"\n\
                 mkdir -p \"$STAND_IN_ENTRY\"\n\
                 printf '#!/bin/sh\\n' >\"$STAND_IN_ENTRY/sce-codegen\"\n\
                 chmod 0755 \"$STAND_IN_ENTRY/sce-codegen\"\n\
                 printf '%s\\n' \"$STAND_IN_TOKEN\" >\"$STAND_IN_ENTRY/.sce-codegen.pin\"\n",
            )
            .expect("write the stand-in");
            let bin = root.path().join("bin");
            std::fs::create_dir_all(&bin).expect("mkdir bin");
            std::fs::write(bin.join("cargo"), "#!/bin/sh\nexit 0\n").expect("write cargo");
            executable(&bin.join("cargo"));
            Self {
                root,
                store: tempfile::tempdir().expect("tempdir"),
            }
        }

        fn ws(&self) -> PathBuf {
            self.root.path().join("vendor/sce")
        }

        fn marker(&self) -> PathBuf {
            self.root.path().join("built")
        }

        fn entry(&self) -> PathBuf {
            sce_codegen_store_entry(self.store.path(), &checkout_root(), &self.ws())
                .expect("a store key")
        }

        fn ensure(&self) -> Output {
            let path = std::env::join_paths(std::iter::once(self.root.path().join("bin")).chain(
                std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
            ))
            .expect("a PATH");
            let entry = self.entry();
            let token = token_of(&self.ws());
            let logs = self.root.path().join("logs");
            bash(
                self.root.path(),
                self.store.path(),
                "sce_codegen_ensure test",
                &[],
                &[
                    ("PATH", path.as_os_str()),
                    ("STAND_IN_ENTRY", entry.as_os_str()),
                    ("STAND_IN_TOKEN", OsStr::new(&token)),
                    ("STAND_IN_MARKER", self.marker().as_os_str()),
                    ("RUNCI_LOG_DIR", logs.as_os_str()),
                ],
            )
        }
    }

    /// A HIT BUILDS NOTHING. With the entry holding a build of the tree's state,
    /// ensure passes without running build-sce.sh and records the take.
    #[test]
    fn ensure_takes_a_held_build_and_builds_nothing() {
        let tree = EnsureTree::new();
        let stored = fill_entry(&tree.entry(), &token_of(&tree.ws()));
        executable(&stored.binary);

        let out = tree.ensure();
        assert!(out.status.success(), "{}", said(&out));
        assert!(
            !tree.marker().exists(),
            "a held build was built again: {}",
            said(&out)
        );
        assert!(
            tree.entry().join(".used").exists(),
            "the take was not recorded, so the entry would be pruned"
        );
    }

    /// A MISS BUILDS. A half-written entry and the entry of an edited state
    /// each make ensure run build-sce.sh, and what it then publishes is taken.
    #[test]
    fn ensure_builds_for_a_half_written_entry_and_for_another_state() {
        let tree = EnsureTree::new();
        let stored = SceCodegenBuild::in_dir(&tree.entry());
        std::fs::create_dir_all(tree.entry()).expect("mkdir entry");
        std::fs::write(&stored.binary, b"#!/bin/sh\n").expect("write binary");
        executable(&stored.binary);

        let out = tree.ensure();
        assert!(out.status.success(), "{}", said(&out));
        assert!(
            tree.marker().exists(),
            "a binary with no stamp was taken: {}",
            said(&out)
        );
        std::fs::remove_file(tree.marker()).expect("remove marker");

        std::fs::write(
            tree.ws().join("NEW_TEMPLATE"),
            b"a template nobody committed\n",
        )
        .expect("add file");
        let out = tree.ensure();
        assert!(out.status.success(), "{}", said(&out));
        assert!(
            tree.marker().exists(),
            "an edited state was not built: {}",
            said(&out)
        );
    }

    /// Pruning removes an entry nobody took for the window and nothing else: not
    /// one taken lately, not the entry being kept, not a directory whose name is
    /// not an entry's.
    #[test]
    fn prune_removes_only_an_entry_nobody_took_for_the_window() {
        let store = tempfile::tempdir().expect("tempdir");
        let base = store.path().join("sce-codegen");
        let name = |rev: &str| {
            format!(
                "{}-{}-{}-1.97.0",
                rev.repeat(40),
                "e".repeat(40),
                "f".repeat(40)
            )
        };
        let old = base.join(name("a"));
        let fresh = base.join(name("b"));
        let kept = base.join(name("c"));
        let other = base.join("not-an-entry");
        let month_ago = SystemTime::now() - Duration::from_secs(30 * 86_400);
        for dir in [&old, &fresh, &kept, &other] {
            std::fs::create_dir_all(dir).expect("mkdir");
            let used = std::fs::File::create(dir.join(".used")).expect("write .used");
            if *dir != fresh {
                used.set_modified(month_ago).expect("age .used");
            }
        }

        let out = bash(
            store.path(),
            store.path(),
            "sce_codegen_store_prune \"$2\"",
            &[kept.as_os_str()],
            &[],
        );
        assert!(out.status.success(), "{}", said(&out));
        assert!(!old.exists(), "an entry nobody took for a month was kept");
        assert!(fresh.exists(), "an entry taken lately was removed");
        assert!(kept.exists(), "the entry being kept was removed");
        assert!(
            other.exists(),
            "a directory that is not an entry was removed"
        );
    }
}
