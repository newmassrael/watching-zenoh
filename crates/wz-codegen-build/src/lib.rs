// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared build-script helper for watching-zenoh SCE codegen.
//!
//! R311in — one source for the two things every codegen build script
//! does: locate the vendored `sce-codegen` binary, and post-process its
//! emit so the generated file can be `include!`'d into a module scope.
//!
//! Two emit kinds:
//! - [`Codegen::emit_statechart`] — `sce:kind="statechart"` →
//!   `$OUT_DIR/{stem}_sm.rs`; strips the file-head `#![...]` inner
//!   attributes / `//!` inner doc comments (illegal mid-module; the
//!   consuming `pub mod` restores the lint allows as outer attributes).
//! - [`Codegen::emit_buffer_pool`] — `sce:kind="buffer-pool"` →
//!   `$OUT_DIR/{stem}.rs` (note: NOT `_sm.rs`); strips the inner
//!   attributes AND the trailing `#[cfg(test)] mod generated_tests`
//!   block (it constructs the pool inline — a multi-MiB stack allocation
//!   at large dims — and exercises SCE's §5.E DMA-pool API the wz
//!   dispatcher does not use; SCE's own CI covers those tests).
//!
//! The strip transforms are byte-identical to the per-build-script logic
//! they replace, so regenerated emits are unchanged.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate the vendored `sce-codegen` binary under `sce_workspace`
/// (`<sce_workspace>/target/release/sce-codegen[.exe]`), accounting for the
/// host executable suffix (`std::env::consts::EXE_SUFFIX` = `.exe` on Windows,
/// empty on Unix). Panics with the `build-sce.sh` directive if absent.
///
/// R311y20 — the SINGLE source of the sce-codegen binary path for EVERY wz
/// build script. The statechart [`Codegen::from_manifest`] AND the switchboard
/// `--emit-ast` build scripts (`wz-ap-demo-app`, `wz-switchboard-example`,
/// `deploy/mcu-noheap-probe`) all route through here, so the `EXE_SUFFIX` rule
/// — and any future path/lookup change — lives in one place rather than five
/// hand-copied blocks (R311y17 fixed only this crate's copy; the other three
/// still hardcoded the suffix-less path and would panic on Windows). Callers
/// emit their own `cargo:rerun-if-changed` on the returned path.
pub fn locate_sce_codegen(sce_workspace: &Path) -> PathBuf {
    let bin = sce_workspace
        .join("target/release")
        .join(format!("sce-codegen{}", std::env::consts::EXE_SUFFIX));
    if !bin.exists() {
        panic!(
            "sce-codegen binary not found at {}\n\
             run `scripts/build-sce.sh` from the wz workspace root to build it \
             (vendor pin: see vendor/sce HEAD).",
            bin.display()
        );
    }
    assert_sce_codegen_provenance(sce_workspace);
    bin
}

/// Path of the provenance stamp `scripts/build-sce.sh` writes beside the
/// binary. Named here rather than inlined because several callers read it.
pub fn sce_codegen_stamp(sce_workspace: &Path) -> PathBuf {
    sce_workspace.join("target/release/.sce-codegen.pin")
}

/// What the built `sce-codegen` was built from, relative to what this tree
/// pins. Returned rather than asserted so each caller can apply its own
/// policy: a build script panics, a test that cannot rebuild refuses, and a
/// first-clone ergonomics path may skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// The binary provably came from the pinned `vendor/sce` state.
    Matches,
    /// It came from something else — or carries no stamp at all, which is the
    /// same answer: its origin is not established.
    Mismatch {
        /// The token the binary carries, or `None` when it is unstamped.
        have: Option<String>,
        /// The token this tree's `vendor/sce` state produces.
        want: String,
    },
    /// git cannot answer here — a checkout with no `.git`, or no git on PATH.
    /// Not a failure by itself: a verdict that cannot be computed must not be
    /// invented in either direction.
    Unverifiable,
}

impl Provenance {
    /// The operator-facing account of a non-`Matches` verdict, worded once so
    /// every caller says the same thing and names the same remedy.
    pub fn explain(&self) -> String {
        match self {
            Self::Matches => "sce-codegen is the pinned build".to_owned(),
            Self::Unverifiable => {
                "sce-codegen provenance UNVERIFIABLE (no readable vendor/sce git checkout)"
                    .to_owned()
            }
            Self::Mismatch { have, want } => format!(
                "sce-codegen was built from a different vendor/sce state.\n\
                 \x20 built from: {}\n\
                 \x20 tree pins:  {want}\n\
                 run `scripts/build-sce.sh` from the wz workspace root.",
                have.as_deref()
                    .unwrap_or("<unstamped: predates the provenance gate>")
            ),
        }
    }
}

/// Grade the built `sce-codegen` against the `vendor/sce` state this tree
/// carries.
///
/// EXISTENCE IS NOT THE QUESTION. The binary is an untracked build product, so
/// it survives a pin bump, a branch switch and a rebase without changing, and
/// nothing about a stale one looks stale: it emits confidently from the
/// templates it was compiled against. MEASURED 2026-08-22 — a build host's
/// older binary met the templates of pin `6399fad49c` and reported
/// `unknown filter: filter host_invoker is unknown`, naming a template, a
/// filter and a line number, none of which was the defect. The sibling class is
/// R311y774/R311y776, where a feature was tested against a demo binary
/// predating it and the resulting red was attributed to a defect that did not
/// exist.
///
/// The token is recomputed with git alone so it is byte-identical to the shell
/// library's — see `scripts/lib/sce-codegen-oracle.sh` for the format and for
/// why the digest is a `git hash-object` rather than an md5.
pub fn sce_codegen_provenance(sce_workspace: &Path) -> Provenance {
    let want = match sce_source_token(sce_workspace) {
        Some(t) => t,
        None => return Provenance::Unverifiable,
    };
    let have = std::fs::read_to_string(sce_codegen_stamp(sce_workspace))
        .ok()
        .and_then(|s| s.lines().next().map(str::to_owned))
        .filter(|s| !s.is_empty());

    if have.as_deref() == Some(want.as_str()) {
        Provenance::Matches
    } else {
        Provenance::Mismatch { have, want }
    }
}

/// Refuse an `sce-codegen` that was built from a different `vendor/sce` state
/// than the one this tree carries.
///
/// EXISTENCE IS NOT THE QUESTION. The binary is an untracked build product, so
/// it survives a pin bump, a branch switch and a rebase without changing, and
/// nothing about a stale one looks stale: it emits confidently from the
/// templates it was compiled against. MEASURED 2026-08-22 — a build host's
/// older binary met the templates of pin `6399fad49c` and reported
/// `unknown filter: filter host_invoker is unknown`, naming a template, a
/// filter and a line number, none of which was the defect. The sibling class is
/// R311y774/R311y776, where a feature was tested against a demo binary
/// predating it and the resulting red was attributed to a defect that did not
/// exist.
///
/// This is the REFUSAL half of the gate, deliberately: it does not rebuild. A
/// build script that builds its own toolchain hides the cost inside an
/// unrelated `cargo build` and can recurse. The repair half lives in
/// `sce_codegen_ensure` (scripts/lib/sce-codegen-oracle.sh), which every wz
/// gate calls before reaching this path; what is left here is the last line of
/// defence for anything that arrives another way.
///
/// UNVERIFIABLE IS NOT A FAILURE by default: a checkout with no `.git` (a
/// source tarball) or a box with no `git` cannot be graded, so this warns and
/// proceeds rather than inventing a verdict. Set `WZ_SCE_ORACLE_REQUIRE=1` —
/// hosted CI does — to make that case a hard failure, where the submodule and
/// the toolchain are always present and their absence means a broken runner.
fn assert_sce_codegen_provenance(sce_workspace: &Path) {
    // Emitted before the verdict, not after: a rebuild of sce-codegen rewrites
    // the stamp, and this is what makes cargo re-run the build script — and so
    // re-ask the question — instead of replaying a cached emit from the binary
    // that has just been replaced.
    println!(
        "cargo:rerun-if-changed={}",
        sce_codegen_stamp(sce_workspace).display()
    );

    match sce_codegen_provenance(sce_workspace) {
        Provenance::Matches => {}
        Provenance::Unverifiable => {
            let msg = Provenance::Unverifiable.explain();
            assert!(
                std::env::var("WZ_SCE_ORACLE_REQUIRE").as_deref() != Ok("1"),
                "{msg} — WZ_SCE_ORACLE_REQUIRE=1 forbids proceeding"
            );
            println!("cargo:warning={msg}");
        }
        mismatch => panic!("{}", mismatch.explain()),
    }
}

/// The `<rev>-<digest>` token identifying the SCE source state a build of
/// `sce-codegen` would consume. `None` when git cannot answer.
///
/// Byte-for-byte the shell library's construction: `git status --porcelain`
/// sorted bytewise (what `LC_ALL=C sort` does), then `git diff HEAD` appended
/// raw, the pair fed to `git hash-object --stdin`. The two streams are both
/// needed — a status listing cannot see an edit that leaves the path list
/// unchanged, and a diff cannot see a new untracked template.
///
/// `target/` is excluded from both, for the reason spelled out in the shell
/// library: it holds the binary and the stamp, so counting it would make the
/// record change the thing it records and no stamp could ever match.
fn sce_source_token(sce_workspace: &Path) -> Option<String> {
    if !sce_workspace.join(".git").exists() {
        return None;
    }

    let rev_out = git_stdout(sce_workspace, &["rev-parse", "HEAD"])?;
    let rev = String::from_utf8(rev_out).ok()?.trim().to_owned();
    if rev.is_empty() {
        return None;
    }

    let status = git_stdout(
        sce_workspace,
        &["status", "--porcelain", "--", ".", ":(exclude)target"],
    )?;
    let mut lines: Vec<&[u8]> = status
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    lines.sort_unstable();

    let mut input: Vec<u8> = Vec::new();
    for line in lines {
        input.extend_from_slice(line);
        input.push(b'\n');
    }
    input.extend_from_slice(&git_stdout(
        sce_workspace,
        &["diff", "HEAD", "--", ".", ":(exclude)target"],
    )?);

    let digest = git_hash_object(sce_workspace, &input)?;
    Some(format!("{rev}-{digest}"))
}

/// Run `git <args>` in `dir`, returning stdout on success. `None` on any
/// failure — a missing git, a non-repository, a non-zero exit — because every
/// one of them means the same thing here: the question cannot be answered.
fn git_stdout(dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

fn git_hash_object(dir: &Path, input: &[u8]) -> Option<String> {
    use std::io::Write;

    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["hash-object", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(input).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let digest = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!digest.is_empty()).then_some(digest)
}

/// A located `sce-codegen` binary + its SCE workspace root, ready to
/// drive one or more emits into `$OUT_DIR`.
pub struct Codegen {
    sce_codegen: PathBuf,
    sce_workspace: PathBuf,
}

impl Codegen {
    /// Locate the vendored `sce-codegen` from a crate's manifest dir
    /// (`<manifest>/../../vendor/sce/target/release/sce-codegen`),
    /// panicking with the `build-sce.sh` directive if absent. Emits the
    /// binary's `rerun-if-changed` so a vendor/sce pin bump + rebuild
    /// re-triggers codegen even when the crate sources are unchanged.
    pub fn from_manifest(manifest_dir: &Path) -> Self {
        let sce_workspace = manifest_dir
            .join("../../vendor/sce")
            .canonicalize()
            .expect("canonicalize vendor/sce");

        let sce_codegen = locate_sce_codegen(&sce_workspace);
        println!("cargo:rerun-if-changed={}", sce_codegen.display());

        Self {
            sce_codegen,
            sce_workspace,
        }
    }

    /// Codegen one `sce:kind="statechart"` document into
    /// `$OUT_DIR/{stem}_sm.rs`, stripping inner attributes / inner doc
    /// comments. `resource_dir` is the directory holding `{stem}.scxml`
    /// (plus any `<sce:import>` siblings sce-codegen resolves relatively).
    pub fn emit_statechart(&self, stem: &str, resource_dir: &Path, out_dir: &Path) {
        self.run_generate(stem, resource_dir, out_dir);
        let emit_path = out_dir.join(format!("{stem}_sm.rs"));
        let original = read(&emit_path);
        let stripped = strip_inner_attrs(original.lines());
        write(&emit_path, &stripped);
    }

    /// Codegen one `sce:kind="buffer-pool"` document into
    /// `$OUT_DIR/{stem}.rs`, stripping inner attributes AND the trailing
    /// `generated_tests` module (see the module docs for why).
    pub fn emit_buffer_pool(&self, stem: &str, resource_dir: &Path, out_dir: &Path) {
        self.run_generate(stem, resource_dir, out_dir);
        let emit_path = out_dir.join(format!("{stem}.rs"));
        let original = read(&emit_path);
        let lines: Vec<&str> = original.lines().collect();
        let end = cut_generated_tests(&lines);
        let stripped = strip_inner_attrs(lines[..end].iter().copied());
        write(&emit_path, &stripped);
    }

    /// Allocator-free emit (`--no-std`): the buffer-pool / statechart
    /// templates use only `core::` types under this flag, so one emit
    /// serves both the std (AP) and heapless (MCU) runtimes.
    fn run_generate(&self, stem: &str, resource_dir: &Path, out_dir: &Path) {
        let scxml_path = resource_dir.join(format!("{stem}.scxml"));
        let status = Command::new(&self.sce_codegen)
            // R311y756 — the RESOURCE directories too, not only the root.
            //
            // `--workspace-root` tells sce-codegen where the workspace is; it
            // does NOT tell it where its Jinja2 templates and XSD schemas live,
            // and those are resolved separately against wherever the binary
            // thinks it was installed. On a build host every one of those
            // guesses missed and every emit died with `Cannot find Jinja2
            // templates`, taking Layers B2 and C1 with it — while the identical
            // tree passed here, which is the signature of a resolution that
            // depends on the machine rather than on the repository.
            //
            // The paths are derived from the workspace this struct already
            // holds, so nothing new has to be configured or kept in step. Set
            // rather than overridden: a caller with a reason to point elsewhere
            // keeps it.
            .env(
                "SCE_TEMPLATE_DIR",
                std::env::var_os("SCE_TEMPLATE_DIR").unwrap_or_else(|| {
                    self.sce_workspace
                        .join("tools")
                        .join("codegen")
                        .join("templates")
                        .into_os_string()
                }),
            )
            .env(
                "SCE_SCHEMAS_DIR",
                std::env::var_os("SCE_SCHEMAS_DIR")
                    .unwrap_or_else(|| self.sce_workspace.join("schemas").into_os_string()),
            )
            .arg("--workspace-root")
            .arg(&self.sce_workspace)
            .arg("generate")
            .arg("--language")
            .arg("rust")
            .arg("--no-std")
            .arg("--output-dir")
            .arg(out_dir)
            .arg(&scxml_path)
            .status()
            .unwrap_or_else(|e| panic!("invoke sce-codegen for {stem}: {e}"));

        if !status.success() {
            panic!("sce-codegen generate failed for {stem} (exit {status:?})");
        }
    }
}

/// Drop the trailing `#[cfg(test)] mod generated_tests { ... }` block —
/// returns the line index to truncate at (the block is the last in the
/// template, so this also drops everything after it). Cuts from the
/// leading `#[...]` attribute(s) above the `mod generated_tests` line.
fn cut_generated_tests(lines: &[&str]) -> usize {
    match lines
        .iter()
        .position(|l| l.trim_start().starts_with("mod generated_tests"))
    {
        Some(i) => {
            let mut start = i;
            while start > 0 && lines[start - 1].trim_start().starts_with("#[") {
                start -= 1;
            }
            start
        }
        None => lines.len(),
    }
}

/// Read a generated file, strip its file-head `#![...]` inner attributes +
/// `//!` inner doc comments (illegal once `include!`'d mid-module), and write
/// it back in place. R311y22e — the SINGLE shared strip for both the
/// statechart/pool emits in this crate AND the `xtask` switchboard `--emit-ast`
/// leg (the strip was duplicated in the xtask; the byte-faithfulness the
/// regen-diff gate relies on requires ONE strip predicate, not two that can
/// drift — the very shape R311y21 eliminated for the clock).
pub fn strip_inner_attrs_file(path: &Path) {
    let original = read(path);
    let stripped = strip_inner_attrs(original.lines());
    write(path, &stripped);
}

/// Strip file-head `#![...]` inner attributes and `//!` inner doc
/// comments — illegal once the emit is `include!`'d mid-module.
fn strip_inner_attrs<'a>(lines: impl Iterator<Item = &'a str>) -> String {
    lines
        .filter(|line| {
            let t = line.trim_start();
            !t.starts_with("#![") && !t.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()))
}
