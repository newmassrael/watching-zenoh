// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one door through which a Rust program of this tree runs `sce-codegen`.
//!
//! `sce-codegen` finds its workspace, its Jinja2 templates and its XSD schemas
//! by looking around the machine it runs on when it is not told, and each of
//! those guesses has missed on some build host while the same tree passed on
//! the machine it was written on. A spawn site that names only one of them, or
//! none, inherits whatever the machine answers. So every spawn goes through
//! [`SceCodegen`], which names all three, and `scripts/lib/sce_codegen_spawn_lint.py`
//! refuses a spawn written anywhere else. The shell twin of this door is
//! `sce_codegen_spawn` in `scripts/lib/sce-codegen-oracle.sh`.
//!
//! The XSD validation is the quiet half. When `sce-codegen` cannot find the
//! schema, or was built without the `xsd` feature, it prints a warning and
//! goes on to emit from a document whose `sce:` attributes nobody checked,
//! with exit status 0. A warning in a build log is not a verdict, so the door
//! refuses before the spawn when the schema is not where it is named, and
//! after the spawn when the generator says validation did not run.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The variable `sce-codegen` reads its Jinja2 template directory from.
pub const TEMPLATE_DIR_ENV: &str = "SCE_TEMPLATE_DIR";

/// The variable `sce-codegen` reads its XSD schema directory from.
pub const SCHEMAS_DIR_ENV: &str = "SCE_SCHEMAS_DIR";

/// The schema `sce-codegen` validates every document against, looked up in
/// the directory [`SCHEMAS_DIR_ENV`] names.
pub const XSD_SCHEMA_FILE: &str = "sce-forge.xsd";

/// What `sce-codegen` prints on stderr when it parsed a document without
/// validating it (`warn_if_not_validated` in SCE's `forge/xsd_validator.rs`).
/// The shell door carries the same text, and the spawn lint holds the two and
/// the generator's own wording to one another.
pub const XSD_NOT_VALIDATED: &str = "XSD schema validation did not run";

/// The three locations every spawn names: the SCE workspace, its template
/// directory and its schema directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SceResources {
    /// Passed as `--workspace-root`.
    pub workspace: PathBuf,
    /// Passed as [`TEMPLATE_DIR_ENV`].
    pub templates: PathBuf,
    /// Passed as [`SCHEMAS_DIR_ENV`].
    pub schemas: PathBuf,
}

impl SceResources {
    /// The locations for `workspace`, with the two directories taken from the
    /// given overrides where they are set and non-empty, and derived from the
    /// workspace otherwise. An empty value counts as unset, as `${VAR:-x}`
    /// does in the shell door, so both doors read one environment one way.
    pub fn resolve_in(
        workspace: &Path,
        templates: Option<&OsStr>,
        schemas: Option<&OsStr>,
    ) -> Self {
        let given = |v: Option<&OsStr>| v.filter(|v| !v.is_empty()).map(PathBuf::from);
        Self {
            workspace: workspace.to_path_buf(),
            templates: given(templates)
                .unwrap_or_else(|| workspace.join("tools").join("codegen").join("templates")),
            schemas: given(schemas).unwrap_or_else(|| workspace.join("schemas")),
        }
    }

    /// [`Self::resolve_in`] with the overrides read from this process's
    /// environment: a caller with a reason to point elsewhere still can.
    pub fn resolve(workspace: &Path) -> Self {
        Self::resolve_in(
            workspace,
            std::env::var_os(TEMPLATE_DIR_ENV).as_deref(),
            std::env::var_os(SCHEMAS_DIR_ENV).as_deref(),
        )
    }

    /// Where the schema the validation reads must be.
    pub fn schema_file(&self) -> PathBuf {
        self.schemas.join(XSD_SCHEMA_FILE)
    }

    /// Refuse a spawn whose named directories do not hold what it needs:
    /// without the templates every emit fails, and without the schema it
    /// succeeds unvalidated.
    pub fn check(&self) -> Result<(), SpawnRefusal> {
        if !self.templates.is_dir() {
            return Err(SpawnRefusal::NoTemplates(self.templates.clone()));
        }
        let schema = self.schema_file();
        if !schema.is_file() {
            return Err(SpawnRefusal::NoSchema(schema));
        }
        Ok(())
    }
}

/// Why a spawn of `sce-codegen` did not produce a validated result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnRefusal {
    /// The template directory the spawn would name does not exist.
    NoTemplates(PathBuf),
    /// The XSD schema is not where the spawn would name it.
    NoSchema(PathBuf),
    /// The binary could not be started.
    Spawn {
        /// The binary that was asked to run.
        binary: PathBuf,
        /// What the operating system said.
        error: String,
    },
    /// `sce-codegen` ran and exited unsuccessfully.
    Failed {
        /// The exit status as the platform prints it.
        status: String,
        /// Everything it wrote on stderr.
        stderr: String,
    },
    /// `sce-codegen` exited successfully without validating its input.
    NotValidated {
        /// Everything it wrote on stderr, the warning included.
        stderr: String,
    },
}

impl fmt::Display for SpawnRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTemplates(dir) => write!(
                f,
                "no sce-codegen template directory at {} (set {TEMPLATE_DIR_ENV} or init vendor/sce)",
                dir.display()
            ),
            Self::NoSchema(file) => write!(
                f,
                "no XSD schema at {}, so sce-codegen would emit without validating \
                 (set {SCHEMAS_DIR_ENV} or init vendor/sce)",
                file.display()
            ),
            Self::Spawn { binary, error } => {
                write!(f, "could not start {}: {error}", binary.display())
            }
            Self::Failed { status, stderr } => {
                write!(f, "sce-codegen failed ({status}):\n{stderr}")
            }
            Self::NotValidated { stderr } => write!(
                f,
                "sce-codegen exited successfully but did not validate against the XSD:\n{stderr}"
            ),
        }
    }
}

impl std::error::Error for SpawnRefusal {}

/// Judge a finished `sce-codegen` run: it must have succeeded, and it must
/// not have said that validation did not run.
pub fn judge(output: &Output) -> Result<(), SpawnRefusal> {
    judge_parts(output.status.success(), &output.status, &output.stderr)
}

fn judge_parts(
    success: bool,
    status: &dyn fmt::Display,
    stderr: &[u8],
) -> Result<(), SpawnRefusal> {
    let text = String::from_utf8_lossy(stderr);
    if !success {
        return Err(SpawnRefusal::Failed {
            status: status.to_string(),
            stderr: text.into_owned(),
        });
    }
    if text.contains(XSD_NOT_VALIDATED) {
        return Err(SpawnRefusal::NotValidated {
            stderr: text.into_owned(),
        });
    }
    Ok(())
}

/// A located `sce-codegen` and the locations it is run with.
#[derive(Debug, Clone)]
pub struct SceCodegen {
    bin: PathBuf,
    resources: SceResources,
}

impl SceCodegen {
    /// The vendored binary of `sce_workspace`, refusing an absent or foreign
    /// build by panicking with the `build-sce.sh` directive: what a build
    /// script or the codegen task wants.
    pub fn locate(sce_workspace: &Path) -> Self {
        Self::at(crate::locate_sce_codegen(sce_workspace), sce_workspace)
    }

    /// The vendored binary of `sce_workspace` when it is built, or the path it
    /// was looked for at. Its provenance is NOT graded here: a caller that may
    /// skip on an absent binary still has to refuse a foreign one, through
    /// [`crate::sce_codegen_provenance`].
    pub fn find(sce_workspace: &Path) -> Result<Self, PathBuf> {
        let bin = crate::sce_codegen_binary(sce_workspace);
        if bin.exists() {
            Ok(Self::at(bin, sce_workspace))
        } else {
            Err(bin)
        }
    }

    fn at(bin: PathBuf, sce_workspace: &Path) -> Self {
        Self {
            bin,
            resources: SceResources::resolve(sce_workspace),
        }
    }

    /// The binary this runs.
    pub fn binary(&self) -> &Path {
        &self.bin
    }

    /// The locations it is run with.
    pub fn resources(&self) -> &SceResources {
        &self.resources
    }

    /// Run `sce-codegen <args>` with its standard output passed through and
    /// its standard error relayed to this process's, then judged by [`judge`].
    pub fn run<I, S>(&self, args: I) -> Result<(), SpawnRefusal>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.run_with(args, |cmd| {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::piped()).output()
        })?;
        // A warning that does not refuse the run is still the generator's to
        // say; relayed only on success because a refusal carries it already.
        let _ = io::stderr().write_all(&output.stderr);
        Ok(())
    }

    /// Run `sce-codegen <args>` through `runner`, which starts the configured
    /// command and collects its output however the caller must (a test bounds
    /// it in time), then judge the output by [`judge`].
    pub fn run_with<I, S, R>(&self, args: I, runner: R) -> Result<Output, SpawnRefusal>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
        R: FnOnce(&mut Command) -> io::Result<Output>,
    {
        let mut cmd = self.command()?;
        cmd.args(args);
        let output = runner(&mut cmd).map_err(|e| SpawnRefusal::Spawn {
            binary: self.bin.clone(),
            error: e.to_string(),
        })?;
        judge(&output)?;
        Ok(output)
    }

    /// The command with all three locations named and no subcommand yet.
    fn command(&self) -> Result<Command, SpawnRefusal> {
        self.resources.check()?;
        let mut cmd = Command::new(&self.bin);
        cmd.env(TEMPLATE_DIR_ENV, &self.resources.templates)
            .env(SCHEMAS_DIR_ENV, &self.resources.schemas)
            .arg("--workspace-root")
            .arg(&self.resources.workspace);
        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A workspace holding the template directory and the schema.
    fn complete_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("tools/codegen/templates")).expect("templates");
        std::fs::create_dir_all(dir.path().join("schemas")).expect("schemas");
        std::fs::write(
            dir.path().join("schemas").join(XSD_SCHEMA_FILE),
            "<xs:schema/>",
        )
        .expect("schema");
        dir
    }

    fn codegen_in(workspace: &Path) -> SceCodegen {
        SceCodegen {
            bin: workspace.join("bin/sce-codegen"),
            resources: SceResources::resolve_in(workspace, None, None),
        }
    }

    #[test]
    fn unset_overrides_derive_both_directories_from_the_workspace() {
        let ws = Path::new("/ws");
        let r = SceResources::resolve_in(ws, None, None);
        assert_eq!(r.workspace, PathBuf::from("/ws"));
        assert_eq!(r.templates, PathBuf::from("/ws/tools/codegen/templates"));
        assert_eq!(r.schemas, PathBuf::from("/ws/schemas"));
        assert_eq!(r.schema_file(), PathBuf::from("/ws/schemas/sce-forge.xsd"));
    }

    #[test]
    fn a_set_override_wins_and_an_empty_one_counts_as_unset() {
        let ws = Path::new("/ws");
        let r = SceResources::resolve_in(ws, Some(OsStr::new("/t")), Some(OsStr::new("")));
        assert_eq!(r.templates, PathBuf::from("/t"));
        assert_eq!(r.schemas, PathBuf::from("/ws/schemas"));
        let r = SceResources::resolve_in(ws, Some(OsStr::new("")), Some(OsStr::new("/s")));
        assert_eq!(r.templates, PathBuf::from("/ws/tools/codegen/templates"));
        assert_eq!(r.schemas, PathBuf::from("/s"));
    }

    #[test]
    fn a_complete_workspace_passes_the_check() {
        let dir = complete_workspace();
        assert_eq!(
            SceResources::resolve_in(dir.path(), None, None).check(),
            Ok(())
        );
    }

    #[test]
    fn a_missing_template_directory_is_refused() {
        let dir = complete_workspace();
        std::fs::remove_dir_all(dir.path().join("tools")).expect("remove templates");
        assert_eq!(
            SceResources::resolve_in(dir.path(), None, None).check(),
            Err(SpawnRefusal::NoTemplates(
                dir.path().join("tools/codegen/templates")
            ))
        );
    }

    #[test]
    fn a_schema_directory_without_the_schema_is_refused() {
        let dir = complete_workspace();
        std::fs::remove_file(dir.path().join("schemas").join(XSD_SCHEMA_FILE))
            .expect("remove schema");
        assert_eq!(
            SceResources::resolve_in(dir.path(), None, None).check(),
            Err(SpawnRefusal::NoSchema(
                dir.path().join("schemas").join(XSD_SCHEMA_FILE)
            ))
        );
    }

    #[test]
    fn the_command_names_all_three_locations_before_any_argument() {
        let dir = complete_workspace();
        let codegen = codegen_in(dir.path());
        let cmd = codegen
            .command()
            .expect("a complete workspace is not refused");
        assert_eq!(
            cmd.get_program(),
            dir.path().join("bin/sce-codegen").as_os_str()
        );
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            vec![OsStr::new("--workspace-root"), dir.path().as_os_str()]
        );
        let templates = dir.path().join("tools/codegen/templates");
        let schemas = dir.path().join("schemas");
        let envs: Vec<(&OsStr, Option<&OsStr>)> = cmd.get_envs().collect();
        assert!(envs.contains(&(OsStr::new(TEMPLATE_DIR_ENV), Some(templates.as_os_str()))));
        assert!(envs.contains(&(OsStr::new(SCHEMAS_DIR_ENV), Some(schemas.as_os_str()))));
    }

    #[test]
    fn no_command_is_made_when_the_schema_is_missing() {
        let dir = complete_workspace();
        std::fs::remove_file(dir.path().join("schemas").join(XSD_SCHEMA_FILE))
            .expect("remove schema");
        let refused = codegen_in(dir.path()).run_with(["generate"], |_| {
            unreachable!("a refused spawn must not start")
        });
        assert!(matches!(refused, Err(SpawnRefusal::NoSchema(_))));
    }

    #[test]
    fn a_binary_that_cannot_start_is_a_spawn_refusal() {
        let dir = complete_workspace();
        let refused = codegen_in(dir.path()).run_with(["generate"], |cmd| cmd.output());
        assert!(matches!(refused, Err(SpawnRefusal::Spawn { .. })));
    }

    #[test]
    fn a_clean_success_is_accepted() {
        assert_eq!(
            judge_parts(true, &"exit status: 0", b"emitted 3 files\n"),
            Ok(())
        );
    }

    #[test]
    fn a_success_that_says_validation_did_not_run_is_refused() {
        let stderr = "warning: XSD schema validation did not run -- schemas/sce-forge.xsd \
                      not found. Documents are parsed structurally.\n";
        assert_eq!(
            judge_parts(true, &"exit status: 0", stderr.as_bytes()),
            Err(SpawnRefusal::NotValidated {
                stderr: stderr.to_owned()
            })
        );
    }

    #[test]
    fn a_failure_is_refused_with_its_status_and_stderr() {
        assert_eq!(
            judge_parts(false, &"exit status: 3", b"Cannot find Jinja2 templates\n"),
            Err(SpawnRefusal::Failed {
                status: "exit status: 3".to_owned(),
                stderr: "Cannot find Jinja2 templates\n".to_owned(),
            })
        );
    }
}
