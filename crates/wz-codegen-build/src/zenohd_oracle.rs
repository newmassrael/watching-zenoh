// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The reference `zenohd` router the interop tests drive, held to the version
//! this tree pins.
//!
//! `WZ_ZENOHD_BIN` names any path. `scripts/lib/oracle_pin_gate.py` grades only
//! the binaries `scripts/build-zenohd.sh` installs, so a lane pointed at another
//! build on the same machine (an older `debug/` beside a pinned `release/`, a
//! `cargo install` of another version) grades wz against a router this tree no
//! longer targets, and nothing says so: the older router still completes the
//! handshake and still routes, and a divergence reads as a wz defect. The
//! population that matters is the binary a lane actually runs, so the question
//! is asked where that binary is handed out: [`zenohd_binary`] asks it for its
//! version and refuses one off the pin.
//!
//! The pin is read from the build script's `ZENOHD_VERSION` default, the number
//! the gate reads, so there is one number and not a copy of it. The parse is
//! the gate's own (`PIN_RE` and `VERSION_RE` in `oracle_pin_gate.py`): the
//! version token is not assumed to be semver, because a router built from an
//! untagged checkout reports a commit hash there and that is a version this
//! tree does not pin either.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::{artifact, checkout_root};

/// The variable a lane names its reference router with.
pub const ZENOHD_BIN_ENV: &str = "WZ_ZENOHD_BIN";

/// The script whose `ZENOHD_VERSION` default is the pin, relative to the checkout.
pub const ZENOHD_BUILD_SCRIPT: &str = "scripts/build-zenohd.sh";

/// The line of the build script that carries the pin, up to the version.
const PIN_PREFIX: &str = "ZENOHD_VERSION=\"${ZENOHD_VERSION:-";

/// What `zenohd --version` prints in front of the version token.
const VERSION_MARK: &str = "zenohd v";

/// How long `zenohd --version` may take. It answers at once; this bounds a
/// binary that is not a zenohd at all and waits on its input or the network,
/// which `oracle_pin_gate.py` bounds the same way.
const VERSION_BUDGET: Duration = Duration::from_secs(60);

/// How often the version run is looked at while it has not ended.
const VERSION_POLL: Duration = Duration::from_millis(10);

/// What a router binary is, relative to the version this tree pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZenohdPinVerdict {
    /// The binary answers with the pinned version.
    Match,
    /// The binary answers with another version.
    OffPin {
        /// The version the binary reports.
        have: String,
        /// The version the build script pins.
        want: String,
    },
    /// The binary would not say which version it is: it did not run, did not
    /// end within its budget, or printed no `zenohd v...` line. Unknown is not
    /// a match.
    Unreadable {
        /// What happened instead of an answer.
        why: String,
    },
    /// The pin itself could not be read, so there is nothing to compare with.
    PinUnknown {
        /// Why the build script gave no pin.
        why: String,
    },
}

/// The `ZENOHD_VERSION` default of a build script's text, the first one in it,
/// as `oracle_pin_gate.py` reads it: `ZENOHD_VERSION="${ZENOHD_VERSION:-<pin>}"`
/// at the start of a line after any indentation. `None` when no line has that
/// shape or the pin in it is empty.
pub fn zenohd_pin_in(script: &str) -> Option<String> {
    script.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix(PIN_PREFIX)?;
        let (pin, tail) = rest.split_once('}')?;
        if !tail.starts_with('"') || pin.contains('"') {
            return None;
        }
        let pin = pin.trim();
        (!pin.is_empty()).then(|| pin.to_owned())
    })
}

/// The version token of `zenohd --version` output: the non-blank run that
/// follows the first `zenohd v` not preceded by a word character. `None` when
/// the output has no such token.
pub fn zenohd_version_in(output: &str) -> Option<String> {
    output.match_indices(VERSION_MARK).find_map(|(at, _)| {
        let word_before = output[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if word_before {
            return None;
        }
        let token: String = output[at + VERSION_MARK.len()..]
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        (!token.is_empty()).then_some(token)
    })
}

/// Grade the router at `binary` against the pin in the build script at
/// `script`. Runs `binary --version`.
pub fn zenohd_pin_verdict(binary: &Path, script: &Path) -> ZenohdPinVerdict {
    let want = match std::fs::read_to_string(script) {
        Ok(text) => match zenohd_pin_in(&text) {
            Some(pin) => pin,
            None => {
                return ZenohdPinVerdict::PinUnknown {
                    why: format!(
                        "{} has no `ZENOHD_VERSION=\"${{ZENOHD_VERSION:-...}}\"` line",
                        script.display()
                    ),
                }
            }
        },
        Err(e) => {
            return ZenohdPinVerdict::PinUnknown {
                why: format!("{} is unreadable: {e}", script.display()),
            }
        }
    };
    let output = match version_output(binary) {
        Ok(output) => output,
        Err(why) => return ZenohdPinVerdict::Unreadable { why },
    };
    match zenohd_version_in(&output) {
        Some(have) if have == want => ZenohdPinVerdict::Match,
        Some(have) => ZenohdPinVerdict::OffPin { have, want },
        None => ZenohdPinVerdict::Unreadable {
            why: format!("`--version` printed no `{VERSION_MARK}...` line: {output:?}"),
        },
    }
}

/// What `binary --version` printed on both streams, or why it printed nothing.
fn version_output(binary: &Path) -> Result<String, String> {
    let mut child = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("`{} --version` did not start: {e}", binary.display()))?;
    // Both streams are read while the child runs, so a child that writes more
    // than a pipe holds cannot stall on a reader that has not started yet.
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    if !ended_within(&mut child, VERSION_BUDGET) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "`{} --version` did not end within {VERSION_BUDGET:?}",
            binary.display()
        ));
    }
    let mut text = stdout.join().unwrap_or_default();
    text.push('\n');
    text.push_str(&stderr.join().unwrap_or_default());
    Ok(text)
}

/// Read one of a child's streams to its end on a thread of its own.
fn drain(stream: Option<impl Read + Send + 'static>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stream) = stream {
            let _ = stream.read_to_end(&mut bytes);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

/// Whether `child` ended before `budget` ran out.
fn ended_within(child: &mut Child, budget: Duration) -> bool {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if start.elapsed() < budget => thread::sleep(VERSION_POLL),
            Ok(None) | Err(_) => return false,
        }
    }
}

/// Refuse a reference router that is not the pinned version: panic with what
/// it reported and how to put the pinned one there.
///
/// A path that passed is remembered for the life of the process, so a test
/// that spawns the router many times asks it once.
pub fn assert_zenohd_at_pin(binary: &Path) {
    static GRADED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let graded = GRADED.get_or_init(Default::default);
    if graded
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(binary)
    {
        return;
    }
    let script = checkout_root().join(ZENOHD_BUILD_SCRIPT);
    let repair = format!(
        "build the pinned router with `bash {ZENOHD_BUILD_SCRIPT}` and leave {ZENOHD_BIN_ENV} \
         unset, or point {ZENOHD_BIN_ENV} at a router of the pinned version"
    );
    match zenohd_pin_verdict(binary, &script) {
        ZenohdPinVerdict::Match => {
            graded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(binary.to_path_buf());
        }
        ZenohdPinVerdict::OffPin { have, want } => panic!(
            "the reference router at {} is zenohd {have}, and this tree pins {want} \
             ({ZENOHD_BUILD_SCRIPT}). A verdict against it would be about a router this tree \
             no longer targets.\nFix: {repair}",
            binary.display()
        ),
        ZenohdPinVerdict::Unreadable { why } => panic!(
            "the reference router at {} would not say which version it is, so it cannot be \
             held to the pin: {why}\nFix: {repair}",
            binary.display()
        ),
        ZenohdPinVerdict::PinUnknown { why } => panic!(
            "the zenohd pin cannot be read, so the reference router at {} cannot be held to \
             it: {why}",
            binary.display()
        ),
    }
}

/// Locate the reference `zenohd` and hold it to the pin: the `WZ_ZENOHD_BIN`
/// override, else the install `scripts/build-zenohd.sh` makes at
/// `target/zenohd/zenohd` under the artifact root (`zenohd.exe` on Windows).
/// Panics with the build hint when the binary is absent, and through
/// [`assert_zenohd_at_pin`] when it is not the pinned version.
pub fn zenohd_binary() -> PathBuf {
    let path = match std::env::var_os(ZENOHD_BIN_ENV).filter(|p| !p.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => artifact("target/zenohd").join(format!("zenohd{}", std::env::consts::EXE_SUFFIX)),
    };
    assert!(
        path.is_file(),
        "zenohd binary missing at {}; set {ZENOHD_BIN_ENV} or run {ZENOHD_BUILD_SCRIPT} first",
        path.display()
    );
    assert_zenohd_at_pin(&path);
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = "#!/usr/bin/env bash\n\
        set -euo pipefail\n\
        # ZENOHD_VERSION=\"${ZENOHD_VERSION:-0.0.1}\" in a comment is not the pin\n\
        ZENOHD_VERSION=\"${ZENOHD_VERSION:-1.10.2}\"\n\
        ZENOHD_VERSION=\"${ZENOHD_VERSION:-9.9.9}\"\n";

    #[test]
    fn the_pin_is_the_first_default_line_of_the_script() {
        assert_eq!(zenohd_pin_in(SCRIPT).as_deref(), Some("1.10.2"));
    }

    #[test]
    fn an_indented_or_crlf_pin_line_still_reads() {
        let script = "if true; then\n    ZENOHD_VERSION=\"${ZENOHD_VERSION:-1.10.2}\"\r\nfi\n";
        assert_eq!(zenohd_pin_in(script).as_deref(), Some("1.10.2"));
    }

    #[test]
    fn a_script_without_the_default_line_has_no_pin() {
        assert_eq!(zenohd_pin_in("ZENOHD_VERSION=1.10.2\n"), None);
        assert_eq!(
            zenohd_pin_in("ZENOHD_VERSION=\"${ZENOHD_VERSION:-}\"\n"),
            None
        );
        assert_eq!(
            zenohd_pin_in("ZENOHD_VERSION=\"${ZENOHD_VERSION:-1.10.2}\n"),
            None
        );
        assert_eq!(zenohd_pin_in(""), None);
    }

    #[test]
    fn the_version_token_follows_the_router_name() {
        let out = "zenohd v1.10.2 built with rustc 1.97.1 (abc 2026-01-01)\n";
        assert_eq!(zenohd_version_in(out).as_deref(), Some("1.10.2"));
    }

    #[test]
    fn a_commit_hash_version_is_read_as_it_is() {
        assert_eq!(
            zenohd_version_in("zenohd v49c8a538 built with rustc\n").as_deref(),
            Some("49c8a538")
        );
    }

    #[test]
    fn output_without_the_router_name_has_no_version() {
        assert_eq!(zenohd_version_in("usage: zenohd [OPTIONS]\n"), None);
        assert_eq!(zenohd_version_in("myzenohd v1.10.2\n"), None);
        assert_eq!(zenohd_version_in("zenohd v \n"), None);
        assert_eq!(zenohd_version_in(""), None);
    }

    #[test]
    fn an_unreadable_script_leaves_the_pin_unknown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let verdict = zenohd_pin_verdict(&dir.path().join("zenohd"), &dir.path().join("absent"));
        assert!(
            matches!(verdict, ZenohdPinVerdict::PinUnknown { .. }),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_binary_that_does_not_start_is_unreadable() {
        let _serial = serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("build-zenohd.sh");
        std::fs::write(&script, SCRIPT).expect("write script");
        let verdict = zenohd_pin_verdict(&dir.path().join("absent-zenohd"), &script);
        assert!(
            matches!(verdict, ZenohdPinVerdict::Unreadable { .. }),
            "{verdict:?}"
        );
    }

    /// Held by every test that writes a stand-in or starts a process. A file
    /// written for execution while another test thread forks is held open in
    /// that child until it execs, and executing it then fails with "text file
    /// busy"; one test at a time does the two.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A stand-in router: a shell script printing `version_line` on `stream`.
    #[cfg(unix)]
    fn stand_in(dir: &Path, version_line: &str, stream: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("zenohd");
        let redirect = if stream == "stderr" { " >&2" } else { "" };
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s\\n' '{version_line}'{redirect}\n"),
        )
        .expect("write stand-in");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stand-in");
        path
    }

    #[cfg(unix)]
    fn graded(version_line: &str, stream: &str) -> ZenohdPinVerdict {
        let _serial = serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("build-zenohd.sh");
        std::fs::write(&script, SCRIPT).expect("write script");
        let binary = stand_in(dir.path(), version_line, stream);
        zenohd_pin_verdict(&binary, &script)
    }

    #[cfg(unix)]
    #[test]
    fn a_router_of_the_pinned_version_matches() {
        assert_eq!(
            graded("zenohd v1.10.2 built with rustc 1.97.1", "stdout"),
            ZenohdPinVerdict::Match
        );
        assert_eq!(
            graded("zenohd v1.10.2 built with rustc 1.97.1", "stderr"),
            ZenohdPinVerdict::Match
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_router_of_another_version_is_off_the_pin() {
        assert_eq!(
            graded("zenohd v1.5.0 built with rustc 1.85.0", "stdout"),
            ZenohdPinVerdict::OffPin {
                have: "1.5.0".to_owned(),
                want: "1.10.2".to_owned(),
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_that_prints_no_version_is_unreadable() {
        assert!(matches!(
            graded("hello", "stdout"),
            ZenohdPinVerdict::Unreadable { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "this tree pins")]
    fn the_assertion_refuses_a_router_off_the_pin() {
        let _serial = serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = stand_in(
            dir.path(),
            "zenohd v0.0.0-off-pin built with rustc",
            "stdout",
        );
        assert_zenohd_at_pin(&binary);
    }
}
