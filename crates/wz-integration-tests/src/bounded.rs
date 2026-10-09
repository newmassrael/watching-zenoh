// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A child process run that has an end.
//!
//! `std::process::Command::output` waits for the child for as long as the child
//! lives. A test that runs a C program, a drop-in example or a demo through it
//! has no bound of its own, and the programs it runs wait on peers, on handlers
//! and on the network: one that waits for a message that never comes holds the
//! test until a job's own timeout kills everything around it. Measured twice on
//! the pico differentials (open-debt item 846): a wz arm stood in `z_recv` for
//! 732 s, and the run that found the cause stood for 120 s, and in the same
//! tests the port reservation is held across the child's whole run, so one
//! stalled child also stopped every other test on the machine that needed a port.
//!
//! [`BoundedOutput::output_bounded`] is `output` with a deadline. At the deadline
//! the child's whole process group is killed, and the test fails by name with what
//! the child had printed and, on Linux, what each of its threads was waiting in, so
//! a stall reads as a finding about one program and not as a job that ran out of
//! time.
//!
//! The census test at the end of this file keeps the population closed: a raw
//! `.output()` in this crate's tests is a test whose child can outlive it.

use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How long a child a test runs may take. The programs this crate runs finish in a
/// second or two, and thirty seconds when sixteen of them share a loaded host; this
/// is a bound on a stall, not a measure of speed, so it is several times the
/// slowest of those.
pub const CHILD_RUN_BOUND: Duration = Duration::from_secs(180);

/// How often a waiting test looks at its child.
const POLL: Duration = Duration::from_millis(10);

/// How long after a child has ended its output readers are waited for. A reader ends
/// when every holder of the pipe's write end has gone, and a grandchild that outlives
/// the child can keep it open, so the wait is bounded and what was read is returned.
const READER_GRACE: Duration = Duration::from_secs(5);

/// `Command::output` with a deadline.
pub trait BoundedOutput {
    /// [`Self::output_within`] with [`CHILD_RUN_BOUND`].
    fn output_bounded(&mut self) -> io::Result<Output>;

    /// Run the command to its end and return what it printed, as
    /// `Command::output` does, but give up when `bound` has passed: the child's
    /// process group is killed and this panics with the child's output so far.
    ///
    /// `Err` is only a failure to start the child, as it is for `output`. A child
    /// that does not end is not an error a test can handle, it is the test's
    /// failure, so it is a panic.
    fn output_within(&mut self, bound: Duration) -> io::Result<Output>;

    /// [`Self::output_within`] for a child that reads `stdin`: the child's standard
    /// input, which `output_within` closes.
    fn output_within_stdin(&mut self, bound: Duration, stdin: Stdio) -> io::Result<Output>;
}

impl BoundedOutput for Command {
    fn output_bounded(&mut self) -> io::Result<Output> {
        self.output_within(CHILD_RUN_BOUND)
    }

    fn output_within(&mut self, bound: Duration) -> io::Result<Output> {
        self.output_within_stdin(bound, Stdio::null())
    }

    /// Both streams are captured whatever the command was configured with, and the
    /// input is the one given: a command configured to discard a stream has it read
    /// and returned instead, which is more than `Command::output` gives and costs the
    /// caller nothing.
    fn output_within_stdin(&mut self, bound: Duration, stdin: Stdio) -> io::Result<Output> {
        let program = self.get_program().to_string_lossy().into_owned();
        self.stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // The child leads a process group of its own, so that what it started goes
        // with it at the deadline and a grandchild cannot keep the pipes open.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            self.process_group(0);
        }
        let mut child = self.spawn()?;
        let pid = child.id();
        let stdout = drain(child.stdout.take().expect("stdout was piped"));
        let stderr = drain(child.stderr.take().expect("stderr was piped"));

        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(Output {
                    status,
                    stdout: stdout.finish(READER_GRACE),
                    stderr: stderr.finish(READER_GRACE),
                });
            }
            if started.elapsed() >= bound {
                break;
            }
            thread::sleep(POLL);
        }

        // Read what the threads were waiting in BEFORE the kill: after it there is
        // nothing left to read.
        let threads = threads_of(pid);
        kill_group(pid);
        let _ = child.kill();
        let _ = child.wait();
        let out = String::from_utf8_lossy(&stdout.finish(Duration::from_secs(1))).into_owned();
        let err = String::from_utf8_lossy(&stderr.finish(Duration::from_secs(1))).into_owned();
        panic!(
            "`{program}` (pid {pid}) did not finish within {bound:?}, so it was killed. \
             A child that waits for a message that never comes is the finding; the bound \
             only keeps it from holding the test, and the machine's port reservation, \
             until a job's own timeout.\n\
             --- its threads when the bound ran out ---\n{threads}\n\
             --- its stdout so far ---\n{out}\n\
             --- its stderr so far ---\n{err}\n\
             (a C program's stdout is block-buffered into a pipe, so a line it printed \
             and did not flush is not shown)"
        );
    }
}

/// A pipe being read on a thread of its own, into a buffer that can be read before
/// the thread has ended.
struct Drain {
    captured: Arc<Mutex<Vec<u8>>>,
    reader: JoinHandle<()>,
}

fn drain<R: Read + Send + 'static>(mut pipe: R) -> Drain {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let reader = thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => sink
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    });
    Drain { captured, reader }
}

impl Drain {
    /// What was read, once the reader has ended or `grace` has passed.
    fn finish(self, grace: Duration) -> Vec<u8> {
        let until = Instant::now() + grace;
        while !self.reader.is_finished() && Instant::now() < until {
            thread::sleep(POLL);
        }
        let mut captured = self
            .captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *captured)
    }
}

/// Kill the child and everything of its process group.
fn kill_group(pid: u32) {
    #[cfg(unix)]
    {
        // The child was made the leader of a group named by its own pid, so the
        // negative pid reaches the group.
        let group = -(pid as libc::pid_t);
        // SAFETY: `kill(2)` takes two integers and touches no memory of ours.
        unsafe {
            libc::kill(group, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
}

/// What each thread of `pid` is waiting in, from `/proc`.
#[cfg(target_os = "linux")]
fn threads_of(pid: u32) -> String {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return "(the process's threads could not be read)".to_owned();
    };
    let mut lines = Vec::new();
    for task in tasks.flatten() {
        let dir = task.path();
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .map(|text| text.trim().to_owned())
                .unwrap_or_else(|_| "?".to_owned())
        };
        lines.push(format!(
            "  {} wait={}",
            read("comm"),
            match read("wchan").as_str() {
                "" | "0" => "running".to_owned(),
                waiting => waiting.to_owned(),
            }
        ));
    }
    lines.sort();
    lines.join("\n")
}

#[cfg(not(target_os = "linux"))]
fn threads_of(_pid: u32) -> String {
    "(thread states are read from /proc, which this host does not have)".to_owned()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    /// A child that ends returns what `Command::output` would have: its status and
    /// both streams, whole.
    #[test]
    fn a_child_that_ends_returns_its_status_and_both_streams() {
        let out = sh("printf out; printf err >&2; exit 3")
            .output_bounded()
            .expect("sh starts");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout, b"out");
        assert_eq!(out.stderr, b"err");
    }

    /// Output past the size of a pipe is read while the child runs, so a child that
    /// prints more than a pipe holds is not waiting on a reader that is waiting on it.
    #[test]
    fn a_child_that_prints_more_than_a_pipe_holds_does_not_stall() {
        let out = sh("head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2")
            .output_bounded()
            .expect("sh starts");
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 300_000);
        assert_eq!(out.stderr.len(), 300_000);
    }

    fn panic_message(run: impl FnOnce() + std::panic::UnwindSafe) -> String {
        let payload = std::panic::catch_unwind(run).expect_err("the run was meant to panic");
        match payload.downcast::<String>() {
            Ok(text) => *text,
            Err(other) => other
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
                .expect("a text panic"),
        }
    }

    fn pid_in(message: &str) -> libc::pid_t {
        let after = message
            .split("(pid ")
            .nth(1)
            .expect("the message names a pid");
        after
            .split(')')
            .next()
            .expect("the pid ends")
            .parse()
            .expect("a number")
    }

    fn is_gone(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only asks whether the process exists.
        unsafe { libc::kill(pid, 0) != 0 }
    }

    /// A child that does not end is killed at the bound and the test fails by name,
    /// with what it had printed and where its threads were.
    #[test]
    fn a_child_that_does_not_end_is_killed_and_named() {
        let message = panic_message(|| {
            let _ = sh("echo started; exec sleep 600").output_within(Duration::from_millis(300));
        });
        assert!(message.contains("did not finish within 300ms"), "{message}");
        assert!(message.contains("started"), "its output so far: {message}");
        assert!(message.contains("sleep"), "its threads: {message}");
        assert!(is_gone(pid_in(&message)), "the child outlived the bound");
    }

    /// What the child started goes with it. A grandchild that kept the pipes open would
    /// hold the reader until the grace ran out, so the failure arrives well before it.
    #[test]
    fn a_grandchild_does_not_outlive_the_bound_or_hold_the_pipes() {
        let started = Instant::now();
        let message = panic_message(|| {
            let _ = sh("sleep 600 & wait").output_within(Duration::from_millis(300));
        });
        assert!(message.contains("did not finish"), "{message}");
        assert!(
            started.elapsed() < READER_GRACE,
            "the failure waited on a pipe a grandchild held: {:?}",
            started.elapsed()
        );
    }
}

/// The population, derived from the sources: no test of this crate runs a child with
/// a bare `.output()`.
///
/// A bare `.output()` is the form with no end, and the tests that use it are the
/// ones that run C programs, drop-in examples and demos, each of which waits on
/// something. The census reads every `.rs` file of `tests/` and of `src/` and
/// refuses the call outside this module, so a new test cannot reopen the class
/// by writing the habitual line.
#[cfg(test)]
mod census {
    use std::path::{Path, PathBuf};

    fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }

    /// The lines of `source` that call `.output()` on a command, with the comment
    /// part of a line left out so a sentence that names the call is not one.
    fn bare_output_calls(source: &str) -> Vec<usize> {
        let mut lines = Vec::new();
        for (index, line) in source.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains(".output()") {
                lines.push(index + 1);
            }
        }
        lines
    }

    #[test]
    fn no_test_runs_a_child_with_a_bare_output() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rust_files(&root.join("tests"), &mut files);
        rust_files(&root.join("src"), &mut files);
        assert!(
            files.len() > 50,
            "the census read {} file(s), which is not this crate's tests",
            files.len()
        );
        let mut offenders = Vec::new();
        for file in files {
            if file.file_name().is_some_and(|name| name == "bounded.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&file).expect("a source file reads");
            for line in bare_output_calls(&source) {
                offenders.push(format!(
                    "{}:{line}",
                    file.strip_prefix(&root).unwrap_or(&file).display()
                ));
            }
        }
        assert!(
            offenders.is_empty(),
            "a bare `.output()` waits for its child for as long as the child lives; use \
             `output_bounded()` (`wz_integration_tests::bounded::BoundedOutput`):\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The census is a count of lines, so it is checked against lines it must count
    /// and lines it must not.
    #[test]
    fn the_census_counts_the_call_and_not_a_sentence_about_it() {
        let source = "let a = c.output();\n\
                      let b = c\n    .output()\n    .expect(\"x\");\n\
                      // a bare .output() in a comment\n\
                      let d = c.output_bounded();\n";
        assert_eq!(bare_output_calls(source), vec![1, 3]);
    }
}
