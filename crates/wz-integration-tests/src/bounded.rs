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
//! time. [`BoundedStatus`] does the same for `status`, and [`BoundedChild`] for a
//! child somebody else started (`wait`, `wait_with_output`).
//! [`BoundedOutput::output_or_stall_bounded`] is the one form that hands the stall back
//! instead of failing, for a child whose stall is one of the outcomes of a defect the
//! caller pins.
//!
//! A program that prints into a pipe loses its buffered lines when it is killed, and
//! the stall that most needs its output read is the one that shows none, so
//! [`BoundedOutput`] launches the child through `stdbuf -oL -eL` where the host has
//! one. `stdbuf` replaces itself with the program, so the pid, the process group and
//! the threads read from `/proc` are the program's own. `status` runs are not wrapped:
//! their streams are the caller's, which cannot be read back to be copied.
//!
//! The census test at the end of this file keeps the population closed: a raw
//! `.output()`, `.status()`, `.wait_with_output()` or `.wait()` (one no kill precedes)
//! in this crate's tests is a test whose child can outlive it.

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
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

    /// [`Self::output_or_stall_within`] with [`CHILD_RUN_BOUND`].
    fn output_or_stall_bounded(&mut self) -> io::Result<BoundedRun>;

    /// [`Self::output_within`] that hands a stall back instead of failing on it: the
    /// child is killed at `bound` all the same, and the caller gets what it had printed
    /// and where its threads were, to classify.
    ///
    /// Only for a child whose run past a point it reports is not defined, such as an
    /// upstream example that reads memory a failed call left uninitialised: whether it
    /// then dies on a signal or waits on a lock made of garbage is the same defect, and
    /// only its printed output can say the run reached that point. Every other caller
    /// wants [`Self::output_within`], for which a stall is the finding.
    fn output_or_stall_within(&mut self, bound: Duration) -> io::Result<BoundedRun>;
}

/// How a bounded run ended: by itself, or at its bound.
#[derive(Debug)]
pub enum BoundedRun {
    /// The child ended by itself, with what `Command::output` would have returned.
    Ended(Output),
    /// The child was still running at the bound and has been killed.
    Stalled(Stall),
}

impl BoundedRun {
    /// The output of a run that ended by itself; a stall fails the test by name, as
    /// [`BoundedOutput::output_within`] does.
    pub fn ended(self) -> Output {
        match self {
            BoundedRun::Ended(output) => output,
            BoundedRun::Stalled(stall) => stall.fail(),
        }
    }
}

/// A child that did not end within its bound, read before the kill and collected after it.
#[derive(Debug)]
pub struct Stall {
    program: String,
    pid: u32,
    bound: Duration,
    threads: String,
    /// What the child had written to its standard output when it was killed.
    pub stdout: Vec<u8>,
    /// What the child had written to its standard error when it was killed.
    pub stderr: Vec<u8>,
}

impl Stall {
    /// What each of the child's threads was waiting in when the bound ran out.
    pub fn threads(&self) -> &str {
        &self.threads
    }

    /// Fail the test with this stall, in the words [`BoundedOutput::output_within`] uses.
    pub fn fail(&self) -> ! {
        stalled(
            &self.program,
            self.pid,
            self.bound,
            &self.threads,
            Some((&self.stdout, &self.stderr)),
        )
    }
}

impl BoundedOutput for Command {
    fn output_bounded(&mut self) -> io::Result<Output> {
        self.output_within(CHILD_RUN_BOUND)
    }

    fn output_within(&mut self, bound: Duration) -> io::Result<Output> {
        self.output_within_stdin(bound, Stdio::null())
    }

    fn output_within_stdin(&mut self, bound: Duration, stdin: Stdio) -> io::Result<Output> {
        Ok(run_within(self, bound, stdin)?.ended())
    }

    fn output_or_stall_bounded(&mut self) -> io::Result<BoundedRun> {
        self.output_or_stall_within(CHILD_RUN_BOUND)
    }

    fn output_or_stall_within(&mut self, bound: Duration) -> io::Result<BoundedRun> {
        run_within(self, bound, Stdio::null())
    }
}

/// The one bounded run every [`BoundedOutput`] method is.
///
/// Both streams are captured whatever the command was configured with, and the input
/// is the one given: a command configured to discard a stream has it read and returned
/// instead, which is more than `Command::output` gives and costs the caller nothing.
fn run_within(this: &mut Command, bound: Duration, stdin: Stdio) -> io::Result<BoundedRun> {
    let program = this.get_program().to_string_lossy().into_owned();
    // A program that prints into a pipe keeps its lines in a buffer of its own, and a
    // program that is killed loses them: the stall that most needs its output read is
    // the one that shows none. Launched through `stdbuf` where there is one, its lines
    // leave as they are printed. `stdbuf` replaces itself with the program (same pid,
    // same process group), so what is killed and what is read are the program's.
    let mut wrapped = line_buffered(this);
    let command = wrapped.as_mut().unwrap_or(this);
    command
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The child leads a process group of its own, so that what it started goes
    // with it at the deadline and a grandchild cannot keep the pipes open.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let pid = child.id();
    let stdout = drain(child.stdout.take().expect("stdout was piped"));
    let stderr = drain(child.stderr.take().expect("stderr was piped"));

    Ok(match wait_until(&mut child, bound)? {
        Some(status) => BoundedRun::Ended(Output {
            status,
            stdout: stdout.finish(READER_GRACE),
            stderr: stderr.finish(READER_GRACE),
        }),
        None => {
            let threads = kill_and_read_threads(&mut child);
            BoundedRun::Stalled(Stall {
                program,
                pid,
                bound,
                threads,
                stdout: stdout.finish(Duration::from_secs(1)),
                stderr: stderr.finish(Duration::from_secs(1)),
            })
        }
    })
}

/// `Command::status` with a deadline.
///
/// The command's standard streams are left as the caller set them: a caller that
/// sends a child's output to a capture file keeps doing so, and a stalled child's
/// output is then in that file and not in the failure.
pub trait BoundedStatus {
    /// [`Self::status_within`] with [`CHILD_RUN_BOUND`].
    fn status_bounded(&mut self) -> io::Result<ExitStatus>;

    /// Run the command to its end and return its exit status, or kill its process group
    /// at `bound` and fail the test by name.
    fn status_within(&mut self, bound: Duration) -> io::Result<ExitStatus>;
}

impl BoundedStatus for Command {
    fn status_bounded(&mut self) -> io::Result<ExitStatus> {
        self.status_within(CHILD_RUN_BOUND)
    }

    fn status_within(&mut self, bound: Duration) -> io::Result<ExitStatus> {
        let program = self.get_program().to_string_lossy().into_owned();
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            self.process_group(0);
        }
        let mut child = self.spawn()?;
        let pid = child.id();
        match wait_until(&mut child, bound)? {
            Some(status) => Ok(status),
            None => {
                let threads = kill_and_read_threads(&mut child);
                stalled(&program, pid, bound, &threads, None)
            }
        }
    }
}

/// A child process that was started elsewhere (a long-lived counterparty, a reader in a
/// namespace) and is now waited for.
pub trait BoundedChild {
    /// [`Self::wait_within`] with [`CHILD_RUN_BOUND`].
    fn wait_bounded(&mut self) -> io::Result<ExitStatus>;

    /// Wait for the child to end by itself; at `bound` kill it and fail the test by name.
    /// A wait that follows a kill needs none of this, and the census says so. The result
    /// is `Child::wait`'s: `Err` only when the child could not be polled.
    fn wait_within(&mut self, bound: Duration) -> io::Result<ExitStatus>;

    /// [`Self::wait_with_output_within`] with [`CHILD_RUN_BOUND`].
    fn wait_with_output_bounded(self) -> io::Result<Output>;

    /// `Child::wait_with_output` with a deadline: the piped streams are read while the
    /// child runs, and at `bound` the child is killed and the test fails by name with
    /// what it had written.
    fn wait_with_output_within(self, bound: Duration) -> io::Result<Output>;
}

impl BoundedChild for Child {
    fn wait_bounded(&mut self) -> io::Result<ExitStatus> {
        self.wait_within(CHILD_RUN_BOUND)
    }

    fn wait_within(&mut self, bound: Duration) -> io::Result<ExitStatus> {
        let pid = self.id();
        match wait_until(self, bound)? {
            Some(status) => Ok(status),
            None => {
                let threads = kill_and_read_threads(self);
                stalled("a child process", pid, bound, &threads, None)
            }
        }
    }

    fn wait_with_output_bounded(self) -> io::Result<Output> {
        self.wait_with_output_within(CHILD_RUN_BOUND)
    }

    fn wait_with_output_within(mut self, bound: Duration) -> io::Result<Output> {
        let pid = self.id();
        // Closed first, as `wait_with_output` does: a child that reads its input would
        // otherwise wait for a writer that is waiting for it.
        drop(self.stdin.take());
        let stdout = self.stdout.take().map(drain);
        let stderr = self.stderr.take().map(drain);
        let finish =
            |drain: Option<Drain>, grace| drain.map(|d| d.finish(grace)).unwrap_or_default();
        match wait_until(&mut self, bound)? {
            Some(status) => Ok(Output {
                status,
                stdout: finish(stdout, READER_GRACE),
                stderr: finish(stderr, READER_GRACE),
            }),
            None => {
                let threads = kill_and_read_threads(&mut self);
                let out = finish(stdout, Duration::from_secs(1));
                let err = finish(stderr, Duration::from_secs(1));
                stalled("a child process", pid, bound, &threads, Some((&out, &err)))
            }
        }
    }
}

/// Poll `child` until it has ended (`Some`) or `bound` has passed (`None`).
fn wait_until(child: &mut Child, bound: Duration) -> io::Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if started.elapsed() >= bound {
            return Ok(None);
        }
        thread::sleep(POLL);
    }
}

/// What each thread of the stalled child was waiting in, read BEFORE the kill (after it
/// there is nothing left to read), and then the kill: its whole process group, which
/// is the child's own for the runners that made it a group leader and reaches nothing
/// else for one that did not, and the child itself either way.
fn kill_and_read_threads(child: &mut Child) -> String {
    let threads = threads_of(child.id());
    kill_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
    threads
}

/// The failure of a child that did not end within its bound.
fn stalled(
    program: &str,
    pid: u32,
    bound: Duration,
    threads: &str,
    output: Option<(&[u8], &[u8])>,
) -> ! {
    let streams = match output {
        Some((out, err)) => format!(
            "--- its stdout so far ---\n{}\n--- its stderr so far ---\n{}\n\
             (run through stdbuf where the host has one, so its lines are not held back by \
             its own buffer; a host without it shows only what the program flushed)",
            String::from_utf8_lossy(out),
            String::from_utf8_lossy(err)
        ),
        None => "(its output went where the caller sent it, not here)".to_owned(),
    };
    panic!(
        "`{program}` (pid {pid}) did not finish within {bound:?}, so it was killed. \
         A child that waits for a message that never comes is the finding; the bound \
         only keeps it from holding the test, and the machine's port reservation, \
         until a job's own timeout.\n\
         --- its threads when the bound ran out ---\n{threads}\n{streams}"
    );
}

/// `command` launched through `stdbuf -oL -eL`, or `None` where the host has no
/// `stdbuf` (macOS and Windows do not) or the command is already one.
///
/// The copy carries the program, its arguments, its working directory and every
/// environment change that can be read back from the original. Its standard streams
/// are the caller's to set: the original's cannot be read back, which is why only the
/// runners that set their own use this.
fn line_buffered(command: &Command) -> Option<Command> {
    let stdbuf = find_on_path("stdbuf")?;
    if command.get_program() == stdbuf.as_os_str() || command.get_program() == "stdbuf" {
        return None;
    }
    let mut wrapped = Command::new(stdbuf);
    wrapped
        .args(["-oL", "-eL"])
        .arg(command.get_program())
        .args(command.get_args());
    for (key, value) in command.get_envs() {
        match value {
            Some(value) => wrapped.env(key, value),
            None => wrapped.env_remove(key),
        };
    }
    if let Some(dir) = command.get_current_dir() {
        wrapped.current_dir(dir);
    }
    Some(wrapped)
}

/// The first executable file called `name` on `PATH`.
fn find_on_path(name: &str) -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| {
            candidate.is_file() && {
                #[cfg(unix)]
                {
                    candidate
                        .metadata()
                        .is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
                }
                #[cfg(not(unix))]
                {
                    true
                }
            }
        })
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

    /// The run that hands a stall back kills the child exactly as the failing one does,
    /// and the caller gets the same evidence: what it printed and where its threads were.
    /// A run that ends is the same `Output` the failing form returns.
    #[test]
    fn a_stall_handed_back_is_killed_and_carries_its_output_and_threads() {
        let run = sh("echo started; exec sleep 600")
            .output_or_stall_within(Duration::from_millis(300))
            .expect("sh starts");
        let BoundedRun::Stalled(stall) = run else {
            panic!("a child that sleeps for ten minutes ended within 300ms: {run:?}");
        };
        assert_eq!(stall.stdout, b"started\n");
        assert!(stall.threads().contains("sleep"), "{}", stall.threads());
        assert!(
            is_gone(stall.pid as libc::pid_t),
            "the child outlived the bound"
        );
        let message = panic_message(|| stall.fail());
        assert!(message.contains("did not finish within 300ms"), "{message}");
        assert!(message.contains("started"), "its output so far: {message}");

        let run = sh("printf out; exit 5")
            .output_or_stall_bounded()
            .expect("sh starts");
        let out = run.ended();
        assert_eq!(out.status.code(), Some(5));
        assert_eq!(out.stdout, b"out");
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

    /// A status that comes back is the child's own, and the streams the caller
    /// configured are the ones the child writes to.
    #[test]
    fn a_status_that_ends_is_returned_and_the_callers_streams_are_kept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let capture = dir.path().join("out");
        let status = sh("printf kept; exit 7")
            .stdout(std::fs::File::create(&capture).expect("capture file"))
            .status_bounded()
            .expect("sh starts");
        assert_eq!(status.code(), Some(7));
        assert_eq!(std::fs::read(&capture).expect("capture"), b"kept");
    }

    #[test]
    fn a_status_that_does_not_end_is_killed_and_named() {
        let message = panic_message(|| {
            let _ = sh("exec sleep 600").status_within(Duration::from_millis(300));
        });
        assert!(message.contains("did not finish within 300ms"), "{message}");
        assert!(is_gone(pid_in(&message)), "the child outlived the bound");
    }

    /// The waits on a child somebody else started: the end by itself, the end at the
    /// bound, and the piped streams read while it runs.
    #[test]
    fn a_wait_on_a_started_child_has_the_same_three_endings() {
        let mut quick = sh("exit 4").spawn().expect("sh starts");
        assert_eq!(quick.wait_bounded().expect("wait").code(), Some(4));

        let loud = sh("head -c 300000 /dev/zero; printf done >&2")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("sh starts");
        let out = loud.wait_with_output_bounded().expect("read and wait");
        assert_eq!(out.stdout.len(), 300_000);
        assert_eq!(out.stderr, b"done");

        let message = panic_message(|| {
            let mut stuck = sh("exec sleep 600").spawn().expect("sh starts");
            let _ = stuck.wait_within(Duration::from_millis(300));
        });
        assert!(message.contains("did not finish within 300ms"), "{message}");
        assert!(is_gone(pid_in(&message)), "the child outlived the bound");

        let message = panic_message(|| {
            let stuck = sh("printf partial; exec sleep 600")
                .stdout(Stdio::piped())
                .spawn()
                .expect("sh starts");
            let _ = stuck.wait_with_output_within(Duration::from_millis(300));
        });
        assert!(message.contains("partial"), "its output so far: {message}");
    }

    /// A killed C program shows what it printed.
    ///
    /// A program that prints into a pipe keeps its lines in a buffer of its own, and the
    /// kill that ends a stalled one takes the buffer with it: the failure then names a
    /// child that said nothing. This is the probe shape the differentials run, a compiled C
    /// program that prints a line and then waits, and its line is in the failure because the
    /// runner launches it through `stdbuf`. The control is the same program started
    /// directly, which loses the line, so the assertion cannot pass on a program that
    /// flushes anyway.
    ///
    /// Linux only, and no skip: `stdbuf` is coreutils and `cc` is the linker every Rust
    /// build here already needs, so a host this test runs on that lacks either is a broken
    /// host, and a test that passed by printing "skip" there would be the shape
    /// `silent_skip_gate.py` exists to refuse.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_killed_c_program_shows_the_line_it_printed_before_it_stalled() {
        assert!(
            find_on_path("stdbuf").is_some() && find_on_path("cc").is_some(),
            "this host has no stdbuf or no cc, and the runner's line-buffering needs both"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("stall.c");
        std::fs::write(
            &src,
            "#include <stdio.h>\n#include <unistd.h>\n\
             int main(void) { printf(\"printed-before-the-stall\\n\"); sleep(600); return 0; }\n",
        )
        .expect("write the program");
        let exe = dir.path().join("stall");
        let built = Command::new("cc")
            .arg(&src)
            .arg("-o")
            .arg(&exe)
            .output_bounded()
            .expect("cc starts");
        assert!(built.status.success(), "cc failed: {built:?}");

        let message = panic_message(|| {
            let _ = Command::new(&exe).output_within(Duration::from_millis(500));
        });
        assert!(
            message.contains("printed-before-the-stall"),
            "the killed program's line is in the failure: {message}"
        );

        // The control: the same program, started directly, loses its buffered line.
        let mut direct = Command::new(&exe)
            .stdout(Stdio::piped())
            .spawn()
            .expect("start the program directly");
        std::thread::sleep(Duration::from_millis(300));
        direct.kill().expect("kill it");
        let out = direct.wait_with_output().expect("collect what it wrote");
        assert!(
            out.stdout.is_empty(),
            "the control must lose the line, or the assertion above proves nothing: {:?}",
            String::from_utf8_lossy(&out.stdout)
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

    /// How many lines before a `.wait()` a kill may stand for the wait to be one that
    /// follows it. A wait after a kill returns when the kernel has delivered the signal,
    /// and needs no bound; the window is the distance the tests in this crate keep between
    /// the two (the longest is a comment block of a few lines).
    const KILL_WINDOW: usize = 8;

    /// The calls on a child with no end in `source`: `.output()`, `.status()`,
    /// `.wait_with_output()`, and a `.wait()` with no kill in the lines before it. Each as
    /// (line number, what), with the comment part of a line left out so a sentence that
    /// names a call is not one. A wait that follows a kill is not one: the child it waits
    /// for has been told to go.
    fn unbounded_child_calls(source: &str) -> Vec<(usize, &'static str)> {
        let lines: Vec<&str> = source
            .lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect();
        let mut found = Vec::new();
        for (index, code) in lines.iter().enumerate() {
            for call in [".output()", ".status()", ".wait_with_output()"] {
                if code.contains(call) {
                    found.push((index + 1, call));
                }
            }
            if code.contains(".wait()") {
                let from = index.saturating_sub(KILL_WINDOW);
                let killed = lines[from..=index]
                    .iter()
                    .any(|l| l.contains("kill") || l.contains("graceful_terminate"));
                if !killed {
                    found.push((index + 1, ".wait()"));
                }
            }
        }
        found
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
            for (line, call) in unbounded_child_calls(&source) {
                offenders.push(format!(
                    "{}:{line}  {call}",
                    file.strip_prefix(&root).unwrap_or(&file).display()
                ));
            }
        }
        assert!(
            offenders.is_empty(),
            "a bare `.output()`, `.status()`, `.wait_with_output()` or `.wait()` (one no \
             kill precedes) waits for its child for as long as the child lives; use \
             `output_bounded()`, `status_bounded()`, `wait_with_output_bounded()` or \
             `wait_bounded()` (`wz_integration_tests::bounded`):\n  {}",
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
        assert_eq!(
            unbounded_child_calls(source),
            vec![(1, ".output()"), (3, ".output()")]
        );
    }

    /// The four forms, and the one exception: a wait with a kill before it is not a wait
    /// for a child that decides when to end.
    #[test]
    fn the_census_counts_each_wait_and_spares_the_one_after_a_kill() {
        let source = "let s = cmd.status();\n\
                      let o = child.wait_with_output();\n\
                      let w = child.wait();\n\
                      child.kill();\n\
                      let after = child.wait();\n\
                      let bounded = child.wait_bounded();\n\
                      let s2 = cmd.status_bounded();\n";
        assert_eq!(
            unbounded_child_calls(source),
            vec![(1, ".status()"), (2, ".wait_with_output()"), (3, ".wait()")]
        );
        // A kill further back than the window stands for nothing.
        let far = format!("child.kill();\n{}let w = child.wait();\n", "\n".repeat(9));
        assert_eq!(unbounded_child_calls(&far), vec![(11, ".wait()")]);
    }
}
