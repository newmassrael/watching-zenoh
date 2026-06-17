// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared helpers for the `wz_*_round_trip` / `ap_demo_*` integration
//! tests in this crate. Through R215 each test redefined the same set
//! of helpers locally (9 files × 5 fns = 45 duplicates); the
//! `pick_free_port` clone in particular carried a TOCTOU race that
//! manifested as the Layer E flake observed on the R209 / R214 push
//! hook runs (`wz_initiator_round_trip_against_wz_acceptor` and
//! `ap_demo_round_trip_against_zenoh_pico_z_put`). R216 lifts the
//! helpers into this module and replaces the racey port picker with
//! a [`PortReservation`] that holds a process-global mutex across the
//! bind → child-spawn → bind-confirmed window so concurrent tests in
//! the same `cargo test` invocation cannot pick the same port.

pub mod common {
    //! Test harness primitives shared by the `wz_*_round_trip` /
    //! `ap_demo_*` integration tests. See module-level rationale for
    //! the flake background.

    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::net::{Ipv4Addr, TcpListener};
    use std::path::PathBuf;
    use std::process::Child;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::thread;
    use std::time::{Duration, Instant};

    fn port_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Process-global port reservation guard for the bind → child-spawn
    /// → bind-confirmed window.
    ///
    /// `bind("127.0.0.1:0")` returns an OS-allocated ephemeral port,
    /// and dropping the listener immediately returns that port to the
    /// free pool. Two parallel tests in the same `cargo test`
    /// invocation can therefore observe the same port if test A drops
    /// its listener between test B's `bind(0)` syscall and test B's
    /// subsequent child-process spawn — both children then race to
    /// bind the same port and one fails. The empirical flake rate on
    /// R209 / R214 push runs is ~13 % per Layer E lane (2 of ~15+
    /// pushes); the failure mode is "listening on" or "connected to"
    /// substring never appearing in the captured stderr within the
    /// 5 s timeout because the child's bind raced and lost.
    ///
    /// [`PortReservation::pick`] acquires a process-global mutex
    /// before binding so the bind → child-spawn → bind-confirmed
    /// sequence runs atomically with respect to other tests in the
    /// same process. Callers should drop the reservation as soon as
    /// the child has logged its bind-confirmed witness (e.g.
    /// `listening on`) so subsequent tests can proceed without
    /// blocking on the long-tail handshake / message-driven phase.
    ///
    /// The reservation does NOT defend against an external process
    /// stealing the port between `drop(listener)` and the child's
    /// `bind` syscall — that race window is sub-millisecond on
    /// localhost and has not been observed in this workspace's CI
    /// history. If a future round surfaces it, the textbook fix is
    /// FD inheritance (parent holds the listener, passes the bound
    /// socket FD to the child via `Command::pre_exec` + `dup2`); the
    /// MVP cost of that path is a new `--listen-fd` flag on
    /// `wz-ap-demo` and is deferred until the in-process race is
    /// confirmed insufficient.
    pub struct PortReservation {
        port: u16,
        _guard: MutexGuard<'static, ()>,
    }

    impl PortReservation {
        /// Acquire the process-global port-alloc lock, bind a fresh
        /// ephemeral port, drop the listener, and return a guard
        /// holding the lock plus the picked port. The caller must
        /// hold the guard alive until the child process has bound
        /// the port (signalled by e.g. a `listening on` log line);
        /// dropping the guard before that point reintroduces the
        /// race for the next reservation.
        pub fn pick() -> Self {
            let guard = port_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
            let port = listener.local_addr().expect("local_addr").port();
            drop(listener);
            Self {
                port,
                _guard: guard,
            }
        }

        /// The reserved port. Pass this to `--listen` / `-l` flags or
        /// to the `tcp/127.0.0.1:<port>` endpoint constructor.
        pub fn port(&self) -> u16 {
            self.port
        }

        /// Reserve TWO distinct ephemeral ports under a SINGLE lock
        /// acquisition, returning the guard (carrying port #1) plus a bare
        /// second port. R311pk — the WS dual-listen Layer Z legs need a
        /// `tcp_port` (pico dials TCP) + `ws_port` (wz dials WS) pair on one
        /// zenohd; calling [`pick`](Self::pick) twice on the same thread would
        /// re-enter the process-global mutex and deadlock. Both listeners are
        /// bound while the lock is held — so the two ports are guaranteed
        /// distinct — then dropped to the free pool. The returned guard holds
        /// the lock until dropped, exactly like [`pick`](Self::pick): drop it
        /// once the child has bound both ports.
        pub fn pick_pair() -> (Self, u16) {
            let guard = port_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let l1 = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0 (#1)");
            let l2 = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0 (#2)");
            let p1 = l1.local_addr().expect("local_addr #1").port();
            let p2 = l2.local_addr().expect("local_addr #2").port();
            drop(l1);
            drop(l2);
            (
                Self {
                    port: p1,
                    _guard: guard,
                },
                p2,
            )
        }
    }

    /// Resolve the watching-zenoh project root from
    /// `CARGO_MANIFEST_DIR`. Cargo sets this env var to
    /// `<root>/crates/wz-integration-tests`; the project root is two
    /// levels up.
    pub fn project_root() -> PathBuf {
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
        PathBuf::from(manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .expect("project root resolves from CARGO_MANIFEST_DIR")
    }

    /// Locate the freshly-built `wz-ap-demo` binary. Cargo emits it at
    /// `crates/target/<profile>/wz-ap-demo`; the test profile is
    /// usually debug, but release is checked as a fallback so a
    /// developer can run `cargo test --release` without surprises.
    pub fn wz_ap_demo_binary() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/wz-ap-demo"),
            crates_dir.join("target/release/wz-ap-demo"),
        ];
        for c in &candidates {
            if c.is_file() {
                return c.clone();
            }
        }
        panic!(
            "wz-ap-demo binary not found in {candidates:?}; run `cargo build -p wz-ap-demo` first"
        );
    }

    /// Locate the `wz-e2e-pubsub` binary — the minimal pubsub-only
    /// facade-subset e2e consumer (R311fg). Same debug/release lookup
    /// shape as [`wz_ap_demo_binary`]; the Layer E2 lane builds it
    /// under its pinned subset before the e2e test drives it, so a
    /// missing binary is a CI-prep error surfaced as a panic, not a
    /// graceful SKIP.
    pub fn wz_e2e_pubsub_binary() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/wz-e2e-pubsub"),
            crates_dir.join("target/release/wz-e2e-pubsub"),
        ];
        for c in &candidates {
            if c.is_file() {
                return c.clone();
            }
        }
        panic!(
            "wz-e2e-pubsub binary not found in {candidates:?}; \
             run `cargo build -p wz-e2e-pubsub` first"
        );
    }

    /// Locate the `wz-e2e-queryable` binary — the minimal queryable-only
    /// facade-subset e2e consumer (sibling of [`wz_e2e_pubsub_binary`]).
    /// Same debug/release lookup shape; the Layer E2 lane builds it
    /// under its pinned subset before the e2e test drives it, so a
    /// missing binary is a CI-prep error surfaced as a panic, not a
    /// graceful SKIP.
    pub fn wz_e2e_queryable_binary() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/wz-e2e-queryable"),
            crates_dir.join("target/release/wz-e2e-queryable"),
        ];
        for c in &candidates {
            if c.is_file() {
                return c.clone();
            }
        }
        panic!(
            "wz-e2e-queryable binary not found in {candidates:?}; \
             run `cargo build -p wz-e2e-queryable` first"
        );
    }

    /// Locate the `wz-e2e-zget` binary — the minimal z_get-initiator
    /// ("zget-reply-only") facade-subset e2e consumer (initiator-side
    /// mirror of [`wz_e2e_queryable_binary`]: wz ISSUES the query, the
    /// foreign peer answers). Same debug/release lookup shape; the Layer
    /// E2 lane builds it under its pinned subset before the e2e test
    /// drives it, so a missing binary is a CI-prep error surfaced as a
    /// panic, not a graceful SKIP.
    pub fn wz_e2e_zget_binary() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/wz-e2e-zget"),
            crates_dir.join("target/release/wz-e2e-zget"),
        ];
        for c in &candidates {
            if c.is_file() {
                return c.clone();
            }
        }
        panic!(
            "wz-e2e-zget binary not found in {candidates:?}; \
             run `cargo build -p wz-e2e-zget` first"
        );
    }

    /// Locate the `wz-e2e-liveliness` binary — the minimal liveliness-
    /// subscriber-only facade-subset e2e consumer (sibling of
    /// [`wz_e2e_pubsub_binary`] / [`wz_e2e_queryable_binary`]). Same
    /// debug/release lookup shape; the Layer E2 lane builds it under its
    /// pinned subset before the e2e test drives it, so a missing binary
    /// is a CI-prep error surfaced as a panic, not a graceful SKIP.
    pub fn wz_e2e_liveliness_binary() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/wz-e2e-liveliness"),
            crates_dir.join("target/release/wz-e2e-liveliness"),
        ];
        for c in &candidates {
            if c.is_file() {
                return c.clone();
            }
        }
        panic!(
            "wz-e2e-liveliness binary not found in {candidates:?}; \
             run `cargo build -p wz-e2e-liveliness` first"
        );
    }

    /// Locate the `wz-e2e-liveliness-token` binary — the minimal
    /// liveliness-token-DECLARER facade-subset e2e consumer (R283;
    /// symmetric sibling of [`wz_e2e_liveliness_binary`]). Same
    /// debug/release lookup shape; the Layer E2 lane builds it under its
    /// pinned subset before the e2e test drives it.
    pub fn wz_e2e_liveliness_token_binary() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/wz-e2e-liveliness-token"),
            crates_dir.join("target/release/wz-e2e-liveliness-token"),
        ];
        for c in &candidates {
            if c.is_file() {
                return c.clone();
            }
        }
        panic!(
            "wz-e2e-liveliness-token binary not found in {candidates:?}; \
             run `cargo build -p wz-e2e-liveliness-token` first"
        );
    }

    /// Locate the `wz-e2e-declare-observer` binary — the minimal
    /// declare-observer facade-subset e2e consumer (inbound-declare
    /// OBSERVER; wz passively decodes a foreign z_sub's proactive
    /// `DeclSubscriber`). Same debug/release lookup shape; the Layer E2
    /// lane builds it under its pinned subset before the e2e test drives
    /// it, so a missing binary is a CI-prep error surfaced as a panic,
    /// not a graceful SKIP.
    pub fn wz_e2e_declare_observer_binary() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/wz-e2e-declare-observer"),
            crates_dir.join("target/release/wz-e2e-declare-observer"),
        ];
        for c in &candidates {
            if c.is_file() {
                return c.clone();
            }
        }
        panic!(
            "wz-e2e-declare-observer binary not found in {candidates:?}; \
             run `cargo build -p wz-e2e-declare-observer` first"
        );
    }

    /// Locate a zenoh-pico CLI binary under `target/zenoh-pico-cli/`.
    /// `scripts/build-zenoh-pico-cli.sh` produces `z_put`, `z_sub`,
    /// `z_get`, `z_queryable`; pass the bare name and this helper
    /// panics with the install hint if the binary is missing.
    pub fn zenoh_pico_cli_binary(name: &str) -> PathBuf {
        let path = project_root().join("target/zenoh-pico-cli").join(name);
        assert!(
            path.is_file(),
            "{name} binary missing at {}; run scripts/build-zenoh-pico-cli.sh first",
            path.display()
        );
        path
    }

    /// Locate the `zenohd` (zenoh-full REFERENCE Rust router) binary: the
    /// `WZ_ZENOHD_BIN` env override, else `scripts/build-zenohd.sh`'s
    /// `target/zenohd/zenohd` install. zenohd is NOT a wz build artifact
    /// (zenoh is not a wz dependency), so it is built on demand; this panics
    /// with the build hint if absent — the same prereq discipline as
    /// [`zenoh_pico_cli_binary`].
    pub fn zenohd_binary() -> PathBuf {
        if let Ok(p) = std::env::var("WZ_ZENOHD_BIN") {
            return PathBuf::from(p);
        }
        let path = project_root().join("target/zenohd/zenohd");
        assert!(
            path.is_file(),
            "zenohd binary missing at {}; set WZ_ZENOHD_BIN or run scripts/build-zenohd.sh first",
            path.display()
        );
        path
    }

    /// Rewind the file to the start and slurp the entire current
    /// contents into a UTF-8 string, replacing any non-UTF-8 byte
    /// sequence with the U+FFFD replacement character. Used to
    /// inspect a child process's stderr/stdout that was captured to a
    /// tempfile.
    ///
    /// Non-UTF-8 bytes do appear in practice on this surface — e.g. a
    /// child panic backtrace under tokio's worker-thread pool can
    /// interleave with a libc-side `abort(3)` message at byte
    /// granularity, producing a mid-codepoint truncation. The R215
    /// pre-rewrite of this helper used `read_to_string + .expect` and
    /// panicked on the first invalid byte, masking the captured
    /// content from the caller and surfacing as a sporadic Layer E
    /// flake (`stream did not contain valid UTF-8`). R304 retires
    /// the strict decode so the panic path now surfaces the byte
    /// content (lossy-decoded with U+FFFD markers at the offending
    /// position) — diagnostic, not blocking. Caught at the R302b
    /// pre-push gate, fixed in this round before retry.
    pub fn read_captured(file: &mut File) -> String {
        file.seek(SeekFrom::Start(0)).expect("seek to start");
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("read captured bytes");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Deadline for the zenoh-pico `z_sub` CLI's "Opening session"
    /// init witness. The 50 ms `wait_for_substring` polling cadence
    /// is unchanged; this constant is the worst-case envelope under
    /// which the child must reach session-open. R311a-pre raises the
    /// previous 5 s figure to 10 s because R309 recorded one Layer E
    /// trial out of 60 in which `z_sub` legitimately took longer
    /// than 5 s to print "Opening session" (verified non-wz-side
    /// cause via R310 30/30 + R310.5a/b/c 90/90 wz-side flake-0
    /// rerun); the actual fast-path observation is well under 500 ms
    /// on a quiescent localhost, so 10 s is a ~20× safety margin
    /// without slowing the Layer E lane on the common path.
    ///
    /// Shared across the three `z_sub`-consuming integration tests
    /// (`wz_publisher_to_zsub`, `wz_publisher_aliased_to_zsub`,
    /// `wz_publisher_del_to_zsub`) so a future raise touches one
    /// constant instead of three call sites.
    pub const Z_SUB_INIT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Poll `127.0.0.1:port` every 50 ms until a TCP connect succeeds (a
    /// spawned listener / router is accepting) or `timeout` elapses, returning
    /// `true` once it accepts. Readiness for a spawned process whose stderr is
    /// not capturable as a stable readiness line — e.g. `zenohd`, which
    /// block-buffers its startup logs to a non-TTY fd so a stderr-substring wait
    /// races the flush; a successful TCP connect proves the listener is up.
    pub fn wait_for_tcp_accept(port: u16, timeout: Duration) -> bool {
        use std::net::TcpStream;
        let deadline = Instant::now() + timeout;
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Poll the captured tempfile every 50 ms until either `needle`
    /// appears in the contents or `timeout` elapses. Returns the
    /// matching snapshot on success or the final captured snapshot
    /// on timeout so the caller can surface it in a panic message.
    pub fn wait_for_substring(
        file: &mut File,
        needle: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let captured = read_captured(file);
            if captured.contains(needle) {
                return Ok(captured);
            }
            if Instant::now() >= deadline {
                return Err(captured);
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// RAII guard for a spawned `std::process::Child` that guarantees
    /// the process is killed + reaped even if the calling test panics
    /// between `spawn()` and the explicit cleanup line. R305 retires
    /// the orphan-leak pattern surfaced at the R302b pre-push gate:
    /// a `read_captured` panic in `wz_initiator_to_wz_acceptor` left
    /// two `wz-ap-demo` children alive for 23 minutes (verified via
    /// `fuser`), inheriting the parent shell's `.git/run-ci.lock` fd
    /// 200 and blocking every subsequent `git push` with
    /// `another run-ci already running` until manual `kill(1)`.
    ///
    /// The Drop impl is idempotent. Explicit `child_mut().kill()` /
    /// `.wait()` calls before the guard scope exits do the textbook
    /// graceful shutdown; the guard's Drop then runs `kill` (returns
    /// `ESRCH` on the already-reaped child — `let _ = ...`-ignored)
    /// and `wait` (returns the cached `ExitStatus`). Tests that
    /// previously held a raw `Child` keep the same call shape via
    /// `guard.child_mut().kill()`.
    pub struct ChildGuard {
        child: Child,
        label: String,
    }

    impl ChildGuard {
        /// Wrap an already-spawned `Child` in the panic-safe guard.
        /// Pass a short human label (e.g. `"wz-ap-demo acceptor"`)
        /// for forensic logs; the label is exposed via `label()` but
        /// otherwise opaque.
        pub fn wrap(label: impl Into<String>, child: Child) -> Self {
            Self {
                child,
                label: label.into(),
            }
        }

        /// Mutable access to the wrapped `Child` for direct
        /// `.kill()` / `.wait()` / `.id()` usage. Tests that want
        /// graceful shutdown call `guard.child_mut().kill()` followed
        /// by `guard.child_mut().wait()`; the Drop impl is the safety
        /// net for the panic path.
        pub fn child_mut(&mut self) -> &mut Child {
            &mut self.child
        }

        /// Human-readable label captured at `wrap()` time. Surfaced
        /// only via tests' own panic messages; not part of any
        /// behavioural contract.
        pub fn label(&self) -> &str {
            &self.label
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            // Best-effort kill + reap. Both calls tolerate prior
            // explicit `.kill()` / `.wait()` from the test body:
            // - `Child::kill` returns `ESRCH` when the process has
            //   already exited; the `let _` discards the result.
            // - `Child::wait` caches the `ExitStatus` after the first
            //   successful call and returns the cached value on
            //   subsequent calls, so a second `.wait()` is cheap.
            // The ordering matters when the test body panicked
            // BEFORE any explicit cleanup: kill first sends SIGKILL,
            // wait then reaps the zombie. Without `wait` the child
            // would persist as a zombie until the test runner exit.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Send `SIGTERM` to `child` via `kill -TERM <pid>`, then poll
    /// `try_wait()` every 50 ms until either the process exits or
    /// `timeout` elapses, in which case `Child::kill` (SIGKILL on
    /// Linux) is the fallback.
    ///
    /// Used by integration tests that want to exercise the
    /// graceful-shutdown path of `wz-ap-demo` — `LivelinessToken`'s
    /// RAII Drop emits `Declare(UndeclToken)` on the wire only when
    /// the binary receives SIGTERM through `shutdown_signal()` and
    /// runs its tokio drop ordering. SIGKILL bypasses Rust Drop
    /// entirely, so a raw `Child::kill` skips the Drop emit; this
    /// helper exists to make the SIGTERM-first contract explicit.
    ///
    /// R305 lifts the helper from per-test duplicates
    /// (`wz_remote_declare_round_trip` + `wz_liveliness_subscriber_
    /// round_trip` carried verbatim copies) into the shared common
    /// module so a future signature change (e.g. accepting `&mut
    /// ChildGuard` instead of `&mut Child`) lands in one place.
    pub fn graceful_terminate(child: &mut Child, timeout: Duration) {
        let pid = child.id().to_string();
        let _ = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(&pid)
            .status();
        let start = Instant::now();
        while start.elapsed() < timeout {
            match child.try_wait() {
                Ok(Some(_status)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
        // SIGTERM did not produce a graceful exit within the budget —
        // fall back to SIGKILL so the test does not hang.
        let _ = child.kill();
        let _ = child.wait();
    }

    // ── multicast interop SSOT (shared by the wz<->pico multicast lanes) ──

    /// zenoh's well-known IPv4 multicast group (`Z_CONFIG_MULTICAST_
    /// LOCATOR_DEFAULT` host part). Both multicast interop lanes
    /// (`wz_publisher_to_pico_multicast_zsub`,
    /// `wz_subscriber_from_pico_multicast`) join this group; each picks
    /// its own distinct PORT so the `--ignored` lanes never contend on a
    /// single bind.
    pub const ZENOH_MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);

    /// zenoh-pico's shipped CONFIG constants, pinned to the VENDORED pico
    /// tree. wz's multicast JOIN params must advertise exactly these for
    /// pico's admission (and wz's own `ingest_join` §3.2 check) to admit
    /// the peer in EITHER direction; a submodule pin bump that shifts any
    /// of them surfaces here as an obvious edit, not a silent admission
    /// rejection. NOTE: these are pico CONFIG values, NOT wz PROTOCOL
    /// defaults — wz's `PROTOCOL_DEFAULT_BATCH_SIZE` is 8192, which pico
    /// would reject; the controlling requirement is pico-config-match.
    /// The `MulticastParams` builder that consumes them stays in each test
    /// (the type is a dev-dependency of this crate, unusable from the lib
    /// body); pinning the VALUES here removes the cross-lane drift risk
    /// without dragging wz-session-core into the lib's dependency graph
    /// (which would defeat the resolver-2 dev-dep isolation, R311nm/nl).
    pub const PICO_PROTO_VERSION: u8 = 0x09; // config.h.in Z_PROTO_VERSION
    pub const PICO_SN_RESOLUTION: u8 = 0x02; // config.h.in Z_SN_RESOLUTION / Z_REQ_RESOLUTION
    pub const PICO_BATCH_MULTICAST_SIZE: u16 = 2_048; // CMakeLists.txt BATCH_MULTICAST_SIZE

    /// The default-route interface name, e.g. `wlp0s20f3`. This is the
    /// interface wz's `INADDR_ANY` multicast egress/join selects (no
    /// explicit `224.0.0.0/4` route → kernel uses the default route), so
    /// pinning pico's `#iface=` to it makes both peers share the link.
    /// Panics if there is no default route (the env-dependent multicast
    /// Layer M lanes require one).
    pub fn default_route_iface() -> String {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .expect("run `ip route show default`");
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let mut toks = line.split_whitespace();
            while let Some(tok) = toks.next() {
                if tok == "dev" {
                    if let Some(dev) = toks.next() {
                        return dev.to_string();
                    }
                }
            }
        }
        panic!(
            "no default-route interface from `ip route show default`; the \
             environment-dependent multicast interop lanes need one (Layer M)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::common::ChildGuard;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    /// `kill -0 <pid>` portable liveness probe. Returns `true` when
    /// the kernel still tracks the PID (process exists, possibly
    /// zombie), `false` on `ESRCH` (process reaped / never existed).
    /// Pure shell command so the test stays std-only without pulling
    /// `nix` / `libc` into wz-integration-tests's dev-deps.
    fn pid_alive(pid: u32) -> bool {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .expect("spawn kill -0")
            .success()
    }

    #[test]
    fn child_guard_drop_kills_running_child_on_normal_exit() {
        let child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep 60");
        let pid = child.id();
        assert!(pid_alive(pid), "sleep PID {pid} not alive after spawn");
        {
            let _guard = ChildGuard::wrap("sleep-60 normal-exit probe", child);
            // Guard goes out of scope at the end of this block → Drop
            // runs → kill + wait. No explicit cleanup; this exercises
            // the safety-net path that the panic-unwind case also
            // walks.
        }
        // SIGKILL + waitpid reap is synchronous in `Child::kill` +
        // `Child::wait`, so the process should be gone by the time
        // control returns from the inner scope. A 100 ms safety
        // window absorbs scheduler jitter on a loaded CI host.
        thread::sleep(Duration::from_millis(100));
        assert!(
            !pid_alive(pid),
            "ChildGuard::drop did not reap PID {pid} after scope exit"
        );
    }

    #[test]
    fn child_guard_drop_kills_running_child_on_panic_unwind() {
        // Mechanical proof that the panic-unwind path through
        // ChildGuard's Drop is the same as the normal-exit path —
        // the orphan-leak that caused the R302b push-time
        // `.git/run-ci.lock` outage is now mechanically prevented.
        //
        // The Arc<Mutex<Option<u32>>> carries the child's PID out of
        // the catch_unwind scope so the assertion can verify the
        // process actually died (a normal `let pid` would be lost on
        // unwind).
        let pid_holder: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let holder_for_closure = pid_holder.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("spawn sleep 60");
            *holder_for_closure.lock().expect("pid holder mutex") = Some(child.id());
            let _guard = ChildGuard::wrap("sleep-60 panic-unwind probe", child);
            panic!("simulated test panic — ChildGuard's Drop should still reap");
        }));
        assert!(
            result.is_err(),
            "catch_unwind did not observe the simulated panic"
        );
        let pid = pid_holder
            .lock()
            .expect("pid holder mutex post-catch")
            .expect("ChildGuard never published its PID");
        thread::sleep(Duration::from_millis(100));
        assert!(
            !pid_alive(pid),
            "ChildGuard::drop did not reap PID {pid} after panic-unwind"
        );
    }
}
