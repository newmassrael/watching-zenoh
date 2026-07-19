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
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
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
            let (listener, port) = Self::bind_ephemeral();
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
            // Bind BOTH before dropping either: holding l1 while binding l2 is
            // what guarantees p1 != p2 (a bind-then-drop helper called twice
            // could hand back the same port). The shared bind/extract is
            // [`bind_ephemeral`]; the drop timing is the per-caller part.
            let (l1, p1) = Self::bind_ephemeral();
            let (l2, p2) = Self::bind_ephemeral();
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

        /// Bind a fresh ephemeral loopback listener and return it WITH its
        /// port — the bind/extract the single and dual reservations share
        /// (R311pp). The caller owns the drop: [`pick`](Self::pick) drops at
        /// once, [`pick_pair`](Self::pick_pair) holds both bound until two
        /// distinct ports are read (so the OS cannot re-hand the first).
        fn bind_ephemeral() -> (TcpListener, u16) {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
            let port = listener.local_addr().expect("local_addr").port();
            (listener, port)
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

    /// Locate the `wz-e2e-silent-peer` binary — the R311y338 test double
    /// that completes the session handshake and then never answers a
    /// Request. Same debug/release lookup shape as its siblings; Layer E
    /// builds it before the query-timeout e2e drives it, so a missing
    /// binary is a CI-prep error surfaced as a panic, not a graceful SKIP.
    ///
    /// Its silence is enforced by its manifest (no `codec-response` /
    /// `codec-response-final` / `query-queryable`, so a Reply and a
    /// ResponseFinal are types it does not have), which is the whole reason
    /// it exists — see its `Cargo.toml`.
    pub fn wz_e2e_silent_peer_binary() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/wz-e2e-silent-peer"),
            crates_dir.join("target/release/wz-e2e-silent-peer"),
        ];
        for c in &candidates {
            if c.is_file() {
                return c.clone();
            }
        }
        panic!(
            "wz-e2e-silent-peer binary not found in {candidates:?}; \
             run `cargo build -p wz-e2e-silent-peer` first"
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

    /// Locate the `zenoh-plugin-storage-manager` dynamic plugin
    /// (`libzenoh_plugin_storage_manager.so`): the `WZ_STORAGE_MANAGER_SO`
    /// env override, else `scripts/build-zenohd.sh`'s
    /// `target/zenohd/libzenoh_plugin_storage_manager.so` install. Loaded by
    /// zenohd via `--plugin "storage_manager:<path>"` for the A10 storage
    /// replication interop (`tests/wz_zenohd_storage_replication.rs`). The
    /// plugin must be built from the SAME zenoh source as `zenohd_binary`
    /// (matching version + rustc) so the plugin ABI-compat hash matches and
    /// zenohd loads it; `build-zenohd.sh` builds both from one checkout.
    /// Panics with the build hint if absent — the same prereq discipline as
    /// [`zenohd_binary`].
    pub fn storage_manager_plugin() -> PathBuf {
        if let Ok(p) = std::env::var("WZ_STORAGE_MANAGER_SO") {
            return PathBuf::from(p);
        }
        let path = project_root().join("target/zenohd/libzenoh_plugin_storage_manager.so");
        assert!(
            path.is_file(),
            "storage-manager plugin missing at {}; set WZ_STORAGE_MANAGER_SO or run scripts/build-zenohd.sh first",
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

    /// Spawn a `wz-ap-demo` acceptor (`--listen <addr> --key <key>`), routing
    /// the child's stderr into the caller-supplied `stderr` tempfile, and wrap
    /// it in a panic-safe [`ChildGuard`]. Returns the guard plus the readable
    /// capture handle (the same `stderr` File, ready for [`wait_for_substring`]).
    ///
    /// R311q1 — lifted from three near-verbatim per-test copies (the
    /// `wz_initiator_*` round-trip tests + the sever-reconnect e2e all spawn an
    /// identical `--listen --key` acceptor differing only in the keyexpr and
    /// label), the same per-test-duplicate consolidation R305 applied to
    /// [`graceful_terminate`]. The `tempfile` crate is a dev-dependency (unusable
    /// from this lib target), so the caller owns the `tempfile::tempfile()` call
    /// and passes the File in; the helper owns the dup-for-child + Command shape
    /// + ChildGuard wrapping, which is the duplicated bulk.
    pub fn spawn_listen_acceptor(
        demo: &Path,
        addr: &str,
        key: &str,
        label: &str,
        stderr: File,
    ) -> (ChildGuard, File) {
        let writer = stderr.try_clone().expect("dup acceptor stderr handle");
        let guard = ChildGuard::wrap(
            label.to_string(),
            Command::new(demo)
                .arg("--listen")
                .arg(addr)
                .arg("--key")
                .arg(key)
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer))
                .spawn()
                .expect("spawn wz-ap-demo --listen acceptor"),
        );
        (guard, stderr)
    }

    /// Parse the bound port from a node's `listening on 127.0.0.1:<port>`
    /// log line — the ephemeral-port read-back that lets the next node
    /// dial this one without a reserved-port allocation.
    ///
    /// R311y138 — lifted from four byte-identical per-test copies
    /// (`wz_peer_data_forward`, `wz_peer_adminspace_config_write`,
    /// `wz_router_hat_mesh`, `wz_router_hat_pico_interop`), the same
    /// per-test-duplicate consolidation R216 / R305 / R311q1 applied to
    /// the port picker, `graceful_terminate`, and `spawn_listen_acceptor`.
    pub fn listen_port(captured: &str) -> u16 {
        let marker = "listening on 127.0.0.1:";
        let rest = captured
            .split(marker)
            .nth(1)
            .unwrap_or_else(|| panic!("no '{marker}' in:\n{captured}"));
        rest.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or_else(|e| panic!("unparseable port after '{marker}': {e}\n{captured}"))
    }

    /// Spawn a `wz-ap-demo` node that binds an EPHEMERAL port
    /// (`… 127.0.0.1:0`), wait until it logs `listen_marker`, and read the
    /// bound port back via [`listen_port`]. Routes the child's stderr into
    /// the caller-supplied `stderr` tempfile (the [`spawn_listen_acceptor`]
    /// caller-owns-File convention — `tempfile` is a dev-dependency unusable
    /// from this lib target) and wraps the child in a panic-safe
    /// [`ChildGuard`]. `listen_marker` is the role-specific listen-line prefix
    /// (`"router-hat: listening on 127.0.0.1:"` /
    /// `"peer: listening on 127.0.0.1:"`), so one spawner serves every
    /// ephemeral-bind node kind.
    ///
    /// R311y138 — lifted from `wz_router_hat_mesh::spawn_node` +
    /// `wz_router_hat_pico_interop::spawn_router_hat` (near-verbatim copies).
    pub fn spawn_on_ephemeral_port(
        demo: &Path,
        args: &[&str],
        listen_marker: &str,
        label: &str,
        stderr: File,
    ) -> (ChildGuard, File, u16) {
        let writer = stderr.try_clone().expect("dup node stderr handle");
        let mut reader = stderr;
        let mut guard = ChildGuard::wrap(
            label,
            Command::new(demo)
                .args(args)
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer))
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
        );
        let captured = wait_for_substring(&mut reader, listen_marker, Duration::from_secs(5))
            .unwrap_or_else(|c| {
                let _ = guard.child_mut().kill();
                let _ = guard.child_mut().wait();
                panic!("{label} did not bind within 5s\n--- {label} stderr ---\n{c}");
            });
        let port = listen_port(&captured);
        (guard, reader, port)
    }

    /// Spawn a zenoh-pico `z_sub` as a CLIENT of a router
    /// (`-e <endpoint> -m client`), returned once its session is OPEN and the
    /// subscriber DECLARED (`"Declaring Subscriber on"`). `stdbuf -oL -eL`
    /// forces line buffering (pico's CLI block-buffers non-TTY stdout, else its
    /// `Received` line never reaches the file); the 6-attempt retry absorbs
    /// pico's non-self-retrying one-shot open transient
    /// (`"Unable to open session!"`) — robustness for a FOREIGN binary, not a
    /// wz workaround. `router_label` names the dial target in the give-up panic;
    /// `mk_stderr` is the per-attempt stdout tempfile factory (the caller owns
    /// the dev-dependency `tempfile::tempfile()` call, once per attempt).
    ///
    /// Why the retry, honestly (R311pf / R311pi): the pico open transient was NOT
    /// reproduced synthetically (~200+ opens under 5x CPU oversubscription produced
    /// zero failures), so the mechanism is a HYPOTHESIS — scheduler starvation of the
    /// handshake window under full-run-ci load — not a verified fact; a router-side
    /// handshake stall is not excludable (the symptom `z_open() < 0` is reported on
    /// the pico side and would look identical either way). Callers should gate their
    /// router's cold-start where they can (the zenohd caller drives a wz handshake to
    /// Established first); this retry is the residual client-side safety net for a
    /// foreign one-shot that cannot self-retry.
    ///
    /// R311y138 — lifted from the ~95%-identical
    /// `wz_to_zenohd_router::spawn_subscribed_zsub` +
    /// `wz_router_hat_pico_interop::spawn_subscribed_pico_zsub` into one SSOT.
    pub fn spawn_subscribed_zsub(
        z_sub: &Path,
        sub_key: &str,
        endpoint: &str,
        router_label: &str,
        mut mk_stderr: impl FnMut() -> File,
    ) -> (ChildGuard, File) {
        const ATTEMPTS: usize = 6;
        for attempt in 1..=ATTEMPTS {
            let out = mk_stderr();
            let out_writer = out.try_clone().expect("dup z_sub stdout handle");
            let mut out_reader = out;
            let mut child = ChildGuard::wrap(
                "z_sub client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(z_sub)
                    .args(["-k", sub_key, "-e", endpoint, "-m", "client"])
                    .stdout(Stdio::from(out_writer))
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn z_sub via stdbuf"),
            );
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let cap = read_captured(&mut out_reader);
                if cap.contains("Declaring Subscriber on") {
                    return (child, out_reader); // session open + subscriber declared
                }
                if cap.contains("Unable to open session") || Instant::now() >= deadline {
                    break; // transient open failure / timeout -> respawn
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            eprintln!("z_sub open attempt {attempt}/{ATTEMPTS} did not subscribe; retrying");
        }
        panic!("pico z_sub failed to open a session to {router_label} after {ATTEMPTS} attempts");
    }

    /// Spawn a zenoh-pico `z_pub` against a router (`-e <endpoint> -m client`)
    /// and return it once it has opened a session, declared its publisher, and
    /// begun putting (stdout `"Putting Data"`). Publishes `-n 30` times with a
    /// `z_sleep_s(1)` before each Put, so the burst spans ~30s — the caller
    /// spawns this only AFTER the matching subscription has propagated to the
    /// router, so every Put in the burst lands on an already-installed route
    /// (no one-shot drop to race). Like [`spawn_subscribed_zsub`], the 6-attempt
    /// retry absorbs pico's non-self-retrying one-shot open transient
    /// (`"Unable to open session!"`) — robustness for a FOREIGN binary, not a wz
    /// workaround. `router_label` names the dial target in the give-up panic;
    /// `mk_stdout` is the per-attempt stdout tempfile factory (the caller owns
    /// the dev-dependency `tempfile::tempfile()` call, once per attempt, since
    /// the lib crate cannot depend on the dev-only `tempfile`).
    ///
    /// R311y140 — lifted from `wz_to_zenohd_router::spawn_publishing_zpub` into
    /// this SSOT when the wz-router-hat <-> zenohd router-tier interop test
    /// (`wz_router_hat_zenohd_interop`) became its second consumer, the same
    /// second-user trigger that lifted [`spawn_subscribed_zsub`] in R311y138.
    pub fn spawn_publishing_zpub(
        z_pub: &Path,
        key: &str,
        value: &str,
        endpoint: &str,
        router_label: &str,
        mut mk_stdout: impl FnMut() -> File,
    ) -> ChildGuard {
        const ATTEMPTS: usize = 6;
        for attempt in 1..=ATTEMPTS {
            let out = mk_stdout();
            let out_writer = out.try_clone().expect("dup z_pub stdout handle");
            let mut out_reader = out;
            let mut child = ChildGuard::wrap(
                "z_pub client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(z_pub)
                    .args([
                        "-k", key, "-v", value, "-e", endpoint, "-m", "client", "-n", "30",
                    ])
                    .stdout(Stdio::from(out_writer))
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn z_pub via stdbuf"),
            );
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let cap = read_captured(&mut out_reader);
                if cap.contains("Putting Data") {
                    return child; // session open + publisher declared + publishing
                }
                if cap.contains("Unable to open session") || Instant::now() >= deadline {
                    break; // transient open failure / timeout -> respawn
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            eprintln!("z_pub open attempt {attempt}/{ATTEMPTS} did not start publishing; retrying");
        }
        panic!("pico z_pub failed to open a session to {router_label} after {ATTEMPTS} attempts");
    }

    /// Spawn a zenoh-pico `z_queryable` against a router (`-e <endpoint> -m
    /// client`) and return it once it has opened a session and declared its
    /// queryable (stdout `"Creating Queryable on"` — the pico example's
    /// pre-declare line; there is no "Declaring Queryable" string). Answers every
    /// matching query with a single Put-form reply carrying `value`. Like
    /// [`spawn_subscribed_zsub`], the 6-attempt retry absorbs pico's
    /// non-self-retrying one-shot open transient (`"Unable to open session!"`) —
    /// robustness for a FOREIGN binary, not a wz workaround. `router_label` names
    /// the dial target in the give-up panic; `mk_stdout` is the per-attempt
    /// stdout tempfile factory (the caller owns the dev-dependency
    /// `tempfile::tempfile()` call, since the lib crate cannot depend on the
    /// dev-only `tempfile`). Returns `(ChildGuard, File)` — the `File` is the
    /// stdout reader so a caller can later assert the foreign-side
    /// `"[Queryable handler] Received Query"` witness.
    pub fn spawn_answering_zqueryable(
        z_queryable: &Path,
        key: &str,
        value: &str,
        endpoint: &str,
        router_label: &str,
        mut mk_stdout: impl FnMut() -> File,
    ) -> (ChildGuard, File) {
        const ATTEMPTS: usize = 6;
        for attempt in 1..=ATTEMPTS {
            let out = mk_stdout();
            let out_writer = out.try_clone().expect("dup z_queryable stdout handle");
            let mut out_reader = out;
            let mut child = ChildGuard::wrap(
                "z_queryable client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(z_queryable)
                    .args(["-k", key, "-v", value, "-e", endpoint, "-m", "client"])
                    .stdout(Stdio::from(out_writer))
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn z_queryable via stdbuf"),
            );
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let cap = read_captured(&mut out_reader);
                if cap.contains("Creating Queryable on") {
                    return (child, out_reader); // session open + queryable declared
                }
                if cap.contains("Unable to open session") || Instant::now() >= deadline {
                    break; // transient open failure / timeout -> respawn
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            eprintln!("z_queryable open attempt {attempt}/{ATTEMPTS} did not declare; retrying");
        }
        panic!(
            "pico z_queryable failed to open a session to {router_label} after {ATTEMPTS} attempts"
        );
    }

    /// Spawn a zenoh-pico `z_querier` (the PERSISTENT querier — the only pico CLI
    /// that installs a querier write-filter, unlike the one-shot `z_get`) against
    /// a router (`-e <endpoint> -m client`) and return it once it has opened a
    /// session and declared its querier (stdout `"Declaring Querier on"`). Issues
    /// an `-n 30` get burst (one `z_querier_get` per second) so delivery is
    /// self-healing across the route install, mirroring [`spawn_publishing_zpub`].
    /// `-t 3000` overrides pico's 10 s `Z_GET_TIMEOUT_DEFAULT` so an unanswered
    /// query (sent into a not-yet-installed reverse route) retries on a ~3 s
    /// cadence instead of stalling ~10 s — restoring parity with the 1/s put
    /// burst. Selector is passed via `-s` (NOT `-k`, which z_querier does not
    /// accept). The 6-attempt retry absorbs pico's non-self-retrying one-shot
    /// open transient, as for [`spawn_subscribed_zsub`]. Returns
    /// `(ChildGuard, File)` — the `File` is the stdout reader on which the caller
    /// asserts the reply witness `">> Received ('"`.
    ///
    /// `matching` adds `-a` (a background matching listener): the querier then also
    /// prints `"Querier has matching queryable."` on write-filter DEACTIVATION and
    /// `"Querier has NO MORE matching queryables."` on RE-ARM — the pico-side
    /// positive observables of the wz future-push / undeclare-re-arm. Pass `false`
    /// for the plain reply-witness legs.
    pub fn spawn_querying_zquerier(
        z_querier: &Path,
        selector: &str,
        endpoint: &str,
        router_label: &str,
        matching: bool,
        mut mk_stdout: impl FnMut() -> File,
    ) -> (ChildGuard, File) {
        const ATTEMPTS: usize = 6;
        for attempt in 1..=ATTEMPTS {
            let out = mk_stdout();
            let out_writer = out.try_clone().expect("dup z_querier stdout handle");
            let mut out_reader = out;
            let mut child = ChildGuard::wrap(
                "z_querier client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(z_querier)
                    .args([
                        "-s", selector, "-e", endpoint, "-m", "client", "-n", "30", "-t", "3000",
                    ])
                    // `matching` adds `-a`: z_querier declares a background matching
                    // listener that prints "Querier has matching queryable." when its
                    // write-filter DEACTIVATES (a queryable matched) and "Querier has
                    // NO MORE matching queryables." when it RE-ARMS (all withdrawn) —
                    // the positive cross-impl observables of the y150 future-push and
                    // the y151 undeclare-re-arm on the pico querier's OWN filter state.
                    .args(matching.then_some("-a"))
                    .stdout(Stdio::from(out_writer))
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn z_querier via stdbuf"),
            );
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let cap = read_captured(&mut out_reader);
                if cap.contains("Declaring Querier on") {
                    return (child, out_reader); // session open + querier declared
                }
                if cap.contains("Unable to open session") || Instant::now() >= deadline {
                    break; // transient open failure / timeout -> respawn
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            eprintln!("z_querier open attempt {attempt}/{ATTEMPTS} did not declare; retrying");
        }
        panic!(
            "pico z_querier failed to open a session to {router_label} after {ATTEMPTS} attempts"
        );
    }

    /// Spawn a zenoh-pico `z_liveliness` (a client + liveliness-TOKEN declarer)
    /// against `endpoint`, blocking until it has declared its token (the
    /// `Declaring liveliness token '<keyexpr>'...` readiness line). No `-t` is
    /// passed, so the token is held for the process's whole lifetime — z_liveliness
    /// undeclares only on exit / socket close, so killing the child triggers the
    /// UndeclareToken flood the undeclare half of the token cross-impl leg observes.
    /// The liveliness-token twin of [`spawn_answering_zqueryable`], with the same
    /// 6-attempt foreign-one-shot open-retry.
    pub fn spawn_liveliness_token(
        z_liveliness: &Path,
        keyexpr: &str,
        endpoint: &str,
        router_label: &str,
        mut mk_stdout: impl FnMut() -> File,
    ) -> (ChildGuard, File) {
        const ATTEMPTS: usize = 6;
        for attempt in 1..=ATTEMPTS {
            let out = mk_stdout();
            let out_writer = out.try_clone().expect("dup z_liveliness stdout handle");
            let mut out_reader = out;
            let mut child = ChildGuard::wrap(
                "z_liveliness client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(z_liveliness)
                    .args(["-k", keyexpr, "-e", endpoint, "-m", "client"])
                    .stdout(Stdio::from(out_writer))
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn z_liveliness via stdbuf"),
            );
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let cap = read_captured(&mut out_reader);
                if cap.contains("Declaring liveliness token") {
                    return (child, out_reader); // session open + token declared
                }
                if cap.contains("Unable to open session") || Instant::now() >= deadline {
                    break; // transient open failure / timeout -> respawn
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            eprintln!("z_liveliness open attempt {attempt}/{ATTEMPTS} did not declare; retrying");
        }
        panic!(
            "pico z_liveliness failed to open a session to {router_label} after {ATTEMPTS} attempts"
        );
    }

    /// Spawn a zenoh-pico `z_sub_liveliness` (a client + liveliness SUBSCRIBER)
    /// against `endpoint`, blocking until it has declared its subscriber (the
    /// `Declaring liveliness subscriber on '<keyexpr>'...` readiness line). No `-h`
    /// is passed, so the subscriber's token interest is FUTURE-only (no
    /// CURRENT/history bit, pico `src/net/liveliness.c` `mode = FUTURE`) — a token
    /// therefore reaches it ONLY via the router's proactive future push, making the
    /// router's `future_token_pushes_seen()` a deterministic discriminator (no
    /// CURRENT dump to race). Its handler prints `New alive token ('<ke>')` on a
    /// token declaration and `Dropped token ('<ke>')` on an undeclare. Same
    /// 6-attempt open-retry as the other pico client helpers.
    pub fn spawn_liveliness_subscriber(
        z_sub_liveliness: &Path,
        keyexpr: &str,
        endpoint: &str,
        router_label: &str,
        mut mk_stdout: impl FnMut() -> File,
    ) -> (ChildGuard, File) {
        const ATTEMPTS: usize = 6;
        for attempt in 1..=ATTEMPTS {
            let out = mk_stdout();
            let out_writer = out.try_clone().expect("dup z_sub_liveliness stdout handle");
            let mut out_reader = out;
            let mut child = ChildGuard::wrap(
                "z_sub_liveliness client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(z_sub_liveliness)
                    .args(["-k", keyexpr, "-e", endpoint, "-m", "client"])
                    .stdout(Stdio::from(out_writer))
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn z_sub_liveliness via stdbuf"),
            );
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let cap = read_captured(&mut out_reader);
                if cap.contains("Declaring liveliness subscriber on") {
                    return (child, out_reader); // session open + subscriber declared
                }
                if cap.contains("Unable to open session") || Instant::now() >= deadline {
                    break; // transient open failure / timeout -> respawn
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            eprintln!(
                "z_sub_liveliness open attempt {attempt}/{ATTEMPTS} did not declare; retrying"
            );
        }
        panic!(
            "pico z_sub_liveliness failed to open a session to {router_label} after {ATTEMPTS} attempts"
        );
    }

    /// Spawn a zenohd router on the given `-l` listener locators and block until
    /// it is HANDSHAKE-ready. The spawn + two-stage readiness SSOT both zenohd
    /// spawn variants delegate to (R311pn). `--no-multicast-scouting` +
    /// `--rest-http-port none` keep it to the configured unicast listeners.
    ///
    /// Two-stage readiness (R311pi). First a TCP-accept probe on `accept_port`
    /// ([`wait_for_tcp_accept`]): a captured-stderr log-wait would race zenohd's
    /// block-buffered startup flush, so the connect is the listener-up signal.
    /// But TCP-accept proves only that the KERNEL accepted the SYN — not that
    /// zenohd's transport/routing tasks are scheduled and can complete a zenoh
    /// handshake. Under load there is a cold-start window between "listener up"
    /// and "handshake-ready" that a bare TCP-accept gate leaves open. So the
    /// second stage drives a real wz client to `Established` against
    /// `handshake_probe` ([`wait_for_zenohd_handshake_ready`]) before returning.
    ///
    /// `mk_probe_stderr` is the readiness-probe stderr tempfile factory (the
    /// caller owns the dev-dependency `tempfile::tempfile()` call, since the lib
    /// crate cannot depend on the dev-only `tempfile`) — same factory-closure
    /// shape as [`spawn_subscribed_zsub`] / [`spawn_publishing_zpub`].
    ///
    /// R311y140 — lifted from `wz_to_zenohd_router` into this SSOT when the
    /// wz-router-hat <-> zenohd router-tier interop test
    /// (`wz_router_hat_zenohd_interop`) became a second consumer, the same
    /// second-user trigger that lifted [`spawn_subscribed_zsub`] in R311y138.
    pub fn spawn_zenohd_listeners(
        listeners: &[String],
        accept_port: u16,
        handshake_probe: &str,
        mk_probe_stderr: impl FnMut() -> File,
    ) -> ChildGuard {
        let mut command = Command::new(zenohd_binary());
        for locator in listeners {
            command.arg("-l").arg(locator);
        }
        command
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ChildGuard::wrap(
            "zenohd (reference router)",
            command.spawn().expect("spawn zenohd"),
        );
        assert!(
            wait_for_tcp_accept(accept_port, Duration::from_secs(10)),
            "zenohd did not start accepting on 127.0.0.1:{accept_port} within 10s"
        );
        // R311pi — close the TCP-accept-vs-handshake-ready gap with a real wz session.
        wait_for_zenohd_handshake_ready(handshake_probe, mk_probe_stderr);
        guard
    }

    /// Spawn a TCP-only zenohd router on the reserved `port` and block until it
    /// is HANDSHAKE-ready. A single unicast TCP listener; both readiness gates
    /// target the one port. See [`spawn_zenohd_listeners`] for the readiness
    /// rationale and the `mk_probe_stderr` factory.
    pub fn spawn_zenohd(port: u16, mk_probe_stderr: impl FnMut() -> File) -> ChildGuard {
        spawn_zenohd_listeners(
            &[format!("tcp/127.0.0.1:{port}")],
            port,
            &format!("127.0.0.1:{port}"),
            mk_probe_stderr,
        )
    }

    /// R311y374 — spawn a zenohd that DIALS a wz `ws/...` acceptor
    /// (`-e ws/<wz_ws_endpoint>`) while also listening on `tcp/<tcp_port>` for a
    /// pico client. This is the FOREIGN WebSocket DIALER that verifies wz's new ws
    /// ACCEPTOR (the `bind_locator` ws arm + `accept_locator`'s RFC6455 server
    /// upgrade): zenoh-pico has NO ws client (`z_sub -e ws/...` returns "Unable to
    /// open session!"), so zenohd is the only foreign ws dialer available. Once
    /// the ws link Establishes, a pico `z_put` on the tcp listener routes through
    /// zenohd and ACROSS the ws link to the wz acceptor's subscriber — the
    /// cross-impl witness that wz accepts a foreign ws session AND carries data
    /// over it. Readiness = zenohd accepting on its tcp listener (the ws dial to
    /// wz is witnessed on the wz side: "ws server upgrade" + "session
    /// Established"). No handshake-probe param: unlike the `-l`-only helpers, this
    /// zenohd DIALS out, and the wz-side log is the Established witness.
    pub fn spawn_zenohd_ws_dialer(wz_ws_endpoint: &str, tcp_port: u16) -> ChildGuard {
        let mut command = Command::new(zenohd_binary());
        command
            .arg("-e")
            .arg(wz_ws_endpoint)
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ChildGuard::wrap(
            "zenohd (ws dialer)",
            command.spawn().expect("spawn zenohd ws dialer"),
        );
        assert!(
            wait_for_tcp_accept(tcp_port, Duration::from_secs(10)),
            "zenohd (ws dialer) did not start accepting tcp on 127.0.0.1:{tcp_port} within 10s"
        );
        guard
    }

    /// R311y372 — spawn a zenohd router with the LOWLATENCY unicast transport
    /// enabled. zenoh refuses `transport/unicast/lowlatency` unless qos is also
    /// disabled ("'lowlatency' is incompatible with 'qos'",
    /// DEFAULT_CONFIG.json5:541), so this passes BOTH `--cfg` overrides. A wz
    /// client that OFFERS Z_EXT_LOWLATENCY negotiates the lean (Frame-less)
    /// transport with this router; a non-offering client — including the
    /// handshake-readiness probe below and a pico `z_sub` (zenoh-pico has NO
    /// lowlatency transport) — transparently falls back to the UNIVERSAL
    /// transport on its own link, so the same router routes both sides of the
    /// lowlatency interop leg. Single `tcp/` listener; the readiness probe dials
    /// it universal (fallback), which Establishes against a lowlatency-enabled
    /// router just as a plain one does.
    pub fn spawn_zenohd_lowlatency(port: u16, mk_probe_stderr: impl FnMut() -> File) -> ChildGuard {
        let mut command = Command::new(zenohd_binary());
        command
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .arg("--cfg")
            .arg("transport/unicast/lowlatency:true")
            .arg("--cfg")
            .arg("transport/unicast/qos/enabled:false")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ChildGuard::wrap(
            "zenohd (reference router, lowlatency)",
            command.spawn().expect("spawn zenohd (lowlatency)"),
        );
        assert!(
            wait_for_tcp_accept(port, Duration::from_secs(10)),
            "zenohd (lowlatency) did not start accepting on 127.0.0.1:{port} within 10s"
        );
        wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), mk_probe_stderr);
        guard
    }

    /// Spawn a zenohd router listening on BOTH `tcp/` (for pico TCP clients) and
    /// `ws/` (for a wz WebSocket client) on the reserved ports, and block until
    /// it is HANDSHAKE-ready. R311pk — the dual-transport variant of
    /// [`spawn_zenohd`] for the WS legs: zenoh-pico has NO native WS link
    /// (emscripten-only), so pico dials TCP while wz dials WS, and zenohd routes
    /// between its two listeners. The TCP-accept gate targets `tcp_port` (pico
    /// dials it), and the handshake-ready probe drives a real wz client to
    /// `Established` over `ws/127.0.0.1:{ws_port}` — a genuine RFC6455 upgrade +
    /// zenoh handshake that exercises the WS listener directly. This REAL
    /// handshake is required, not a raw-TCP poke: R311pk's earlier bare
    /// `TcpStream::connect`-then-close (no upgrade) made zenoh's serial
    /// single-worker `zenoh-link-ws` accept task hit a tungstenite EOF, return
    /// `Err`, and self-delete — wedging every later `ws/` dial. A completed WS
    /// upgrade keeps the accept task alive, so it is the only sound WS-readiness
    /// signal.
    pub fn spawn_zenohd_tcp_ws(
        tcp_port: u16,
        ws_port: u16,
        mk_probe_stderr: impl FnMut() -> File,
    ) -> ChildGuard {
        spawn_zenohd_listeners(
            &[
                format!("tcp/127.0.0.1:{tcp_port}"),
                format!("ws/127.0.0.1:{ws_port}"),
            ],
            tcp_port,
            &format!("ws/127.0.0.1:{ws_port}"),
            mk_probe_stderr,
        )
    }

    /// R311y367 — the UDP counterpart of [`spawn_zenohd_tcp_ws`]: zenohd listens
    /// on BOTH `tcp/` (pico's TCP link + the readiness gate) and `udp/` (the wz
    /// datagram client). zenoh-pico dials TCP (its native udp link is
    /// scouting/multicast-oriented here), wz dials the `udp/` listener, and zenohd
    /// routes between its two listeners. UDP is a cert-free DATAGRAM transport
    /// already in the demo default (preset-ap-client = transport-link-{tcp,udp}),
    /// so unlike ws/tls/quic NO demo feature is needed.
    ///
    /// UNLIKE the ws/unixsock spawns, the readiness probe here dials `tcp/`, NOT
    /// the `udp/` listener under test (the TLS-style discipline). A `udp/` probe
    /// would open a SECOND wz->zenohd udp session that overlaps the test's udp
    /// client (the probe's session lingers on zenohd past the probe process until
    /// lease expiry), and two concurrent wz udp sessions on this loopback fail the
    /// second one to `Terminal` — so the probe must not hold a udp session. The
    /// `udp/` listener binds at startup like every `-l` listener, so a `tcp/`
    /// readiness gate confirms it is up, and the test body itself is the direct
    /// `udp/` handshake witness (leg 16). The probe drives a real wz `tcp/` client
    /// to `Established`, closing the TCP-accept-vs-routing-ready gap.
    pub fn spawn_zenohd_tcp_udp(
        tcp_port: u16,
        udp_port: u16,
        mk_probe_stderr: impl FnMut() -> File,
    ) -> ChildGuard {
        spawn_zenohd_listeners(
            &[
                format!("tcp/127.0.0.1:{tcp_port}"),
                format!("udp/127.0.0.1:{udp_port}"),
            ],
            tcp_port,
            &format!("127.0.0.1:{tcp_port}"),
            mk_probe_stderr,
        )
    }

    /// Spawn a zenohd router listening on BOTH `tcp/` (for pico TCP clients and
    /// the TCP-accept readiness gate) and `unixsock-stream/` (for a wz Unix-
    /// domain-socket client), and block until it is HANDSHAKE-ready. R311y364 —
    /// the unixsock counterpart of [`spawn_zenohd_tcp_ws`]: zenoh-pico has NO
    /// `unixsock-stream` link, so pico dials TCP while wz dials the Unix socket,
    /// and zenohd routes between its two listeners. The TCP-accept gate targets
    /// `tcp_port` (pico dials it), and the handshake-ready probe drives a real wz
    /// client to `Established` over `unixsock-stream/{sock_path}` — a genuine
    /// `UnixStream` connect + zenoh 4-way handshake that exercises the unixsock
    /// listener DIRECTLY (the same probe-the-actual-listener discipline
    /// [`spawn_zenohd_tcp_ws`] uses for WS; a full wz handshake, not a bare
    /// connect-then-close, so zenoh's accept task is left healthy).
    ///
    /// `sock_path` is an ABSOLUTE filesystem path (so the emitted locator is
    /// `unixsock-stream/<abs>` = `unixsock-stream//tmp/...`). A stale socket file
    /// from a SIGKILLed prior zenohd is removed first so the bind does not hit
    /// `EADDRINUSE`.
    pub fn spawn_zenohd_tcp_unixsock(
        tcp_port: u16,
        sock_path: &str,
        mk_probe_stderr: impl FnMut() -> File,
    ) -> ChildGuard {
        // Remove BOTH a stale socket and its `<path>.lock` flock twin (zenoh's
        // unixsock-stream listener creates a lock file beside the socket via
        // nix flock). A SIGKILLed prior zenohd leaves both; clearing them keeps
        // the bind from EADDRINUSE and keeps /tmp from accruing 0-byte locks.
        let _ = std::fs::remove_file(sock_path);
        let _ = std::fs::remove_file(format!("{sock_path}.lock"));
        spawn_zenohd_listeners(
            &[
                format!("tcp/127.0.0.1:{tcp_port}"),
                format!("unixsock-stream/{sock_path}"),
            ],
            tcp_port,
            &format!("unixsock-stream/{sock_path}"),
            mk_probe_stderr,
        )
    }

    /// Spawn a zenohd router listening on BOTH `tcp/` (for pico TCP clients and
    /// the readiness gate) and `tls/` (for a wz TLS client), presenting the
    /// server cert at `cert_path` / key at `key_path`, and block until it is
    /// HANDSHAKE-ready. R311y365 — the TLS counterpart of
    /// [`spawn_zenohd_tcp_ws`] / [`spawn_zenohd_tcp_unixsock`]: zenoh-pico dials
    /// TCP (its TLS link is emscripten-limited here) while wz dials the TLS
    /// listener, and zenohd routes between the two.
    ///
    /// Unlike the `-l`-only spawns, a `tls/` listener needs its cert + key, which
    /// zenoh takes from config (`transport/link/tls/listen_certificate` /
    /// `listen_private_key`), NOT from the locator — so this writes a JSON5
    /// config beside the cert (`<cert_path>.zenohd.json5`) and passes `--config`.
    /// The readiness gate probes the TCP listener (a wz demo without `--tls-ca`
    /// cannot drive the TLS probe), which proves the router core is up; every
    /// `-l` listener binds at startup, so the TLS listener is ready once TCP is.
    /// The caller owns cert/key/config cleanup (the config path is derived above).
    pub fn spawn_zenohd_tcp_tls(
        tcp_port: u16,
        tls_port: u16,
        cert_path: &str,
        key_path: &str,
        mk_probe_stderr: impl FnMut() -> File,
    ) -> ChildGuard {
        let cfg_path = format!("{cert_path}.zenohd.json5");
        let cfg = format!(
            "{{ transport: {{ link: {{ tls: {{ \
             listen_private_key: {key_path:?}, listen_certificate: {cert_path:?} }} }} }} }}"
        );
        std::fs::write(&cfg_path, cfg).expect("write zenohd tls config");

        let mut command = Command::new(zenohd_binary());
        command
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("-l")
            .arg(format!("tls/127.0.0.1:{tls_port}"))
            .arg("--config")
            .arg(&cfg_path)
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ChildGuard::wrap(
            "zenohd (reference router, tls)",
            command.spawn().expect("spawn zenohd (tls)"),
        );
        assert!(
            wait_for_tcp_accept(tcp_port, Duration::from_secs(10)),
            "zenohd (tls) did not start accepting on 127.0.0.1:{tcp_port} within 10s"
        );
        wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{tcp_port}"), mk_probe_stderr);
        guard
    }

    /// R311y366 — the QUIC counterpart of [`spawn_zenohd_tcp_tls`]: zenohd listens
    /// on `tcp/` (readiness gate + the pico subscriber's link) AND `quic/` (the wz
    /// client's link). A `quic/` listener needs the SAME cert + key as `tls/` —
    /// zenoh's QUIC link reads its server cert from the `transport/link/tls` config
    /// block (there is NO separate `quic` cert block; verified at R311y366 by a
    /// standalone zenohd `-l quic/...` bind from a tls-block config), so this
    /// writes the identical JSON5 config beside the cert (`<cert>.zenohd.json5`)
    /// that `spawn_zenohd_tcp_tls` does and passes `--config`. The readiness gate
    /// probes the TCP listener (a wz demo without `--quic-ca` cannot drive a QUIC
    /// probe); every `-l` listener binds at startup, so the QUIC (UDP) listener is
    /// ready once TCP is. The caller owns cert/key/config cleanup.
    pub fn spawn_zenohd_tcp_quic(
        tcp_port: u16,
        quic_port: u16,
        cert_path: &str,
        key_path: &str,
        mk_probe_stderr: impl FnMut() -> File,
    ) -> ChildGuard {
        let cfg_path = format!("{cert_path}.zenohd.json5");
        let cfg = format!(
            "{{ transport: {{ link: {{ tls: {{ \
             listen_private_key: {key_path:?}, listen_certificate: {cert_path:?} }} }} }} }}"
        );
        std::fs::write(&cfg_path, cfg).expect("write zenohd quic config");

        let mut command = Command::new(zenohd_binary());
        command
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("-l")
            .arg(format!("quic/127.0.0.1:{quic_port}"))
            .arg("--config")
            .arg(&cfg_path)
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ChildGuard::wrap(
            "zenohd (reference router, quic)",
            command.spawn().expect("spawn zenohd (quic)"),
        );
        assert!(
            wait_for_tcp_accept(tcp_port, Duration::from_secs(10)),
            "zenohd (quic) did not start accepting on 127.0.0.1:{tcp_port} within 10s"
        );
        wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{tcp_port}"), mk_probe_stderr);
        guard
    }

    /// R311pi — confirm zenohd can complete a zenoh handshake by driving a
    /// throwaway wz client to `Established` against the `connect` locator, then
    /// dropping the client. The wz open is deterministic (in-process, no fork),
    /// so this probe is reliable even when the foreign one-shot clients' opens
    /// occasionally need a retry under load. This is the readiness signal
    /// [`spawn_zenohd_listeners`] returns on (replacing the bare TCP-accept
    /// gate). The probe publishes to a dedicated keyexpr no test subscribes to,
    /// and is killed before returning, so it leaves no routing state behind.
    ///
    /// R311pn — `connect` is a full `--connect` locator (not a bare port), so the
    /// probe can target a `ws/...` listener with a REAL WS handshake (the
    /// TCP-only variant passes `127.0.0.1:{port}`, the dual variant
    /// `ws/127.0.0.1:{ws_port}`). A `ws/...` probe needs the `ws` feature in the
    /// demo binary (the Layer Z build enables it); without it the demo surfaces a
    /// typed `Unsupported` and this probe fails loudly rather than passing on a
    /// TCP fallback. `mk_probe_stderr` is the stderr tempfile factory (see
    /// [`spawn_zenohd_listeners`]).
    pub fn wait_for_zenohd_handshake_ready(
        connect: &str,
        mut mk_probe_stderr: impl FnMut() -> File,
    ) {
        let demo = wz_ap_demo_binary();
        let probe_stderr = mk_probe_stderr();
        let probe_writer = probe_stderr
            .try_clone()
            .expect("dup readiness probe stderr handle");
        let mut probe_reader = probe_stderr;
        let mut probe = ChildGuard::wrap(
            "wz-ap-demo (zenohd handshake readiness probe)",
            Command::new(&demo)
                .arg("--connect")
                .arg(connect)
                .arg("--publish")
                .arg("wz/zenohd/readiness-probe")
                .arg("--value")
                .arg("ready")
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(probe_writer))
                .spawn()
                .expect("spawn zenohd readiness probe"),
        );
        let ready = wait_for_substring(
            &mut probe_reader,
            "session Established",
            Duration::from_secs(10),
        );
        let _ = probe.child_mut().kill();
        let _ = probe.child_mut().wait();
        if ready.is_err() {
            let cap = read_captured(&mut probe_reader);
            panic!(
                "zenohd readiness probe (wz client) did not reach Established within 10s \
                 over {connect:?} — zenohd is up but not handshake-ready.\n\
                 --- probe stderr ---\n{cap}"
            );
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
