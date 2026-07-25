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

    /// Locate the UNIXPIPE-enabled `zenohd` (R311y392): the `WZ_ZENOHD_UNIXPIPE_BIN`
    /// env override, else `scripts/build-zenohd.sh ZENOHD_UNIXPIPE=1`'s
    /// `target/zenohd-unixpipe/zenohd` install. A SEPARATE binary from
    /// [`zenohd_binary`] because zenoh's `default` feature set omits
    /// `transport_unixpipe` (and `cargo install` cannot add it), so a unixpipe
    /// zenohd needs a source build with `--features zenoh/transport_unixpipe` — kept
    /// out of the default oracle to preserve its "one identity". Panics with the
    /// build hint if absent, the same prereq discipline as [`zenohd_binary`].
    pub fn zenohd_unixpipe_binary() -> PathBuf {
        if let Ok(p) = std::env::var("WZ_ZENOHD_UNIXPIPE_BIN") {
            return PathBuf::from(p);
        }
        let path = project_root().join("target/zenohd-unixpipe/zenohd");
        assert!(
            path.is_file(),
            "unixpipe-enabled zenohd missing at {}; set WZ_ZENOHD_UNIXPIPE_BIN or run \
             `ZENOHD_UNIXPIPE=1 ZENOHD_ALLOW_CLONE=1 scripts/build-zenohd.sh` first",
            path.display()
        );
        path
    }

    /// Locate the VSOCK-enabled `zenohd` (R311y400): the `WZ_ZENOHD_VSOCK_BIN`
    /// env override, else `scripts/build-zenohd.sh ZENOHD_VSOCK=1`'s
    /// `target/zenohd-vsock/zenohd` install. A SEPARATE binary from
    /// [`zenohd_binary`] for the same reason as [`zenohd_unixpipe_binary`]:
    /// zenoh's `default` feature set omits `transport_vsock` (and `cargo install`
    /// cannot add it), so a vsock zenohd needs a source build with
    /// `--features zenoh/transport_vsock` — kept out of the default oracle to
    /// preserve its "one identity". Unlike the unixpipe oracle it is NOT
    /// provisioned in hosted CI (the runner has no `vsock_loopback`), so its Layer
    /// Z leg SKIPs rather than FAILs when this binary is absent. Panics with the
    /// build hint if absent, the same prereq discipline as [`zenohd_binary`].
    pub fn zenohd_vsock_binary() -> PathBuf {
        if let Ok(p) = std::env::var("WZ_ZENOHD_VSOCK_BIN") {
            return PathBuf::from(p);
        }
        let path = project_root().join("target/zenohd-vsock/zenohd");
        assert!(
            path.is_file(),
            "vsock-enabled zenohd missing at {}; set WZ_ZENOHD_VSOCK_BIN or run \
             `ZENOHD_VSOCK=1 ZENOHD_ALLOW_CLONE=1 scripts/build-zenohd.sh` first",
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

    /// A generous TCP-accept readiness budget for a spawned `zenohd` — the
    /// zenoh-full reference router. zenohd is a HEAVY external binary (full
    /// config + plugin init before it binds a listener), so its cold start
    /// under a contended CI runner routinely approaches, and can exceed, the
    /// 5-10 s the lighter wz-ap-demo readiness waits use. R311y376 hosted CI hit
    /// exactly this: a healthy zenohd bound at 10.07 s and the old fixed-10 s
    /// gate flaked. This budget is safe to make large precisely BECAUSE
    /// [`wait_for_tcp_accept_alive`] is liveness-aware — a zenohd that dies is
    /// reported the instant it exits, so the full budget only ever elapses for
    /// a genuinely-alive-but-not-yet-listening process, never a corpse.
    pub const ZENOHD_TCP_ACCEPT_BUDGET: Duration = Duration::from_secs(30);

    /// Poll `127.0.0.1:port` for TCP-accept readiness WHILE the spawned `child`
    /// is still alive, returning `Ok(())` once a connect succeeds. The
    /// liveness-aware, self-diagnosing successor to [`wait_for_tcp_accept`] for
    /// a readiness gate that owns the process it is waiting on:
    ///
    /// - `Err` the instant `child` exits before accepting (a crash / bind
    ///   conflict — no point spinning out the rest of `budget` on a dead
    ///   process); the message carries the `ExitStatus`, so a zenohd that
    ///   aborts on a port clash reads as `process exited ... (status: ...)`
    ///   rather than the old blind `did not start ... within 10s`.
    /// - `Err` on `budget` elapse, naming the port and budget.
    ///
    /// Because the exit path fires immediately, `budget` can be generous
    /// (load headroom) without a dead child stalling the failure. The returned
    /// `Err` string is the diagnosis the caller surfaces in its panic — so a
    /// timeout is never opaque about which of the two happened.
    pub fn wait_for_tcp_accept_alive(
        child: &mut Child,
        port: u16,
        budget: Duration,
    ) -> Result<(), String> {
        use std::net::TcpStream;
        let deadline = Instant::now() + budget;
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok(());
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(format!(
                        "process exited before accepting on 127.0.0.1:{port} (status: {status})"
                    ));
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(format!(
                        "try_wait on the spawned child failed while waiting on \
                         127.0.0.1:{port}: {e}"
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "did not start accepting tcp on 127.0.0.1:{port} within {budget:?} \
                     (process still alive — genuinely slow to bind or hung)"
                ));
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

    /// The LIVENESS-AWARE capture wait (R311y411): poll the captured tempfile until
    /// `extract` yields a value, but ALSO poll the spawned child, and give up the
    /// instant the child is a corpse instead of burning the whole budget.
    ///
    /// [`wait_for_substring`] has no `try_wait`, so a child that dies at 0.1s still
    /// costs its caller the full timeout — and the caller then has to GUESS why,
    /// because the exit status was never collected. That is the same defect
    /// [`wait_for_tcp_accept_alive`] already fixed for the accept probe, and it is
    /// the reason [`ZENOHD_TCP_ACCEPT_BUDGET`] is documented as safe to make large:
    /// the full budget should only ever elapse for a genuinely-alive-but-not-yet-
    /// ready process, never a corpse. A log-line wait needs the same guarantee, so
    /// it gets the same shape.
    ///
    /// `extract` returns `None` for "not readable yet", which folds the retry for a
    /// partially-written line into the same loop as the liveness check — see
    /// [`parse_announced_tcp_port`], whose terminator requirement depends on being
    /// re-polled rather than accepted early.
    ///
    /// `what` names the awaited thing for the error text. `Err` carries a diagnosis:
    /// either the child's real `ExitStatus` (a corpse — the actionable case, e.g. a
    /// malformed `--config` aborting the process) or the timeout note, plus the
    /// captured output so the caller can surface it.
    pub fn wait_for_capture_alive<T>(
        child: &mut Child,
        file: &mut File,
        budget: Duration,
        what: &str,
        mut extract: impl FnMut(&str) -> Option<T>,
    ) -> Result<T, String> {
        let deadline = Instant::now() + budget;
        loop {
            let captured = read_captured(file);
            if let Some(value) = extract(&captured) {
                return Ok(value);
            }
            // Liveness BEFORE the deadline check: a corpse is terminal, so there is
            // nothing left to wait for. The capture is re-read first (above) so
            // output the child flushed just before dying is not lost to the race.
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(format!(
                        "process exited before {what} (status: {status})\n\
                         --- captured output ---\n{captured}"
                    ));
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(format!(
                        "try_wait on the spawned child failed while waiting for \
                         {what}: {e}"
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "did not reach {what} within {budget:?} (process still alive — \
                     genuinely slow, or hung)\n--- captured output ---\n{captured}"
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Extract the port from zenohd's `Zenoh can be reached at: tcp/127.0.0.1:<port>`
    /// announcement (R311y411). Pure so it is unit-testable without a zenohd.
    ///
    /// Requires a TERMINATING non-digit after the port. A capture file can in
    /// principle be read mid-write, and accepting a digit run that ends at
    /// end-of-capture would silently yield a TRUNCATED port (`337` for `33763`) —
    /// which is worse than any error, because the caller would then probe a port
    /// nobody is listening on and blame the child. zenohd writes the line with its
    /// trailing newline in one `write(2)`, so demanding the terminator costs nothing
    /// on the real path and closes the torn-read hole by construction.
    ///
    /// Returns `None` when the needle is absent, when no digits follow it, when the
    /// digits are unterminated, or when they do not parse as a `u16`.
    pub fn parse_announced_tcp_port(captured: &str, needle: &str) -> Option<u16> {
        let rest = captured.split(needle).nth(1)?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() || digits.len() == rest.len() {
            // Unterminated: the capture ended inside (or exactly at the end of) the
            // digit run, so the port may be truncated. Treat as not-yet-readable.
            return None;
        }
        digits.parse().ok()
    }

    /// The `RUST_LOG` filter the spawned `wz-ap-demo` children run with. `info` is the
    /// level every witness this crate asserts on is logged at, so it is the default —
    /// but a hardcoded level is also what blocks a diagnostic run: the topology
    /// witnesses report COUNTS (`peak 3 node(s)`), while the identity of a node and
    /// the locators it advertised are `debug` (`linkstate_forward`'s "discovered peer
    /// {zid} reachable at {locators}"). `WZ_TEST_DEMO_LOG` lets an investigation raise
    /// it without editing the harness.
    pub fn demo_log_filter() -> String {
        std::env::var("WZ_TEST_DEMO_LOG").unwrap_or_else(|_| "info".to_string())
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
                .env("RUST_LOG", demo_log_filter())
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
                .env("RUST_LOG", demo_log_filter())
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer))
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
        );
        // R311y375 — 10s (was 5s), matching the more generous 8s windows the pico
        // spawn helpers below use. A wz node's cold-start bind + log can exceed 5s
        // under full-run-ci load (parallel compiles + many live processes), which
        // flaked Layer E6 (a wz --peer node not logging "peer: listening on" in
        // time). wait_for_substring returns the instant the marker appears, so the
        // wider window costs a green run NOTHING — it only raises the false-timeout
        // ceiling for a slow-scheduled start.
        let captured = wait_for_substring(&mut reader, listen_marker, Duration::from_secs(10))
            .unwrap_or_else(|c| {
                let _ = guard.child_mut().kill();
                let _ = guard.child_mut().wait();
                panic!("{label} did not bind within 10s\n--- {label} stderr ---\n{c}");
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
        let mut guard = ChildGuard::wrap(
            "zenohd (reference router)",
            command.spawn().expect("spawn zenohd"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), accept_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (reference router): {e}");
        }
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
        let mut guard = ChildGuard::wrap(
            "zenohd (ws dialer)",
            command.spawn().expect("spawn zenohd ws dialer"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (ws dialer): {e}");
        }
        guard
    }

    /// R311y375 — spawn a zenohd that DIALS a wz `tls/...` acceptor
    /// (`-e tls/<wz>`) while listening on `tcp/<tcp_port>` for a pico client. The
    /// TLS DIALER twin of [`spawn_zenohd_ws_dialer`], verifying wz's new tls
    /// ACCEPTOR (`bind_locator`'s `Proto::Tls` arm + `accept_bound`'s rustls server
    /// handshake). zenohd trusts wz's self-signed cert via
    /// `transport/link/tls/root_ca_certificate` (`ca_cert_path` — a self-signed
    /// leaf IS its own root; the CA-chain trust is LOAD-BEARING, a wrong CA fails
    /// the handshake) and DISABLES SAN hostname matching with
    /// `verify_name_on_connect: false` (DEFAULT_CONFIG.json5:693), so the connect
    /// can be by IP (`tls/127.0.0.1:<wz>`) against a `localhost` cert verifying the
    /// chain-of-trust only. (Distinct from wz's OWN dialer, which decouples
    /// dial-IP from a still-VERIFIED `localhost` SAN — disabling the name check is
    /// weaker, but leaves the CA trust wz's acceptor proves untouched.)
    /// zenoh-pico's CLI here is not built with tls, so zenohd is the foreign
    /// tls dialer. Readiness = zenohd accepting on its tcp listener; the tls dial
    /// to wz is witnessed on the wz side ("tls server handshake" + "Established").
    /// The caller owns the cert/key/config file cleanup.
    pub fn spawn_zenohd_tls_dialer(
        wz_tls_endpoint: &str,
        tcp_port: u16,
        ca_cert_path: &str,
    ) -> ChildGuard {
        let cfg_path = format!("{ca_cert_path}.dialer.zenohd.json5");
        let cfg = format!(
            "{{ transport: {{ link: {{ tls: {{ \
             root_ca_certificate: {ca_cert_path:?}, verify_name_on_connect: false }} }} }} }}"
        );
        std::fs::write(&cfg_path, cfg).expect("write zenohd tls dialer config");
        let mut command = Command::new(zenohd_binary());
        command
            .arg("-e")
            .arg(wz_tls_endpoint)
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("--config")
            .arg(&cfg_path)
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut guard = ChildGuard::wrap(
            "zenohd (tls dialer)",
            command.spawn().expect("spawn zenohd tls dialer"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (tls dialer): {e}");
        }
        guard
    }

    /// R311y401 — spawn a zenohd that DIALS a wz `quic/<ip:port>` acceptor
    /// (`-e quic/<wz>`) while listening on `tcp/<tcp_port>` for a pico client. The
    /// QUIC twin of [`spawn_zenohd_tls_dialer`], verifying wz's QUIC ACCEPTOR
    /// (`BoundListener::Quic` / `bind_quic` + the deferred `accept_quic_incoming` /
    /// `complete_quic_accept` split, R311y401 acceptor / R311y404 deferral). Uses the
    /// DEFAULT [`zenohd_binary`]: QUIC is in zenoh's default features (the existing
    /// wz->zenohd quic dial legs dial stock zenohd's `quic/` listener), so no special
    /// oracle. zenoh's QUIC link reads its trust config from the SAME
    /// `transport.link.tls` block as the tls link (there is no separate quic cert
    /// block), so the dialer config is byte-identical to the tls dialer's — only the
    /// `-e` scheme differs: `root_ca_certificate` (trusting wz's self-signed
    /// `localhost` cert) + `verify_name_on_connect: false` (the by-IP dial verifies
    /// the chain-of-trust only, not the SAN). Readiness = zenohd accepting on its tcp
    /// listener; the quic dial to wz is witnessed on the wz side ("session
    /// Established"). zenoh-pico's CLI has no quic, so zenohd is the only foreign quic
    /// dialer.
    pub fn spawn_zenohd_quic_dialer(
        wz_quic_endpoint: &str,
        tcp_port: u16,
        ca_cert_path: &str,
    ) -> ChildGuard {
        let cfg_path = format!("{ca_cert_path}.dialer.zenohd.json5");
        let cfg = format!(
            "{{ transport: {{ link: {{ tls: {{ \
             root_ca_certificate: {ca_cert_path:?}, verify_name_on_connect: false }} }} }} }}"
        );
        std::fs::write(&cfg_path, cfg).expect("write zenohd quic dialer config");
        let mut command = Command::new(zenohd_binary());
        command
            .arg("-e")
            .arg(wz_quic_endpoint)
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("--config")
            .arg(&cfg_path)
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut guard = ChildGuard::wrap(
            "zenohd (quic dialer)",
            command.spawn().expect("spawn zenohd quic dialer"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (quic dialer): {e}");
        }
        guard
    }

    /// R311y411 — spawn a zenohd that DIALS `dial_locator` while listening on an
    /// OS-ASSIGNED loopback TCP port, and return BOTH the guard and the port zenohd
    /// ACTUALLY bound (for the readiness probe and for pointing pico clients at it).
    ///
    /// ## Why the port is discovered, not chosen
    ///
    /// The sibling dialer helpers take a caller-CHOSEN `tcp_port`, and every
    /// acceptor-direction caller derives it arithmetically from the wz listen port
    /// (`wz_port.wrapping_add(1)`). The quic-family callers justify that in-comment by
    /// "a UDP and a TCP port live in different protocol namespaces, so they cannot
    /// collide" (the ws/tls callers give a different reason, or none — and there the
    /// wz port is itself TCP, so the namespace argument never applied at all). Either
    /// way the conclusion does not hold: it rules out a collision with wz's OWN socket,
    /// not with the rest of the machine. `wz_port + 1` is an ordinary port in the ephemeral range, and any
    /// other process — including a client socket opened moments earlier by this same
    /// test lane — may already hold it. When it does, zenohd logs `Address already in
    /// use (os error 98)` and exits **255** before accepting, and the readiness probe
    /// fails with "process exited before accepting". Measured on this workspace at
    /// R311y411: 1 failure in 30 consecutive runs of a 6-leg lane, reproduced
    /// deterministically by binding the derived port before the spawn.
    ///
    /// The rate is not the ~0.003% a uniform-random collision would give: the
    /// amplifier is TIME_WAIT. zenohd does not set `SO_REUSEADDR` on its listener, so
    /// every client socket this lane opens and closes leaves its ephemeral port
    /// unbindable for ~60s, and the derived port lands in exactly that range. A
    /// campaign accumulates hundreds of them.
    ///
    /// There is no way to hand a child process a port that is guaranteed free — a
    /// reserve-then-release helper only narrows the same TOCTOU window. So this helper
    /// inverts the direction: zenohd binds `tcp/127.0.0.1:0`, the KERNEL picks a free
    /// port, and the test reads it back from zenohd's own
    /// `Zenoh can be reached at: tcp/127.0.0.1:<port>` line. Nothing is guessed, so
    /// there is no window to lose. Readiness is still the `wait_for_tcp_accept_alive`
    /// probe on the discovered port, so callers keep the same guarantee.
    ///
    /// `config_path` is the optional `--config` JSON5 (trust anchors, routing mode);
    /// the caller writes it. `stdout` is the capture file the caller supplies (this
    /// lib crate cannot depend on the dev-only `tempfile`), and it must stay readable
    /// — the port line is parsed out of it.
    pub fn spawn_zenohd_dialer_on_ephemeral_tcp(
        label: &'static str,
        dial_locator: &str,
        config_path: Option<&str>,
        stdout: File,
    ) -> (ChildGuard, u16) {
        /// zenohd's orchestrator announces each bound listener with this prefix; the
        /// port digits follow it directly.
        const LISTEN_LINE: &str = "Zenoh can be reached at: tcp/127.0.0.1:";

        let writer = stdout.try_clone().expect("dup zenohd stdout handle");
        let mut reader = stdout;
        let mut command = Command::new(zenohd_binary());
        command
            // PIN the log level. This helper is the only one in the crate that reads
            // zenohd's LOG rather than probing its socket, so the announcement it
            // parses is a functional dependency, not diagnostics: zenohd builds its
            // filter with `EnvFilter::try_from_default_env()`, so an inherited
            // `RUST_LOG=warn` silently filters the line away and every leg then burns
            // its full budget on a healthy process. `spawn_on_ephemeral_port` pins the
            // same variable for the wz demo for the same reason.
            .env("RUST_LOG", "z=info")
            .arg("-e")
            .arg(dial_locator)
            .arg("-l")
            .arg("tcp/127.0.0.1:0")
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null());
        if let Some(cfg) = config_path {
            command.arg("--config").arg(cfg);
        }
        let mut guard = ChildGuard::wrap(
            label,
            command.spawn().expect("spawn zenohd ephemeral-tcp dialer"),
        );
        // LIVENESS-AWARE: a zenohd that dies at startup (bad --config, unreadable
        // trust anchor) reports its real ExitStatus here in milliseconds instead of
        // costing the full budget and leaving the caller to guess the cause.
        let port = wait_for_capture_alive(
            guard.child_mut(),
            &mut reader,
            ZENOHD_TCP_ACCEPT_BUDGET,
            "announcing its bound tcp listener",
            |captured| parse_announced_tcp_port(captured, LISTEN_LINE),
        )
        .unwrap_or_else(|e| {
            panic!(
                "{label}: {e}\n\
                 (if the process is alive and the capture looks empty, the announcement \
                 was filtered out of zenohd's log — this helper pins RUST_LOG=z=info for \
                 exactly that reason, so a hit here means the log FORMAT moved)"
            )
        });
        if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("{label}: {e}");
        }
        (guard, port)
    }

    /// R311y408 — spawn a zenohd that DIALS a wz `quic-datagram/<ip:port>` acceptor
    /// over the QUIC unreliable-DATAGRAM transport (RFC9221) while listening on
    /// `tcp/<tcp_port>` for a pico client. The DATAGRAM twin of
    /// [`spawn_zenohd_quic_dialer`], verifying wz's QUIC-DATAGRAM ACCEPTOR
    /// (`BoundListener::QuicDatagram` / `bind_quic_datagram` + the deferred
    /// `accept_quic_incoming` / `complete_quic_datagram_accept` split, R311y408).
    ///
    /// zenoh does NOT give its datagram link a distinct scheme: its
    /// `QUIC_DATAGRAM_LOCATOR_PREFIX` is `"quic"` (the SAME prefix as reliable quic),
    /// and stream-vs-datagram is selected by the locator's reliability metadata
    /// `rel` — `quic/<addr>?rel=0` is best-effort, which
    /// `io/zenoh-link/src/lib.rs` routes to `LinkKind::QuicDatagram` when both the
    /// `transport_quic` and `transport_quic_datagram` features are on. So the caller
    /// passes wz's datagram acceptor address (`127.0.0.1:<port>`) and this helper
    /// renders zenoh's `-e quic/<wz-ip:port>?rel=0`. `transport_quic_datagram` is in
    /// zenoh's DEFAULT feature set and zenohd enables `zenoh/default`, so the DEFAULT
    /// [`zenohd_binary`] carries it — no special oracle (unlike the vsock/unixpipe
    /// variants; verified: the default oracle and a `--features
    /// zenoh/transport_quic_datagram` build have identical datagram footprint). zenoh's
    /// QUIC link reads its trust config from the SAME `transport.link.tls` block as
    /// tls (no separate quic block), so the dialer config is byte-identical to the
    /// reliable-quic dialer's — only the `-e` (scheme + `?rel=0`) differs. zenoh-pico's
    /// CLI has no quic, so zenohd is the only foreign quic-datagram dialer.
    pub fn spawn_zenohd_quic_datagram_dialer(
        wz_quic_datagram_addr: &str,
        tcp_port: u16,
        ca_cert_path: &str,
    ) -> ChildGuard {
        let cfg_path = format!("{ca_cert_path}.dialer.zenohd.json5");
        let cfg = format!(
            "{{ transport: {{ link: {{ tls: {{ \
             root_ca_certificate: {ca_cert_path:?}, verify_name_on_connect: false }} }} }} }}"
        );
        std::fs::write(&cfg_path, cfg).expect("write zenohd quic-datagram dialer config");
        let mut command = Command::new(zenohd_binary());
        command
            .arg("-e")
            .arg(format!("quic/{wz_quic_datagram_addr}?rel=0"))
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("--config")
            .arg(&cfg_path)
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut guard = ChildGuard::wrap(
            "zenohd (quic-datagram dialer)",
            command.spawn().expect("spawn zenohd quic-datagram dialer"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (quic-datagram dialer): {e}");
        }
        guard
    }

    /// R311y398 — spawn a zenohd that DIALS a wz `unixsock-stream/<path>` acceptor
    /// (`-e unixsock-stream/<path>`) while also listening on `tcp/<tcp_port>` for a
    /// pico client. The AF_UNIX-stream DIALER sibling of [`spawn_zenohd_ws_dialer`]
    /// / [`spawn_zenohd_tls_dialer`], verifying wz's unixsock ACCEPTOR (the
    /// `bind_locator` `AnyLocator::Unixsock` arm wired in R311y378 + `accept_bound`'s
    /// direct wrap — no post-accept handshake, like tcp). Unlike the unixpipe dialer,
    /// this uses the DEFAULT [`zenohd_binary`]: the unixsock link is in stock zenohd's
    /// build (the existing wz->zenohd unixsock leg dials it), so no special oracle is
    /// needed. zenoh-pico's CLI has no unixsock client, so zenohd is the only foreign
    /// unixsock dialer. Readiness = zenohd accepting on its tcp listener; the unixsock
    /// dial to wz is witnessed on the wz side ("session Established"). No
    /// handshake-probe param (like the ws/tls dialers): this zenohd DIALS out, and the
    /// wz-side log is the Established witness.
    pub fn spawn_zenohd_unixsock_dialer(wz_unixsock_path: &str, tcp_port: u16) -> ChildGuard {
        let mut command = Command::new(zenohd_binary());
        command
            .arg("-e")
            .arg(format!("unixsock-stream/{wz_unixsock_path}"))
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut guard = ChildGuard::wrap(
            "zenohd (unixsock dialer)",
            command.spawn().expect("spawn zenohd unixsock dialer"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (unixsock dialer): {e}");
        }
        guard
    }

    /// R311y399 — spawn a zenohd that DIALS a wz `udp/...` acceptor
    /// (`-e udp/<wz_udp_endpoint>`) while also listening on `tcp/<tcp_port>` for a
    /// pico client. The DATAGRAM DIALER sibling of [`spawn_zenohd_ws_dialer`] /
    /// [`spawn_zenohd_tls_dialer`], verifying wz's UDP-demux ACCEPTOR
    /// (`BoundListener::Udp` / `bind_udp_demux`, R311y382 — the first structurally-
    /// datagram acceptor). Like the ws/tls dialers it takes a PRE-FORMATTED
    /// endpoint (udp is IP-based -- `AcceptedPeer::Ip` = the datagram source -- so
    /// the caller renders `udp/<ip:port>`, unlike the NonIp path dialers). Uses the
    /// DEFAULT [`zenohd_binary`]: udp is in zenoh's default features (the existing
    /// wz->zenohd udp leg dials stock zenohd's udp listener), so no special oracle.
    /// zenoh-pico HAS a udp client, but here pico attaches to zenohd over TCP and
    /// only the zenohd->wz hop is udp, so zenohd is the foreign udp dialer under
    /// test. Readiness = zenohd accepting on its tcp listener; the udp dial to wz is
    /// witnessed on the wz side ("session Established"). No handshake-probe param
    /// (like the ws/tls dialers): this zenohd DIALS out.
    pub fn spawn_zenohd_udp_dialer(wz_udp_endpoint: &str, tcp_port: u16) -> ChildGuard {
        let mut command = Command::new(zenohd_binary());
        command
            .arg("-e")
            .arg(wz_udp_endpoint)
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut guard = ChildGuard::wrap(
            "zenohd (udp dialer)",
            command.spawn().expect("spawn zenohd udp dialer"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (udp dialer): {e}");
        }
        guard
    }

    /// R311y400 — spawn a VSOCK-enabled zenohd that DIALS a wz `vsock/<cid>:<port>`
    /// acceptor (`-e vsock/<cid>:<port>`) while listening on `tcp/<tcp_port>` for a
    /// pico client. The AF_VSOCK DIALER twin of [`spawn_zenohd_unixsock_dialer`],
    /// verifying wz's vsock ACCEPTOR (`BoundListener::Vsock` / `bind_vsock` — direct
    /// wrap, no post-accept handshake — proven wz<->wz by `vsock_e2e`). Needs the
    /// SEPARATE [`zenohd_vsock_binary`] oracle: zenoh's `default` omits
    /// `transport_vsock` (and `cargo install` cannot add it), so a vsock zenohd needs
    /// a source build — the same reason unixpipe needs its own oracle. The caller
    /// passes a PRE-FORMATTED `vsock/<cid>:<port>` endpoint (vsock is NonIp with an
    /// EPHEMERAL kernel-assigned port learned from the wz acceptor's listen line —
    /// like the ws/tls dialers take a pre-rendered endpoint, unlike the bare-path
    /// unixsock dialer). zenoh-pico has NO vsock client, so zenohd is the only
    /// foreign vsock dialer. Readiness = zenohd accepting on its tcp listener; the
    /// vsock dial to wz is witnessed on the wz side ("session Established"). Linux +
    /// AF_VSOCK-loopback host only.
    pub fn spawn_zenohd_vsock_dialer(wz_vsock_endpoint: &str, tcp_port: u16) -> ChildGuard {
        let mut command = Command::new(zenohd_vsock_binary());
        command
            .arg("-e")
            .arg(wz_vsock_endpoint)
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut guard = ChildGuard::wrap(
            "zenohd (vsock dialer)",
            command.spawn().expect("spawn zenohd vsock dialer"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (vsock dialer): {e}");
        }
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
        let mut guard = ChildGuard::wrap(
            "zenohd (reference router, lowlatency)",
            command.spawn().expect("spawn zenohd (lowlatency)"),
        );
        if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (lowlatency): {e}");
        }
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

    /// Poll until the unixpipe request FIFO node `<base>_uplink` exists (a unixpipe
    /// listener has bound) or the deadline passes. A unixpipe listener has no TCP
    /// port, so readiness is the request-channel node appearing — the named-FIFO
    /// analogue of [`wait_for_tcp_accept`]. R311y393 lifted this from
    /// `wz_unixpipe_zenohd_interop`'s local copy when the data-plane leg
    /// (`wz_unixpipe_zenohd_dataplane`) + [`spawn_zenohd_unixpipe_tcp`] became its
    /// second + third consumers.
    pub fn wait_for_unixpipe_request_fifo(base: &str, timeout: Duration) -> bool {
        let node = format!("{base}_uplink");
        let deadline = Instant::now() + timeout;
        loop {
            if Path::new(&node).exists() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// R311y393 — spawn a UNIXPIPE-enabled zenohd LISTENING on BOTH
    /// `unixpipe/<base>` (for a wz client dial) and `tcp/127.0.0.1:<tcp_port>` (for
    /// a pico client + the readiness gate), and block until it is HANDSHAKE-ready.
    /// The named-FIFO sibling of [`spawn_zenohd_tcp_unixsock`] — but it CANNOT
    /// delegate to [`spawn_zenohd_listeners`], which hardcodes the stock
    /// [`zenohd_binary`]: a `unixpipe/` listener needs the SEPARATE
    /// [`zenohd_unixpipe_binary`] oracle (zenoh's `default` omits
    /// `transport_unixpipe`). So it mirrors the INLINE shape of
    /// [`spawn_zenohd_tcp_tls`]: probe the TCP listener for readiness (a wz client
    /// without unixpipe cannot drive a FIFO probe, and every `-l` listener binds at
    /// startup, so the unixpipe listener is ready once TCP is), PLUS wait for the
    /// `<base>_uplink` request FIFO node so a wz dial finds the request channel
    /// present. Linux-only (the unixpipe backend's `read_write` open-rendezvous).
    /// The caller owns request-FIFO cleanup.
    pub fn spawn_zenohd_unixpipe_tcp(
        unixpipe_base: &str,
        tcp_port: u16,
        mk_probe_stderr: impl FnMut() -> File,
    ) -> ChildGuard {
        let mut command = Command::new(zenohd_unixpipe_binary());
        command
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("-l")
            .arg(format!("unixpipe/{unixpipe_base}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut guard = ChildGuard::wrap(
            "zenohd (unixpipe+tcp listener)",
            command.spawn().expect("spawn zenohd unixpipe+tcp listener"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (unixpipe+tcp listener): {e}");
        }
        if !wait_for_unixpipe_request_fifo(unixpipe_base, Duration::from_secs(15)) {
            panic!(
                "zenohd did not create the unixpipe request FIFO {unixpipe_base}_uplink within 15s"
            );
        }
        // Close the TCP-accept-vs-handshake-ready gap with a real wz session (the
        // R311pi discipline in spawn_zenohd_listeners); the wz probe dials TCP, so
        // it needs no unixpipe feature.
        wait_for_zenohd_handshake_ready(&format!("tcp/127.0.0.1:{tcp_port}"), mk_probe_stderr);
        guard
    }

    /// R311y393 — spawn a UNIXPIPE-enabled zenohd that DIALS a wz `unixpipe/<base>`
    /// acceptor (`-e unixpipe/<base>`) while listening on `tcp/<tcp_port>` for a
    /// pico client. The named-FIFO DIALER twin of [`spawn_zenohd_ws_dialer`] /
    /// [`spawn_zenohd_tls_dialer`], verifying that wz's MULTI-CLIENT unixpipe
    /// ACCEPTOR (R311y392) carries the DATA plane, not just the handshake: zenohd's
    /// `UnicastPipeClient` invites wz's acceptor, and a pico `z_pub` on the tcp
    /// listener routes ACROSS the accepted unixpipe link into the wz subscriber.
    /// Needs the SEPARATE [`zenohd_unixpipe_binary`] oracle. The wz acceptor MUST
    /// already be bound (its `<base>_uplink` request FIFO present) before this is
    /// called, so the zenoh client's invitation lands. Readiness = zenohd accepting
    /// on its tcp listener; the unixpipe dial to wz is witnessed on the wz side
    /// ("session Established"). Linux-only.
    pub fn spawn_zenohd_unixpipe_dialer(wz_unixpipe_base: &str, tcp_port: u16) -> ChildGuard {
        let mut command = Command::new(zenohd_unixpipe_binary());
        command
            .arg("-e")
            .arg(format!("unixpipe/{wz_unixpipe_base}"))
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{tcp_port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut guard = ChildGuard::wrap(
            "zenohd (unixpipe dialer)",
            command.spawn().expect("spawn zenohd unixpipe dialer"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (unixpipe dialer): {e}");
        }
        guard
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
        let mut guard = ChildGuard::wrap(
            "zenohd (reference router, tls)",
            command.spawn().expect("spawn zenohd (tls)"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (tls): {e}");
        }
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
        let mut guard = ChildGuard::wrap(
            "zenohd (reference router, quic)",
            command.spawn().expect("spawn zenohd (quic)"),
        );
        if let Err(e) =
            wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("zenohd (quic): {e}");
        }
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
                .env("RUST_LOG", demo_log_filter())
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
    use super::common::{wait_for_tcp_accept_alive, ChildGuard, ZENOHD_TCP_ACCEPT_BUDGET};
    use socket2::{Domain, Socket, Type};
    use std::net::{SocketAddr, TcpListener};
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    /// Reserve an ephemeral TCP port that STAYS closed (a `connect` gets
    /// `ECONNREFUSED`) for as long as the returned [`Socket`] guard is held. The
    /// socket is bound but NEVER `listen()`ed — std's `TcpListener::bind` always
    /// `listen()`s, so a bound std listener would ACCEPT the connect against the
    /// kernel backlog. The prior `bind`-then-`drop` leaked the port straight back
    /// to the OS, which under a loaded CI run recycles it to an unrelated LIVE
    /// listener — a TOCTOU race that flaked `wait_alive_fails_fast_...` (a
    /// third party binds the "closed" port, so `wait_for_tcp_accept_alive`
    /// connects and returns `Ok` before it observes the child exit). This is the
    /// exact race the crate's `socket2` dep was ADDED to fix (but never wired
    /// until now), mirroring the `refused_locator` helper in wz-runtime-tokio's
    /// `static_scout_open.rs`. The caller MUST hold the guard for the whole test.
    fn closed_port() -> (Socket, u16) {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("socket");
        let bind: SocketAddr = "127.0.0.1:0".parse().expect("parse bind addr");
        socket.bind(&bind.into()).expect("bind without listen");
        let port = socket
            .local_addr()
            .expect("local_addr")
            .as_socket()
            .expect("ipv4 socket addr")
            .port();
        (socket, port)
    }

    /// R311y383 — the discriminator for the `closed_port` TOCTOU fix: the guard
    /// RESERVES the port (a concurrent bind to it fails) AND keeps it CLOSED (a
    /// connect is refused), for as long as the guard is held. Under the prior
    /// bind-then-drop helper the port was NOT reserved — a parallel CI process
    /// could rebind the "closed" port into a live listener, so
    /// `wait_for_tcp_accept_alive` would connect and report the exited child as
    /// ready (the `wait_alive_fails_fast` flake). The concurrent-bind-fails
    /// assertion goes RED against that old helper (its dropped listener left the
    /// port free to rebind).
    #[test]
    fn closed_port_reserves_the_port_and_refuses_connect() {
        use std::net::TcpStream;
        let (_guard, port) = closed_port();
        assert!(
            TcpListener::bind(("127.0.0.1", port)).is_err(),
            "closed_port's guard must reserve the port against a concurrent bind"
        );
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_err(),
            "a bound-not-listening port must refuse connects (ECONNREFUSED)"
        );
    }

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

    /// The structural property that fixes the R311y376 Layer Z flake: when the
    /// spawned process exits before the port opens, the wait returns the INSTANT
    /// it observes the exit — it does NOT spin out the (deliberately generous)
    /// budget on a corpse. A `sleep 0` exits at once and never binds anything;
    /// waited against a closed port with the zenohd budget, the helper must Err
    /// in a small fraction of that budget. This is the discriminator against the
    /// old blind `wait_for_tcp_accept` fixed-timeout poll: revert the liveness
    /// check and this fails — it spins the full budget (~30 s) and the message
    /// assertion trips first (the timeout label, not "process exited").
    #[test]
    fn wait_alive_fails_fast_when_child_exits_before_accepting() {
        let (_closed_guard, port) = closed_port();
        let mut guard = ChildGuard::wrap(
            "sleep-0 exits-immediately",
            Command::new("sleep")
                .arg("0")
                .spawn()
                .expect("spawn sleep 0"),
        );
        let budget = ZENOHD_TCP_ACCEPT_BUDGET;
        let start = Instant::now();
        let result = wait_for_tcp_accept_alive(guard.child_mut(), port, budget);
        let elapsed = start.elapsed();
        let err = result.expect_err("a process that exited must not report ready");
        assert!(
            err.contains("process exited"),
            "exit must be self-labelled as an exit, got: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "liveness-aware wait must fail fast on child exit, not spin the \
             30s budget; elapsed {elapsed:?}"
        );
    }

    /// The timeout path stays honest for a LIVE-but-not-listening process: a
    /// `sleep 60` never binds the port, so a short budget must elapse and the
    /// Err must name the timeout (NOT misreport the alive child as exited).
    #[test]
    fn wait_alive_times_out_for_a_live_nonlistening_child() {
        let (_closed_guard, port) = closed_port();
        let mut guard = ChildGuard::wrap(
            "sleep-60 never-listens",
            Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("spawn sleep 60"),
        );
        let budget = Duration::from_millis(300);
        let start = Instant::now();
        let result = wait_for_tcp_accept_alive(guard.child_mut(), port, budget);
        let elapsed = start.elapsed();
        let err = result.expect_err("a non-listening child must not report ready");
        assert!(
            err.contains("did not start accepting"),
            "a live-but-slow child must be labelled a timeout, got: {err}"
        );
        assert!(
            elapsed >= budget,
            "the timeout must not fire before the budget; elapsed {elapsed:?}"
        );
    }

    /// The success path: once a listener is accepting on the port, the wait
    /// returns `Ok` promptly. Binding a `TcpListener` is enough — the kernel
    /// completes the connect handshake into the accept backlog without an
    /// explicit `accept()` call, which is exactly what a spawned router's bound
    /// listener presents.
    #[test]
    fn wait_alive_returns_ok_once_the_port_accepts() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local_addr").port();
        let mut guard = ChildGuard::wrap(
            "sleep-60 alongside-listener",
            Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("spawn sleep 60"),
        );
        let start = Instant::now();
        let result = wait_for_tcp_accept_alive(guard.child_mut(), port, Duration::from_secs(5));
        let elapsed = start.elapsed();
        result.expect("an accepting port must report ready");
        assert!(
            elapsed < Duration::from_secs(5),
            "ready must be observed well within budget; elapsed {elapsed:?}"
        );
        drop(listener);
    }

    /// Guards the CURATIVE half of the fix that the timing tests above do NOT:
    /// the R311y376 flake was a HEALTHY zenohd that bound at 10.07s under the old
    /// fixed-10s gate, so the cure is the budget headroom, not just the liveness
    /// fast-fail. Pin the floor — a revert of `ZENOHD_TCP_ACCEPT_BUDGET` toward
    /// the old 10s (anything <= the observed 10.07s bind) fails HERE, so a budget
    /// regression cannot ship green while reopening the exact flake the commit
    /// title claims to kill (a liveness-only test would miss it).
    #[test]
    fn zenohd_accept_budget_keeps_headroom_over_the_observed_flake() {
        assert!(
            ZENOHD_TCP_ACCEPT_BUDGET >= Duration::from_secs(20),
            "zenohd TCP-accept budget {ZENOHD_TCP_ACCEPT_BUDGET:?} must keep \
             headroom over the 10.07s bind that flaked R311y376; a revert toward \
             10s reopens it"
        );
    }

    /// R311y411 — the port parser must REFUSE an unterminated digit run.
    ///
    /// A capture file can be read while the child is mid-write. Accepting a digit
    /// run that ends at end-of-capture would hand back a TRUNCATED port (`337` for
    /// `33763`), and the caller would then probe a port nobody is listening on and
    /// blame the child. The parser therefore demands a terminating non-digit; this
    /// pins that, since a torn read is exactly the case a live run does not produce.
    #[test]
    fn parse_announced_tcp_port_refuses_an_unterminated_digit_run() {
        use super::common::parse_announced_tcp_port;
        const NEEDLE: &str = "Zenoh can be reached at: tcp/127.0.0.1:";

        // Complete line (the real shape: zenohd writes it with its trailing \n).
        assert_eq!(
            parse_announced_tcp_port(&format!("INFO {NEEDLE}33763\n"), NEEDLE),
            Some(33763),
            "a terminated port must parse"
        );
        // TORN: the write is observed mid-digits. Truncating to 337 would be worse
        // than any error, so the parser must report not-yet-readable instead.
        assert_eq!(
            parse_announced_tcp_port(&format!("INFO {NEEDLE}337"), NEEDLE),
            None,
            "an unterminated digit run must NOT yield a truncated port"
        );
        // Torn exactly at the colon: no digits at all.
        assert_eq!(
            parse_announced_tcp_port(&format!("INFO {NEEDLE}"), NEEDLE),
            None,
            "the needle with no digits must not parse"
        );
        // The needle never appeared.
        assert_eq!(
            parse_announced_tcp_port("INFO some other line\n", NEEDLE),
            None,
            "an absent needle must not parse"
        );
        // Out of u16 range -> refuse rather than wrap.
        assert_eq!(
            parse_announced_tcp_port(&format!("INFO {NEEDLE}70000\n"), NEEDLE),
            None,
            "a port outside u16 must not parse"
        );
    }

    /// R311y411 — the liveness-aware capture wait must report a CORPSE in
    /// milliseconds, not burn its budget.
    ///
    /// `wait_for_substring` has no `try_wait`, so a child that dies at startup
    /// costs the caller the full timeout and the caller must then GUESS the cause.
    /// This pins the fixed behaviour: a real exit status, promptly, with the
    /// captured output attached. `sh -c 'exit 3'` stands in for the real case (a
    /// zenohd aborting on a malformed `--config`) with no external binary.
    #[test]
    fn wait_for_capture_alive_reports_a_corpse_instead_of_waiting() {
        use super::common::wait_for_capture_alive;
        use std::process::{Command, Stdio};

        let capture = tempfile::tempfile().expect("tempfile for child capture");
        let writer = capture.try_clone().expect("dup capture handle");
        let mut reader = capture;
        let mut child = Command::new("sh")
            .args(["-c", "echo starting; exit 3"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the corpse stand-in");

        let budget = Duration::from_secs(30);
        let started = Instant::now();
        let outcome: Result<(), String> = wait_for_capture_alive(
            &mut child,
            &mut reader,
            budget,
            "a line that never comes",
            |captured| captured.contains("NEVER").then_some(()),
        );
        let elapsed = started.elapsed();
        let _ = child.wait();

        let err = outcome.expect_err("a dead child cannot produce the needle");
        assert!(
            err.contains("exit status: 3"),
            "the error must carry the child's REAL exit status (the signal that \
             diagnoses a startup failure), got: {err}"
        );
        assert!(
            err.contains("starting"),
            "the error must carry the captured output, got: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "a corpse must be reported promptly, not after the {budget:?} budget; \
             took {elapsed:?}"
        );
    }

    /// R311y411 — and the same wait must still return the extracted value for a
    /// LIVE child, polling until the line is complete (the twin of the corpse pin
    /// above: a fail-fast that also fails the happy path proves nothing).
    #[test]
    fn wait_for_capture_alive_extracts_from_a_live_child() {
        use super::common::{parse_announced_tcp_port, wait_for_capture_alive};
        use std::process::{Command, Stdio};
        const NEEDLE: &str = "reached at: tcp/127.0.0.1:";

        let capture = tempfile::tempfile().expect("tempfile for child capture");
        let writer = capture.try_clone().expect("dup capture handle");
        let mut reader = capture;
        // Announce only after a delay, so the wait genuinely polls; then stay alive.
        let child = Command::new("sh")
            .args([
                "-c",
                "sleep 0.3; echo \"reached at: tcp/127.0.0.1:41059\"; sleep 30",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the live stand-in");
        let mut guard = ChildGuard::wrap("live capture stand-in", child);

        let port = wait_for_capture_alive(
            guard.child_mut(),
            &mut reader,
            Duration::from_secs(30),
            "announcing its port",
            |captured| parse_announced_tcp_port(captured, NEEDLE),
        );
        assert_eq!(
            port,
            Ok(41059),
            "the wait must return the announced port for a live child"
        );
    }
}
