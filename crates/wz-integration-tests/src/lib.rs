// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared helpers for the `wz_*_round_trip` / `ap_demo_*` integration
//! tests in this crate. Through R215 each test redefined the same set
//! of helpers locally (9 files × 5 fns = 45 duplicates); the
//! `pick_free_port` clone in particular carried a TOCTOU race that
//! manifested as the Layer E flake observed on the R209 / R214 push
//! hook runs (`wz_initiator_round_trip_against_wz_acceptor` and
//! `ap_demo_round_trip_against_zenoh_pico_z_put`). R216 lifts the
//! helpers into this module and replaces the racey port picker with
//! a [`crate::common::PortReservation`] that holds a process-global mutex across the
//! bind → child-spawn → bind-confirmed window so concurrent tests in
//! the same `cargo test` invocation cannot pick the same port.

pub mod common {
    //! Test harness primitives shared by the `wz_*_round_trip` /
    //! `ap_demo_*` integration tests. See module-level rationale for
    //! the flake background.

    use std::collections::BTreeSet;
    use std::fs::File;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
    use std::thread;
    use std::time::{Duration, Instant};

    /// R2226 (open-debt item 575) — the relay records what it carried, and it
    /// records it in the SHAPE `wire_tap::synthesise_pcap` already consumes.
    ///
    /// Imported rather than redeclared: a second `Side` in this module would be
    /// a second answer to "which end wrote this segment", and every leg that
    /// rebuilds a wire would then have to pick one. The two harness halves stay
    /// one vocabulary.
    use crate::wire_tap::{Recording, Side};

    fn port_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// CROSS-PROCESS half of the port reservation (R311y490).
    ///
    /// [`port_lock`] above is a `static` — it is process-global, and that is the
    /// scope the R216 design got wrong rather than the idea. Cargo runs a crate's
    /// test BINARIES concurrently: **17 were measured alive at once** during
    /// Layer E's `cargo test -p wz-integration-tests -- --ignored` sweep. Each is
    /// its own process with its own `static`, so the mutex serialised one
    /// seventeenth of the contention and the other sixteen ran the
    /// `bind(0) -> close -> child bind` window unguarded against each other.
    ///
    /// That is precisely the window [`crate::common::PortReservation`]'s doc dismissed as an
    /// EXTERNAL process stealing the port, "sub-millisecond ... not observed in
    /// this workspace's CI history", deferring the fix "until the in-process race
    /// is confirmed insufficient". It is now confirmed insufficient: 17
    /// concurrent processes running that window in a loop lose the port 1 time in
    /// 6800 with a MINIMAL window, and the real window spans a `fork` + `exec` of
    /// a foreign binary, so it is far wider than the one measured.
    ///
    /// `flock` rather than a lock file with a sentinel: the kernel drops it when
    /// the fd closes, INCLUDING on `SIGKILL`, so a killed test can never strand
    /// the lock for every later run. FD inheritance — the fix the original doc
    /// named — cannot be used here: the listener in the leg that surfaced this is
    /// zenoh-pico's own `z_sub`, a foreign C binary with no `--listen-fd`.
    ///
    /// Non-unix returns `None` and the reservation degrades to the intra-process
    /// mutex, which is what every platform had before this.
    struct CrossProcessPortLock {
        #[cfg(unix)]
        _file: File,
    }

    impl CrossProcessPortLock {
        #[cfg(unix)]
        fn acquire() -> Option<Self> {
            use std::os::unix::io::AsRawFd;

            let path = project_root().join("crates/target/.wz-port-reservation.lock");
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok()?;
            // SAFETY: `file` owns a valid open fd for the whole call, and
            // `LOCK_EX` has no memory effects. Blocking is intended — the
            // critical section is bind-to-child-bound, milliseconds long.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            (rc == 0).then_some(Self { _file: file })
        }

        #[cfg(not(unix))]
        fn acquire() -> Option<Self> {
            None
        }
    }

    // R2049 — whether THIS thread already holds a `PortReservation`.
    //
    // `port_lock` is a plain `std::sync::Mutex`, which is NOT reentrant, so a
    // second `PortReservation::pick` on a thread that already holds one blocks
    // FOREVER. `pick_pair`'s doc has named that hazard since R311pk, and naming
    // it was not enough: R2049 wrote a witness that called `pick` twice, and it
    // printed `running 1 test` followed by NOTHING until it was killed. libtest
    // has no per-test timeout, so a hang and a slow lane are the same
    // observation — which is why the gate belongs on the CONDITION rather than
    // in a static lint. The precise hazard is an OVERLAPPING reservation, and a
    // grep for two `pick()` calls cannot see whether the first is still alive:
    // 164 call sites, ten files with two or more, and almost all of them are
    // one-per-test and correct.
    //
    // A thread-local rather than a global because the hazard is re-entry by ONE
    // thread: libtest runs tests on many threads and two of them each holding a
    // reservation is the ordinary case the mutex exists to serialise.
    thread_local! {
        static HOLDS_PORT_RESERVATION: core::cell::Cell<bool> =
            const { core::cell::Cell::new(false) };
    }

    /// Sets `HOLDS_PORT_RESERVATION` for as long as a reservation is alive, and
    /// refuses a second one on the same thread.
    ///
    /// Armed BEFORE the mutex is taken, which is the whole point: after the
    /// `lock()` call there is nothing left to report from.
    struct ReentryGuard;

    impl ReentryGuard {
        fn arm(caller: &str) -> Self {
            HOLDS_PORT_RESERVATION.with(|held| {
                assert!(
                    !held.get(),
                    "PortReservation::{caller} was called on a thread that \
                     ALREADY holds a reservation. `port_lock` is a \
                     non-reentrant mutex, so this call would block forever and \
                     libtest would print nothing until the job was killed.\n  \
                     If you need two ports, use \
                     `PortReservation::pick_pair()`, which reserves both under \
                     ONE acquisition and guarantees they differ.\n  \
                     If the first reservation is genuinely finished, drop it \
                     first -- the guard must live only until the child has \
                     bound its port."
                );
                held.set(true);
            });
            Self
        }
    }

    impl Drop for ReentryGuard {
        fn drop(&mut self) {
            HOLDS_PORT_RESERVATION.with(|held| held.set(false));
        }
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
    /// R311y490 — THE PARAGRAPH THAT USED TO SIT HERE WAS WRONG ABOUT WHO THE
    /// COMPETITOR IS, and the deferral it justified expired. It said the
    /// reservation "does NOT defend against an EXTERNAL process stealing the
    /// port between `drop(listener)` and the child's `bind`", called that window
    /// "sub-millisecond ... not observed in this workspace's CI history", and
    /// deferred FD inheritance "until the in-process race is confirmed
    /// insufficient".
    ///
    /// The in-process race IS confirmed insufficient. The competitor is not an
    /// exotic external process: cargo runs a crate's test BINARIES concurrently,
    /// **17 were measured alive at once** in Layer E's `--ignored` sweep, and
    /// each has its OWN `static` mutex — so sixteen siblings ran that window
    /// against each other, unguarded, continuously. Reproduced: 17 concurrent
    /// processes lose the port 1 time in 6800 with a minimal window, and the
    /// real one spans a `fork` + `exec`.
    ///
    /// FD inheritance is NOT the fix available here, either: the listener in the
    /// leg that surfaced this is zenoh-pico's own `z_sub`, a foreign C binary
    /// with no `--listen-fd` to give it. `CrossProcessPortLock` widens the
    /// exclusion to the scope the design always intended instead.
    ///
    /// What remains undefended is a genuinely unrelated process on the machine
    /// binding the same ephemeral port inside the window. That one is unchanged,
    /// and unlike the sibling case it is not something this repo creates.
    pub struct PortReservation {
        port: u16,
        _guard: MutexGuard<'static, ()>,
        /// R311y490 — held for the SAME window as `_guard`, and released by the
        /// same drop. See `CrossProcessPortLock` for why the mutex alone was
        /// only one seventeenth of the exclusion this window needs.
        _cross_process: Option<CrossProcessPortLock>,
        /// R2049 — clears [`HOLDS_PORT_RESERVATION`] when this reservation
        /// dies, so a LATER `pick` on the same thread is fine and only an
        /// OVERLAPPING one is refused.
        _reentry: ReentryGuard,
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
            // BEFORE the mutex, or the deadlock wins the race to report itself.
            let reentry = ReentryGuard::arm("pick");
            let guard = port_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Ordering is fixed: intra-process mutex FIRST, then the file lock.
            // Both `pick` and `pick_pair` take them in this order, so two threads
            // of one process can never hold them crosswise.
            let cross_process = CrossProcessPortLock::acquire();
            let (listener, port) = Self::bind_ephemeral();
            drop(listener);
            Self {
                port,
                _guard: guard,
                _cross_process: cross_process,
                _reentry: reentry,
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
            let reentry = ReentryGuard::arm("pick_pair");
            let guard = port_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let cross_process = CrossProcessPortLock::acquire();
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
                    _cross_process: cross_process,
                    _reentry: reentry,
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
    ///
    /// R311y776 — "freshly-built" was a WISH until this round, and it cost a
    /// wrong diagnosis. This helper returns whatever file exists, so a binary
    /// built before the change under test is picked up silently and every
    /// fixture that spawns it tests the OLD behaviour. That happened: a witness
    /// written for R311y771's Interest emit redded against a demo predating it,
    /// and the red was attributed to a feature-closure defect that did not
    /// exist. Nothing in the harness could have said otherwise — the binary
    /// prints its feature banner, which a stale build prints identically.
    ///
    /// [`assert_demo_binary_newer_than_sources`] is the check; it is deliberately
    /// NOT folded in here, because this function is also used by fixtures that
    /// only need the path (usage strings, argv rejection) and staleness cannot
    /// mislead those.
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

    /// R311y776 — refuse a `wz-ap-demo` binary OLDER than the sources it is
    /// supposed to embody.
    ///
    /// A behavioural fixture that spawns the demo is making a claim about the
    /// CURRENT tree; a stale binary turns that into a claim about some past one,
    /// and the failure mode is the worst kind — it looks like the feature under
    /// test does not work, so the diagnosis goes hunting in the wrong place. The
    /// remedy is cheap and local: compare mtimes.
    ///
    /// Deliberately mtime-based rather than a rebuild: a helper that shells out
    /// to cargo inside a test would serialise every fixture behind a build lock
    /// and hide compile errors inside test output. Reporting the staleness and
    /// naming the fix is the harness's job; running the build is the lane's.
    ///
    /// The comparison walks `crates/*/src`, MINUS the crates a demo build cannot
    /// possibly depend on: anything named `*-tests` or `*-test-support`, which
    /// are dev-only. That exclusion is not tidiness — without it this check
    /// false-alarms on its own file. Editing `wz-integration-tests/src/lib.rs`
    /// correctly does NOT relink the demo, so the demo's mtime stays behind and
    /// a naive walk calls it stale on every run; measured, on the first run of
    /// this very function.
    ///
    /// The residual imprecision is stated rather than hidden: a change to a
    /// non-test crate the demo does not link still false-alarms. That direction
    /// is the safe one — it asks for a rebuild that costs seconds — whereas the
    /// direction this exists to prevent (a stale binary read as a working one)
    /// costs a wrong diagnosis. `out/` and `sources/` are excluded for a
    /// different reason: codegen output is committed and regenerating it is
    /// Layer B2's business, so a fresh checkout would otherwise report every
    /// binary stale.
    pub fn assert_demo_binary_newer_than_sources(demo: &std::path::Path) {
        let built = match demo.metadata().and_then(|m| m.modified()) {
            Ok(t) => t,
            // A filesystem with no mtime is not a reason to fail a proof; say so
            // rather than guessing, so a green here is never mistaken for a
            // freshness check that ran.
            Err(e) => {
                eprintln!("wz-ap-demo freshness: mtime unavailable ({e}); check SKIPPED");
                return;
            }
        };
        let crates_dir = project_root().join("crates");
        let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
        let Ok(entries) = std::fs::read_dir(&crates_dir) else {
            eprintln!("wz-ap-demo freshness: crates/ unreadable; check SKIPPED");
            return;
        };
        for entry in entries.flatten() {
            let crate_dir = entry.path();
            // Dev-only crates cannot be a demo dependency, so a change in one
            // says nothing about the binary's freshness. See the doc comment:
            // without this, editing THIS file reports THIS binary stale.
            let is_dev_only = crate_dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("-tests") || n.ends_with("-test-support"));
            if is_dev_only {
                continue;
            }
            let src = crate_dir.join("src");
            if !src.is_dir() {
                continue;
            }
            newest_rust_file(&src, &mut newest);
        }
        if let Some((t, path)) = newest {
            if t > built {
                panic!(
                    "wz-ap-demo is STALE: {} is newer than the binary at {}.\n\
                     This fixture spawns that binary, so it would be testing an OLDER \
                     tree than the one under test -- which reads as \"the feature does \
                     not work\" and sends the diagnosis somewhere else entirely \
                     (R311y774 paid exactly that).\n\
                     Fix: cargo build -p wz-ap-demo",
                    path.display(),
                    demo.display(),
                );
            }
        }
    }

    /// Depth-first walk recording the newest `.rs` under `dir`. Separate from
    /// its caller so the recursion is not tangled with the per-crate loop.
    fn newest_rust_file(
        dir: &std::path::Path,
        newest: &mut Option<(std::time::SystemTime, PathBuf)>,
    ) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                newest_rust_file(&path, newest);
            } else if path.extension().is_some_and(|e| e == "rs") {
                if let Ok(t) = entry.metadata().and_then(|m| m.modified()) {
                    // `is_none_or` is 1.82 and this workspace's MSRV is 1.81,
                    // so the match is spelled out rather than borrowed from a
                    // newer std (clippy's msrv lint caught it).
                    if newest.as_ref().map_or(true, |(best, _)| t > *best) {
                        *newest = Some((t, path));
                    }
                }
            }
        }
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

    /// Locate the `wz-capi-pico` C-ABI shared object — the artifact a
    /// zenoh-pico C program links as a BINARY DROP-IN (§5.27
    /// `api-compat-pico`).
    ///
    /// Unlike every other helper here this does NOT resolve an executable: it
    /// resolves the `cdylib` a foreign C program is linked AGAINST. That is
    /// the atom's whole claim, so it is the artifact a witness has to exercise.
    ///
    /// The `.so` is deliberately reached through the filesystem rather than by
    /// making `wz-capi-pico` a dev-dependency of this crate. A dev-dep would
    /// pull the rlib into the test binary, where its `#[no_mangle]` `z_*`
    /// exports would sit alongside the REAL zenoh-pico ones this crate already
    /// links through `zenoh-pico-sys` (the layer3 codec-parity tests) — two
    /// definitions of `z_open`, `z_put`, `z_bytes_loan` and the rest in one
    /// link. Keeping the drop-in at the OS linker boundary is what keeps the
    /// two implementations separable, and it is also the only shape that
    /// witnesses the real deployment: a C program picks ONE `libzenohpico`-
    /// shaped library at link time.
    pub fn wz_capi_pico_cdylib() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/libwz_capi_pico.so"),
            crates_dir.join("target/release/libwz_capi_pico.so"),
        ];
        for c in &candidates {
            if c.is_file() {
                assert_capi_cdylib_is_not_stale(c, &crates_dir, "wz-capi-pico");
                return c.clone();
            }
        }
        panic!(
            "libwz_capi_pico.so not found in {candidates:?}; \
             run `cargo build -p wz-capi-pico` first"
        );
    }

    /// R311y498 — the §5.27 `api-compat-c` cdylib, the zenoh-c ABI's artifact.
    ///
    /// R2303 (open-debt item 636) gave it the same STALENESS guard the pico
    /// sibling has carried since R311y482, and for the same reason measured a
    /// second time: this crate does not depend on `wz-capi-c`, so
    /// `cargo test -p wz-integration-tests` never rebuilds the artifact and a
    /// run silently witnesses whatever `.so` is already there. That round's
    /// mutation control hit it — the first mutation ran against a library built
    /// before the edit and the oracle reported PASS, which is the exact shape
    /// R311y482 named: a damage probe reading green because the damage never
    /// reached the artifact.
    pub fn wz_capi_c_cdylib() -> PathBuf {
        let crates_dir = project_root().join("crates");
        let candidates = [
            crates_dir.join("target/debug/libwz_capi_c.so"),
            crates_dir.join("target/release/libwz_capi_c.so"),
        ];
        for c in &candidates {
            if c.is_file() {
                assert_capi_cdylib_is_not_stale(c, &crates_dir, "wz-capi-c");
                return c.clone();
            }
        }
        panic!(
            "libwz_capi_c.so not found in {candidates:?}; \
             run `cargo build -p wz-capi-c` first"
        );
    }

    /// The zenoh-c ORACLE on this machine: its include dir, its library dir, and
    /// its example corpus.
    ///
    /// `None` when any part is missing. It is machine-local — the headers are an
    /// installed artifact and the examples are a clone — so a caller must decide
    /// whether absence is a SKIP or a hard failure. The lane makes that decision
    /// with an arming flag; this function only reports.
    ///
    /// Overridable with `WZ_ZENOH_C_PREFIX` / `WZ_ZENOH_C_EXAMPLES` so a CI job
    /// that provisions the oracle elsewhere does not need this list edited.
    pub fn zenoh_c_oracle() -> Option<(PathBuf, PathBuf, PathBuf)> {
        let home = PathBuf::from(std::env::var("HOME").ok()?);
        let prefix = std::env::var("WZ_ZENOH_C_PREFIX")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".local"));
        let examples = std::env::var("WZ_ZENOH_C_EXAMPLES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join("zenoh-c-ref/examples"));
        let include = prefix.join("include");
        let libdir = prefix.join("lib");
        if !include.join("zenoh.h").is_file()
            || !libdir.join("libzenohc.so").is_file()
            || !examples.join("z_put.c").is_file()
        {
            return None;
        }
        Some((include, libdir, examples))
    }

    /// The REAL `libzenohc.so` — the zenoh-c ORACLE, as an artifact.
    ///
    /// R311y565 — a NAMED, REGISTERED resolver, and the naming is the whole
    /// point. Layer A4's corpus classifier derives a file's foreign class from
    /// the resolver FUNCTIONS it names, so a library reached through a local
    /// `libdir.join("libzenohc.so")` is one the audit cannot see is foreign. The
    /// sibling `zenoh_pico_shared_library` was inlined the same way until
    /// R311y536 and every claim in the strongest pico differential in the tree
    /// read as a wz-vs-wz test.
    ///
    /// It is exactly what made `api-compat-c` carry no reference-implementation
    /// proof while a twice-and-diff against that very library ran on every C1cc
    /// pass. Returns `None` rather than panicking, because the oracle is
    /// machine-local and each caller decides whether absence is a skip.
    pub fn zenoh_c_shared_library() -> Option<PathBuf> {
        let (_include, libdir, _examples) = zenoh_c_oracle()?;
        let path = libdir.join("libzenohc.so");
        path.is_file().then_some(path)
    }

    /// Compile ONE upstream zenoh-c example against a chosen library.
    ///
    /// `link` is the library NAME (`wz_capi_c` for the drop-in arm, `zenohc` for
    /// the reference arm) and `libdir` is where it lives. The SOURCE and the
    /// HEADERS are upstream's in both arms, unmodified — that is the whole point:
    /// the only thing that differs between the two binaries is which
    /// implementation answers the `z_*` calls.
    pub fn compile_zenoh_c_example(
        example: &str,
        out_dir: &Path,
        include: &Path,
        examples: &Path,
        libdir: &Path,
        link: &str,
    ) -> Result<PathBuf, String> {
        let src = examples.join(format!("{example}.c"));
        if !src.is_file() {
            return Err(format!("upstream example {} missing", src.display()));
        }
        let exe = out_dir.join(format!("{example}_on_{link}"));
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let out = Command::new(&cc)
            .arg(&src)
            .arg("-std=c11")
            // R2303 (open-debt item 636) — an implicit declaration is an ERROR
            // here, not a warning nobody reads. C89 lets a call to an undeclared
            // function through by assuming it returns `int`, which TRUNCATES a
            // returned pointer on LP64 and segfaults at the first dereference.
            // That is not a hypothesis: the config-document probe called
            // `strdup` (POSIX, hidden by `-std=c11`) and crashed on the wz arm,
            // which read as a wz ABI defect until the probe was compiled by hand
            // and the warning was seen. Every diagnostic this helper produces on
            // a SUCCESSFUL compile is discarded, so a warning here is invisible
            // by construction and the only way to surface it is to refuse.
            //
            // MEASURED before turning on: all 29 of upstream's examples at
            // zenoh-c 1.10.0 compile clean under it.
            .arg("-Werror=implicit-function-declaration")
            .arg(format!("-I{}", include.display()))
            // upstream's examples include their own `parse_args.h` from the
            // example directory.
            .arg(format!("-I{}", examples.display()))
            .arg("-o")
            .arg(&exe)
            .arg(format!("-L{}", libdir.display()))
            .arg(format!("-l{link}"))
            .arg(format!("-Wl,-rpath,{}", libdir.display()))
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn C compiler {cc:?}: {e}"));
        if !out.status.success() {
            return Err(format!(
                "{cc} failed for {example}.c against -l{link} (status {:?})\n\
                 --- stderr ---\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr),
            ));
        }
        Ok(exe)
    }

    /// R311y482 — refuse a cdylib OLDER than the `wz-capi-pico` sources it is
    /// supposed to be built from.
    ///
    /// `wz-capi-pico` is deliberately NOT a dependency of this crate (its
    /// `#[no_mangle]` `z_*` exports would collide with the real zenoh-pico ones
    /// linked via `zenoh-pico-sys`), so `cargo test -p wz-integration-tests` does
    /// not rebuild it and cargo's own staleness tracking never sees it. run-ci's
    /// Layer E builds it explicitly for that reason, but a HAND invocation has no
    /// such step and silently links whatever `.so` is already in `target/debug`.
    ///
    /// That is not a hypothetical: a damage test on `TokenState::drop` during
    /// R311y482 read GREEN because the edit had never reached the linked artifact,
    /// and the round nearly concluded the damaged function was not load-bearing.
    /// A gate that cannot trust its input must not report green
    /// (`feedback_damage_must_build_before_you_read_it`), so this is a HARD panic
    /// naming the command, not a warning.
    ///
    /// Compares against the newest mtime under `<crate>/src` plus its
    /// `Cargo.toml`. A missing mtime is treated as "cannot establish freshness"
    /// and passes — the check exists to catch the stale-artifact case, and a
    /// filesystem that will not report mtimes is a different problem that should
    /// not turn every run of this crate red.
    ///
    /// R2303 (open-debt item 636) made it take the CRATE NAME, because the
    /// sibling C ABI had the same hazard and no guard. The proof is that round's
    /// own control group: a mutation to `wz-capi-c/src/config.rs` was run
    /// against a cdylib built before it and the oracle reported exit 0 — a
    /// mutation control that measured the un-mutated library and would have
    /// been read as "the gate does not catch this".
    ///
    /// ⚠ It watches the named crate's own sources ONLY, not its dependency
    /// closure. An edit in `wz-runtime-tokio` also staleness the artifact and
    /// this cannot see it; the case it exists for is the one that has actually
    /// happened twice, which is an edit to the ABI crate itself.
    fn assert_capi_cdylib_is_not_stale(cdylib: &Path, crates_dir: &Path, krate: &str) {
        fn newest_mtime(dir: &Path) -> Option<std::time::SystemTime> {
            let mut newest = None;
            let mut stack = vec![dir.to_path_buf()];
            while let Some(p) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&p) else {
                    continue;
                };
                for e in entries.flatten() {
                    let path = e.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.extension().is_some_and(|x| x == "rs") {
                        if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                            newest = Some(newest.map_or(m, |n: std::time::SystemTime| n.max(m)));
                        }
                    }
                }
            }
            newest
        }

        let src = crates_dir.join(format!("{krate}/src"));
        let manifest = crates_dir.join(format!("{krate}/Cargo.toml"));
        let Ok(lib_mtime) = std::fs::metadata(cdylib).and_then(|m| m.modified()) else {
            return;
        };
        let mut newest_src = newest_mtime(&src);
        if let Ok(m) = std::fs::metadata(&manifest).and_then(|m| m.modified()) {
            newest_src = Some(newest_src.map_or(m, |n: std::time::SystemTime| n.max(m)));
        }
        let Some(newest_src) = newest_src else { return };
        assert!(
            lib_mtime >= newest_src,
            "{} is OLDER than the {krate} sources it links.\n\
             `cargo test -p wz-integration-tests` does NOT rebuild it ({krate} \
             is not a dependency of this crate), so this run would witness code that \
             is no longer in the tree -- including a damage edit that would read as \
             'not load-bearing'.\n\
             run: cargo build -p {krate}",
            cdylib.display(),
        );
    }

    /// The include directories that let a C compiler build a real zenoh-pico
    /// program against the REAL zenoh-pico headers: the vendored source tree
    /// plus the CMake-GENERATED `zenoh-pico/config.h`.
    ///
    /// Both are needed and neither substitutes for the other. The source tree
    /// carries the API headers; `config.h` carries the `Z_FEATURE_*` switches,
    /// and it does not exist in the source tree at all — CMake writes it from
    /// the configure-time options. Reading the feature set off the cmake
    /// command line instead of off the generated header is the trap R311y466
    /// recorded (`-DFLAG=ON` on the command line can still leave the macro
    /// OFF), so this points at the generated file and nothing else.
    ///
    /// The generated dir belongs to `scripts/build-zenoh-pico-cli.sh`, the same
    /// script that installs the pico CLI oracles. That coupling is the point:
    /// a program compiled through these includes sees the SAME feature
    /// configuration as the `zenoh_pico_cli_binary` it will talk to, so a
    /// mismatch between the two can never be mistaken for an interop failure.
    ///
    /// Panics with the build hint if either dir is missing — the same prereq
    /// discipline as [`zenoh_pico_cli_binary`]; a missing header set must not
    /// degrade into a green run.
    pub fn zenoh_pico_include_dirs() -> [PathBuf; 3] {
        let root = project_root();
        let vendored = root.join("vendor/zenoh-pico/include");
        let generated = root.join("target/zenoh-pico-build/zenohpico/include");
        assert!(
            vendored.is_dir(),
            "vendored zenoh-pico headers missing at {}; run \
             `git submodule update --init vendor/zenoh-pico`",
            vendored.display()
        );
        assert!(
            generated.is_dir(),
            "GENERATED zenoh-pico config.h dir missing at {}; run \
             scripts/build-zenoh-pico-cli.sh first (it is the CMake configure \
             product, and it pins the Z_FEATURE_* set the pico oracles were \
             built with)",
            generated.display()
        );
        [generated, vendored, mbedtls_include_dir()]
    }

    /// The Mbed TLS include dir every pico drop-in compile now needs.
    ///
    /// R311y534 — this is a consequence of `Z_FEATURE_LINK_TLS 1`, not a TLS-leg
    /// detail: with TLS on, `zenoh-pico/link/link.h` pulls
    /// `link/transport/tls_stream.h`, which `#include`s `mbedtls/ssl.h` and
    /// friends. `link.h` is reached from `zenoh-pico.h`, so EVERY example — the
    /// 30 that have nothing to do with TLS included — stops compiling without
    /// these headers on the path.
    ///
    /// It resolves the PINNED prefix `scripts/install-mbedtls.sh` provisions,
    /// deliberately NOT a system include dir. A distro `libmbedtls-dev` would
    /// often satisfy the compiler by accident, and then the suite would be
    /// silently coupled to whatever version that box happened to carry — while a
    /// box without it (Ubuntu 22.04 ships no pkg-config for Mbed TLS, so the
    /// pico CMake configure fails there regardless) would fail much later with a
    /// confusing message. Naming the provisioned prefix makes the dependency the
    /// same fact on every machine.
    pub fn mbedtls_include_dir() -> PathBuf {
        let dir = std::env::var("WZ_MBEDTLS_PREFIX")
            .map(PathBuf::from)
            .unwrap_or_else(|_| project_root().join("target/mbedtls"))
            .join("include");
        assert!(
            dir.join("mbedtls/entropy.h").is_file(),
            "Mbed TLS headers missing at {}; run scripts/install-mbedtls.sh \
             (build-zenoh-pico-cli.sh calls it, so this usually means the pico \
             build has not been run on this checkout). They are required by \
             EVERY pico drop-in compile, not just the TLS ones: with \
             Z_FEATURE_LINK_TLS on, zenoh-pico.h reaches mbedtls/*.h through \
             link.h",
            dir.display()
        );
        dir
    }

    /// The same pair as [`zenoh_pico_include_dirs`], but resolving `config.h`
    /// from the SINGLE-THREADED CMake arm (`Z_FEATURE_MULTI_THREAD 0`).
    ///
    /// Two upstream examples — `z_pub_st.c` and `z_sub_st.c` — guard their whole
    /// `main` on that macro being 0, so against the primary header tree they
    /// compile to a one-`printf` stub and a leg driving them would exercise no wz
    /// code at all. This is the header set that gives them a body.
    ///
    /// Only the config header differs; the API headers are the same vendored
    /// tree, and the LIBRARY is wz's cdylib either way. That the one cdylib
    /// serves both arms is a measurement, not a convenience: across the two
    /// configs the only public owned types whose size moves are
    /// `z_owned_mutex_t` and `z_owned_condvar_t`, neither of which either
    /// example names. `scripts/build-zenoh-pico-cli.sh` carries the numbers and
    /// generates this tree.
    pub fn zenoh_pico_include_dirs_single_threaded() -> [PathBuf; 3] {
        let root = project_root();
        let vendored = root.join("vendor/zenoh-pico/include");
        let generated = root.join("target/zenoh-pico-build-st/zenohpico/include");
        assert!(
            vendored.is_dir(),
            "vendored zenoh-pico headers missing at {}; run \
             `git submodule update --init vendor/zenoh-pico`",
            vendored.display()
        );
        assert!(
            generated.is_dir(),
            "SINGLE-THREADED zenoh-pico config.h dir missing at {}; run \
             scripts/build-zenoh-pico-cli.sh first (it configures a second CMake \
             arm whose only delta is -DZ_FEATURE_MULTI_THREAD=0)",
            generated.display()
        );
        [generated, vendored, mbedtls_include_dir()]
    }

    /// Compile an UNMODIFIED upstream zenoh-pico example
    /// (`vendor/zenoh-pico/examples/unix/c11/<example>.c`) against the REAL
    /// zenoh-pico headers and link it against wz's C-ABI `cdylib`, returning
    /// the executable's path.
    ///
    /// This is the §5.27 `api-compat-pico` witness apparatus. The claim under
    /// test is "a zenoh-pico C program can link the wz cdylib as a binary
    /// drop-in", and each half of that sentence is supplied by a foreign
    /// artifact: upstream's own program TEXT, and upstream's own HEADERS
    /// (types, struct sizes, and the `_Generic` `z_loan`/`z_move`/`z_drop`
    /// dispatch in `api/macros.h`). Only the library is wz's. So the compiler
    /// and the linker do the checking that no wz-authored test could do for
    /// itself: a wrong struct size, a missing export, or a getter whose
    /// null-contract differs from pico's is caught by pico's own program
    /// rather than by an assertion we chose.
    ///
    /// `-DZENOH_LINUX` is required, not optional: pico's
    /// `system/common/platform.h` `#error "Unknown platform"`s without one of
    /// its `ZENOH_<PLATFORM>` macros, and it is the platform selector CMake
    /// passes for a Unix build. `-Wl,-rpath` is baked so the produced binary
    /// finds the `.so` without the caller having to export
    /// `LD_LIBRARY_PATH` — the runtime library search is part of what "drop-in"
    /// means.
    ///
    /// A compile or link failure is returned as `Err(diagnostics)` rather than
    /// panicked, because for this atom a link failure is a MEASUREMENT (which
    /// exports are missing) and a caller may want to assert on it.
    pub fn compile_pico_example_against_wz_capi(
        example: &str,
        out_dir: &Path,
    ) -> Result<PathBuf, String> {
        compile_pico_example_against_wz_capi_with_includes(
            example,
            out_dir,
            &zenoh_pico_include_dirs(),
        )
    }

    /// [`compile_pico_example_against_wz_capi`] against a caller-chosen header
    /// set — the SINGLE-THREADED arm
    /// ([`zenoh_pico_include_dirs_single_threaded`]) being the reason it exists.
    ///
    /// The header set is the only knob a drop-in has for selecting which
    /// `#if Z_FEATURE_*` branch of an upstream example gets compiled, and two of
    /// them have no body under the primary arm. Everything else — upstream's own
    /// program text, wz's cdylib as the sole library, the baked rpath — is
    /// identical, so a leg built this way is the same witness as any other.
    pub fn compile_pico_example_against_wz_capi_with_includes(
        example: &str,
        out_dir: &Path,
        includes: &[PathBuf],
    ) -> Result<PathBuf, String> {
        let root = project_root();
        let src = root
            .join("vendor/zenoh-pico/examples/unix/c11")
            .join(format!("{example}.c"));
        assert!(
            src.is_file(),
            "upstream zenoh-pico example {} missing; run \
             `git submodule update --init vendor/zenoh-pico`",
            src.display()
        );
        let cdylib = wz_capi_pico_cdylib();
        let libdir = cdylib
            .parent()
            .expect("cdylib path has a parent directory")
            .to_path_buf();
        let exe = out_dir.join(format!("{example}_on_wz"));

        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let mut cmd = Command::new(&cc);
        cmd.arg(&src).arg("-DZENOH_LINUX");
        for inc in includes {
            cmd.arg(format!("-I{}", inc.display()));
        }
        cmd.arg("-o")
            .arg(&exe)
            .arg(format!("-L{}", libdir.display()))
            .arg("-lwz_capi_pico")
            .arg(format!("-Wl,-rpath,{}", libdir.display()));

        let out = cmd
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn C compiler {cc:?}: {e}"));
        if !out.status.success() {
            return Err(format!(
                "{cc} failed for {example}.c (status {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            ));
        }
        Ok(exe)
    }

    /// Locate the CMake-built real `libzenohpico.so` — the foreign
    /// implementation as a LIBRARY rather than as a spawned CLI.
    ///
    /// R311y536 — this exists because two corpus files were reaching that
    /// artifact through resolvers of their own: `pico_pure_function_oracle.rs`
    /// `dlopen`ed a `project_root().join(..)` path inline, and this file's
    /// drop-in suite linked `target/zenoh-pico-build/lib` through a local
    /// `oracle_binary` helper. Both are genuine foreign witnesses, and Layer
    /// A4's classifier could see NEITHER: it derives a file's foreign class
    /// from the RESOLVER FUNCTIONS the file names (`FOREIGN_ROOTS` in
    /// `scripts/lib/crossimpl_corpus.py`), so an artifact resolved by hand is
    /// an artifact the audit does not know is foreign. Five `wz->pico` claims
    /// were therefore rejected as "this file spawns/links no foreign
    /// implementation" and the lane was red.
    ///
    /// The fix is the one the corpus module's own header prescribes — reach the
    /// foreign artifact through a NAMED helper — rather than teaching the
    /// classifier about `dlopen`, because the next hand-rolled resolver would
    /// be invisible again.
    pub fn zenoh_pico_shared_library() -> PathBuf {
        let path = zenoh_pico_library_dir().join("libzenohpico.so");
        assert!(
            path.is_file(),
            "libzenohpico.so missing at {}; run scripts/build-zenoh-pico-cli.sh first",
            path.display()
        );
        path
    }

    /// Compile ONE C source against a chosen pico implementation — the generic
    /// form both `_on_wz` and `_oracle` builds reduce to.
    ///
    /// R311y569. Its two predecessors take an upstream example NAME and dig it
    /// out of the vendored tree, which is right for the corpus and wrong for a
    /// PATCHED program: the y548 remedy for "no upstream example sets this
    /// field" is to take upstream's source, add the calls, and compile the
    /// RESULT twice. That has no name in `vendor/`, so it needs an entry point
    /// that takes a path.
    ///
    /// `link` is the library stem — `wz_capi_pico` or `zenohpico` — and it is
    /// also what the output binary is named after, so the two arms cannot
    /// overwrite each other in one directory. Everything else is identical
    /// between the arms by construction, which is what makes a diff of their
    /// stdout a statement about the two libraries and nothing else.
    ///
    /// The zenoh-c side has had [`compile_zenoh_c_example`] in this shape since
    /// y500; this is the pico twin.
    pub fn compile_pico_source(
        src: &Path,
        out_dir: &Path,
        includes: &[PathBuf],
        libdir: &Path,
        link: &str,
    ) -> Result<PathBuf, String> {
        let stem = src
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("pico_probe");
        let exe = out_dir.join(format!("{stem}_on_{link}"));
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let mut cmd = Command::new(&cc);
        cmd.arg(src).arg("-DZENOH_LINUX");
        for inc in includes {
            cmd.arg(format!("-I{}", inc.display()));
        }
        cmd.arg("-o")
            .arg(&exe)
            .arg(format!("-L{}", libdir.display()))
            .arg(format!("-l{link}"))
            .arg(format!("-Wl,-rpath,{}", libdir.display()));
        let out = cmd
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn C compiler {cc:?}: {e}"));
        if !out.status.success() {
            return Err(format!(
                "{cc} failed for {} against -l{link} (status {:?})\n--- stderr ---\n{}",
                src.display(),
                out.status.code(),
                String::from_utf8_lossy(&out.stderr),
            ));
        }
        Ok(exe)
    }

    /// The directory [`zenoh_pico_shared_library`] lives in — what a `cc -L`
    /// needs when an upstream example is linked against REAL pico as the
    /// reference arm of a compile-twice differential.
    pub fn zenoh_pico_library_dir() -> PathBuf {
        let dir = project_root().join("target/zenoh-pico-build/lib");
        assert!(
            dir.is_dir(),
            "zenoh-pico build lib dir missing at {}; run \
             scripts/build-zenoh-pico-cli.sh first",
            dir.display()
        );
        dir
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

    /// R311y442 — locate a `zenoh-ext-examples` example binary (`z_advanced_pub`
    /// / `z_advanced_sub`): the `WZ_ZENOH_EXT_EXAMPLES_DIR` env override, else
    /// `scripts/build-zenohd.sh`'s `target/zenohd/` install.
    ///
    /// These are the ONLY foreign advanced-pubsub counterparties that exist.
    /// zenohd is a router and carries no `AdvancedCache`; zenoh-pico has no
    /// advanced-pubsub plane at all. So unlike every other cross-impl leg in this
    /// tree, the `@adv` legs cannot be witnessed by the two oracles already
    /// provisioned — the cache lives in an APPLICATION built on `zenoh-ext`, and
    /// upstream's own examples are exactly that application.
    ///
    /// Panics with the build hint if absent, the same prereq discipline as
    /// [`zenoh_pico_cli_binary`] and [`zenohd_binary`]: a missing oracle must not
    /// degrade into a green run.
    pub fn zenoh_ext_example_binary(name: &str) -> PathBuf {
        let dir = match std::env::var("WZ_ZENOH_EXT_EXAMPLES_DIR") {
            Ok(d) => PathBuf::from(d),
            Err(_) => project_root().join("target/zenohd"),
        };
        let path = dir.join(name);
        assert!(
            path.is_file(),
            "{name} binary missing at {}; set WZ_ZENOH_EXT_EXAMPLES_DIR or run \
             scripts/build-zenohd.sh first (it builds the zenoh-ext examples \
             alongside zenohd from the same pinned checkout)",
            path.display()
        );
        path
    }

    /// R311y841 — locate a CORE `zenoh-examples` binary (`z_queryable`, `z_get`
    /// or `z_pub`), installed by `scripts/build-zenohd.sh` under a `zenoh_`
    /// prefix so which IMPLEMENTATION a leg spawned is legible at the call site:
    /// this tree also carries a `z_get`, a `z_queryable` and a `z_pub` from
    /// zenoh-pico, and the two sets are different oracles with different
    /// capabilities.
    ///
    /// `z_pub` joined them in R2200 (open-debt item 558) for a capability the
    /// query pair's reason does not cover: it is the only publisher any oracle
    /// here provisions that can be told WHICH PRIORITY to publish at. It has no
    /// priority FLAG either, but it has `--cfg`, and `qos/publication` is a real
    /// config path — see [`spawn_publishing_zenoh_zpub`].
    ///
    /// The query pair exists because a `QueryTarget` route selects on COMPLETENESS, and
    /// neither oracle already provisioned can express it. zenohd is a router and
    /// declares no queryable of its own; zenoh-pico's `z_queryable` example takes
    /// `z_queryable_options_default()`, whose `complete` is hardcoded `false`
    /// (`_Z_QUERYABLE_COMPLETE_DEFAULT`, `vendor/zenoh-pico/include/zenoh-pico/session/queryable.h:42`)
    /// with no flag to change it. Upstream's own `z_queryable --complete` and
    /// `z_get --target` are the only foreign binaries that can drive both sides
    /// of the decision.
    ///
    /// `WZ_ZENOH_CORE_EXAMPLES_DIR` overrides the directory. Panics with the
    /// build hint if absent, the same prereq discipline as
    /// [`zenoh_ext_example_binary`]: a missing oracle must not degrade into a
    /// green run.
    pub fn zenoh_core_example_binary(name: &str) -> PathBuf {
        let dir = match std::env::var("WZ_ZENOH_CORE_EXAMPLES_DIR") {
            Ok(d) => PathBuf::from(d),
            Err(_) => project_root().join("target/zenohd"),
        };
        let path = dir.join(format!("zenoh_{name}"));
        assert!(
            path.is_file(),
            "zenoh_{name} binary missing at {}; set WZ_ZENOH_CORE_EXAMPLES_DIR or run \
             scripts/build-zenohd.sh first (it builds the core zenoh examples \
             alongside zenohd from the same pinned checkout)",
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

    /// Locate the SHARED-MEMORY-enabled `zenohd` (R311y505): the
    /// `WZ_ZENOHD_SHM_BIN` env override, else `scripts/build-zenohd.sh
    /// ZENOHD_SHM=1`'s `target/zenohd-shm/zenohd` install.
    ///
    /// A SEPARATE binary for the same reason as its two siblings — `shared-memory`
    /// is absent from zenoh's `default` set (`zenoh/Cargo.toml:34-46`) and
    /// zenohd's default is `zenoh/default` — but here the separation is what makes
    /// a whole question ASKABLE rather than merely convenient. The stock oracle has
    /// no `init::ext::Shm` compiled in at all, so it can neither send zenoh's SHM
    /// challenge nor react to wz's offer; pointing wz at it proves only that an
    /// unknown UNIT ext is skippable. Every SHM interop claim needs THIS binary,
    /// and R311y505's defect (wz reading zenoh's `Shm` ZBuf as its own UNIT offer)
    /// is invisible without it.
    ///
    /// Returns `None` rather than panicking: unlike the unixpipe oracle this one
    /// is not provisioned in hosted CI, so its legs SKIP where it is absent (the
    /// vsock precedent).
    pub fn zenohd_shm_binary() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("WZ_ZENOHD_SHM_BIN") {
            let p = PathBuf::from(p);
            return p.is_file().then_some(p);
        }
        let path = project_root().join("target/zenohd-shm/zenohd");
        path.is_file().then_some(path)
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

    /// R311y501 — locate `libzenoh_plugin_rest.so`, the foreign oracle for the
    /// §5.26 REST bridge: the `WZ_REST_PLUGIN_SO` env override, else
    /// `scripts/build-zenohd.sh`'s `target/zenohd/` install.
    ///
    /// zenohd accepts `--rest-http-port` whether or not this file exists — the
    /// flag is a CLI option, not a capability probe — and then dies at startup
    /// with `Plugin load failure: Library file 'libzenoh_plugin_rest.so' not
    /// found`. So a leg must assert on THIS path, not on the flag being
    /// accepted, or it reads a provisioning gap as a wz failure. Only a SOURCE
    /// build produces it (`cargo install` yields binaries, not plugin cdylibs),
    /// exactly as for the storage-manager plugin above.
    pub fn rest_plugin() -> PathBuf {
        if let Ok(p) = std::env::var("WZ_REST_PLUGIN_SO") {
            return PathBuf::from(p);
        }
        let path = project_root().join("target/zenohd/libzenoh_plugin_rest.so");
        assert!(
            path.is_file(),
            "REST plugin missing at {}; set WZ_REST_PLUGIN_SO or run scripts/build-zenohd.sh first",
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
    /// R311y413 — reads POSITIONALLY (`pread`), never seeking.
    ///
    /// The previous `seek(0)` + `read_to_end` moved the file OFFSET, and across this
    /// crate the capture handle is overwhelmingly a `try_clone()` of the handle given
    /// to the child as stdout. `try_clone` is `dup(2)`: the two descriptors share one
    /// open file description, hence ONE offset. So a poll from the parent rewound the
    /// CHILD's write position, and the child's next write landed at the start,
    /// overwriting output already captured. Reproduced deterministically (child writes
    /// AAA, parent rewinds, child writes BBB): the AAA line is GONE under `try_clone`
    /// and intact under two independent descriptions. In the wild it is a low-rate
    /// corruption — the window between the seek and the read is microseconds — which
    /// is exactly the profile of a witness that "sometimes isn't there".
    ///
    /// `read_at` takes the offset as an argument and leaves the description's own
    /// offset untouched, so the hazard is closed for EVERY caller at once rather than
    /// by migrating 171 capture sites to independent descriptions.
    /// Which node a `face N UP` log line belongs to, decided by VALUE.
    ///
    /// R311y903, open-debt item 417. `zenohd_scouts_wz_interop.rs` decided this
    /// by the LENGTH of the rendered zid — `zid.len() == 32`, under a message
    /// asserting "a 16-byte ZenohIdProto". Both halves were wrong, and upstream
    /// says so:
    ///
    /// * `ZenohIdProto` is a newtype over `uhlc::ID`, whose `Debug` is
    ///   `write!(f, "{:x}", u128::from_le_bytes(self.0))`
    ///   (`uhlc-0.8.2/src/id.rs:279-283`). `{:x}` DROPS leading zero nibbles, so
    ///   an ordinary zid renders in fewer than 32 characters.
    /// * `ID::rand()` is `OsRng.gen_range(1..u128::MAX)` (`id.rs:88-92`),
    ///   uniform — so the top nibble is zero once in sixteen and the rendering
    ///   is short 6.25% of the time. Hosted run 32411221953's Layer M is where
    ///   it landed: `left: 30, right: 32` on `e77a27c47363d6d97990a76230cc58`.
    ///   zenohd was correct; the discriminator was not.
    ///
    /// ⚠ AND THE OBVIOUS REPAIR IS ALSO WRONG. "Use the byte count, not the
    /// render length" fails one level down: `ID::size()` is
    /// `MAX_SIZE - (leading_zeros / 8)` (`id.rs:63-67`) — SIGNIFICANT bytes, not
    /// 16. A zid whose top byte is zero has size 15, once in 256. So this
    /// asserts neither a length nor a size: it parses the rendering into the
    /// NUMBER it denotes, which is what both sides agree on. Rendering is lossy
    /// about width and exact about value.
    ///
    /// It lives HERE rather than beside its one caller because Layer C0 requires
    /// every `#[test]` in a binary-dep test FILE to carry `#[ignore]`, and a
    /// deterministic reproduction of a probabilistic defect must run always-on
    /// — putting it in the library is what lets Layer C1's workspace run
    /// execute it with no oracle present.
    /// R311y904 (item 420) — generalised over the MARKER, because the same
    /// question is asked of two differently-shaped log lines and the answer
    /// must be one implementation.
    ///
    /// The face line spells it `zid <hex>)` and the scouted-hello line spells
    /// it `zid=<hex> locators=[..]`. Rather than a terminator per caller, the
    /// hex run is taken up to the first character that is not a hex digit,
    /// which is true of both and of any third shape.
    pub fn zid_value_after(line: &str, marker: &str) -> Option<u128> {
        let (_, rest) = line.split_once(marker)?;
        let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if hex.is_empty() {
            return None;
        }
        u128::from_str_radix(&hex, 16).ok()
    }

    pub fn face_zid_value(line: &str) -> Option<u128> {
        zid_value_after(line, "zid ")
    }

    /// The zid of a peer wz DISCOVERED, out of the `hellos=[..]` rendering.
    ///
    /// R311y904, open-debt item 420. `wz_scout_zenohd_interop.rs` asserted the
    /// rendered hex was 32 characters, under the reasoning that a wrong length
    /// means wz misread the cbyte's length nibble. That reasoning is sound and
    /// the assertion was still wrong, for a reason DIFFERENT from item 417's:
    ///
    /// * wz's renderer is FIXED-WIDTH per byte —
    ///   `h.zid.iter().map(|b| format!("{b:02x}"))`
    ///   (`wz-ap-demo/src/runner.rs:601-605`) — so nothing is lost to nibble
    ///   formatting here. Item 417's 1/16 does NOT apply, and copying it would
    ///   have been wrong.
    /// * But the WIRE is variable-length. zenoh writes
    ///   `flags |= ((zid.size() - 1) as u8) << 4` and then exactly `zid.size()`
    ///   bytes (`zenoh-codec/src/scouting/hello.rs:62-66`), and `ID::size()` is
    ///   `MAX_SIZE - (leading_zeros / 8)` (`uhlc-0.8.2/src/id.rs:63-67`). So a
    ///   zid whose top BYTE is zero travels in 15 bytes and renders in 30
    ///   characters.
    ///
    /// `ID::rand()` is uniform over `1..u128::MAX` (`id.rs:88-92`), so the
    /// measured rate is **1 in 256** — not item 417's 1 in 16. Same class,
    /// different mechanism, different number, and the number was measured here
    /// rather than carried over.
    pub fn hello_zid_value(line: &str) -> Option<u128> {
        zid_value_after(line, "zid=")
    }

    /// The VALUE a zid CONFIGURED as `hex` will be rendered as.
    ///
    /// R311y903 — and this is NOT `u128::from_str_radix(hex, 16)`, which is the
    /// trap that follows immediately after avoiding the first one. zenoh parses
    /// the `id` config string into BYTES and holds them little-endian, and
    /// `uhlc::ID`'s `Debug` renders `u128::from_le_bytes(self.0)` — so the
    /// printed hex is the configured hex WITH ITS BYTES REVERSED.
    ///
    /// MEASURED, not derived: pinning `--cfg id:"2e0db2ae"` on a real zenohd
    /// produced `face 0 UP (... zid aeb20d2e)`. Comparing against the config
    /// string's own numeric value would compare against a number that appears on
    /// no wire — the same shape as the length rule it replaced, one layer down.
    pub fn configured_zid_value(hex: &str) -> u128 {
        assert!(
            hex.len() % 2 == 0 && hex.len() <= 32,
            "a zid config string is whole bytes, at most 16 of them: {hex:?}"
        );
        let mut bytes = [0u8; 16];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let pair = core::str::from_utf8(pair).expect("hex is ascii");
            bytes[i] = u8::from_str_radix(pair, 16).expect("hex byte parses");
        }
        u128::from_le_bytes(bytes)
    }

    /// R2059 (open-debt item 421) — WHICH ZID WIDTH EACH SCOUTING E2E ACTUALLY
    /// DRIVES, in one place.
    ///
    /// # Why this exists rather than a sentence in each test
    ///
    /// A zid's length rides in a nibble, so a Hello can carry 1 to 16 bytes,
    /// and each of these tests pins ONE width in a `format!` whose hex-string
    /// length is the only place the number appears. Item 420 fixed a misread of
    /// that nibble; item 421 recorded that the fix left nobody able to say, in
    /// one place, which widths the suite walks — and warned that the honest
    /// first step is to WRITE IT DOWN before building another fixture, because
    /// a fixture built first measures whatever it happens to measure.
    ///
    /// So this is the writing-down, and it is derived: each row's width is
    /// asserted against what [`per_process_zid_hex`] actually produces, and the
    /// e2e build their zids through that function rather than beside it.
    ///
    /// ⚠ WHAT IT DOES NOT DO is close the axis. Two widths out of sixteen, and
    /// only when a zenohd is present, is not a reading of the nibble.
    /// `wz_session_core::scouting_message`'s
    /// `every_zid_width_a_hello_can_carry_decodes_to_the_bytes_that_went_in`
    /// is what walks all sixteen deterministically; these two are the FOREIGN
    /// witness for two of them, which is a different and smaller claim.
    pub const SCOUTING_E2E_ZID_WIDTHS: &[(&str, usize)] = &[
        ("wz_scout_zenohd_interop", 16),
        ("zenohd_scouts_wz_interop", 4),
        // R2094 (open-debt item 510) — the ROUTER-role foreign witness, and a
        // THIRD width. The row is the width of the zid in the Hello UNDER TEST,
        // which is wz's own here: this leg is read by a foreign decoder, so
        // eight bytes is a length nibble no zenohd in this suite had been
        // handed. It is the width the leg PINS, not one it happened to get.
        ("zenohd_scouts_wz_router_interop", 8),
    ];

    /// A zenohd zid of exactly `bytes` bytes, unique to this process.
    ///
    /// Per-process rather than fixed for the reason both e2e already record: a
    /// fixed zid collides with a leftover or a concurrent copy in zenoh's peer
    /// dedupe. `prefix` keeps the two tests' zids distinguishable in a log, and
    /// the filler is deterministic so the value a test pins is the value it
    /// compares against.
    pub fn per_process_zid_hex(prefix: &str, bytes: usize) -> String {
        assert!(
            (1..=16).contains(&bytes),
            "a zid is 1 to 16 bytes; the length nibble cannot name {bytes}"
        );
        let want = bytes * 2;
        let mut hex = format!("{prefix}{:04x}", std::process::id() & 0xffff);
        assert!(
            hex.len() <= want,
            "prefix {prefix:?} plus the pid is already {} hex chars, more than \
             the {want} a {bytes}-byte zid has",
            hex.len()
        );
        const FILLER: &str = "0123456789abcdef0123456789abcdef";
        hex.push_str(&FILLER[..want - hex.len()]);
        hex
    }

    /// R2118 (open-debt item 507) — what a deadline SAYS when the process it
    /// spawned is still running and has not dialled.
    ///
    /// # The sentence this replaces, and why it was the worst part of 507
    ///
    /// `wz_reads_a_stock_zenohd_config`'s wire leg used to read: "Built without
    /// `zenoh-config` it exits on `--config` and never connects, which is what
    /// this deadline exists to say out loud". Three things were wrong with it,
    /// and the third is the one that cost a round.
    ///
    /// It stated a HYPOTHESIS in the indicative. R2086 met that leg failing,
    /// followed the sentence to the build, and the build was fine: the demo was
    /// refusing `qos` beside `lowlatency` and exiting 2. A message that sends
    /// the diagnosis somewhere else is worse than one that says nothing — the
    /// same shape R311y774 paid for with a stale guard.
    ///
    /// It explained an EXIT on the branch where the child is still ALIVE. The
    /// `try_wait` arm owns the exited case and prints the status; by the time
    /// this text renders, "it exits on `--config`" cannot be what happened. The
    /// two arms had one explanation between them and it belonged to the other.
    ///
    /// And the cause it named is unreachable from here: a build without
    /// `zenoh-config` refuses `--config` and EXITS, so it lands in that arm.
    ///
    /// # Why a function with a witness rather than a better sentence
    ///
    /// Because "write a better sentence" is what the round before also
    /// intended. The FORM is the checkable part — a cause is offered as one of
    /// several under a marker, never as the reason — and
    /// `the_stalled_message_offers_hypotheses_rather_than_a_verdict` asserts
    /// that shape. Open-debt item 530 is why this is a form and not a banned
    /// phrase: a grep for the old wording would pass the next confidently wrong
    /// sentence.
    ///
    /// # Why it lives in the LIBRARY
    ///
    /// Layer C0 requires every `#[test]` in a binary-dep test file to carry
    /// `#[ignore]`, because `cargo test --workspace` on a fresh checkout has no
    /// `wz-ap-demo` to spawn. An ignored witness runs only under a `--ignored`
    /// sweep, and this one needs no process, no socket and no daemon — leaving
    /// it there would have put a pure-function assertion in no ordinary run.
    pub fn still_running_reason(stderr: &str) -> String {
        format!(
            "the demo never dialled the acceptor within the deadline, and it is \
             STILL RUNNING (so it did not refuse its argv and exit -- that case \
             is reported by the other arm, with the exit status).\n\
             possible causes:\n\
             1. the document was accepted but selected a run-mode that dials \
             nothing, or dials somewhere else;\n\
             2. the demo is waiting on something else -- scouting, a second \
             endpoint, a retry backoff -- and the deadline was not enough;\n\
             3. the acceptor's port is not the one the document names.\n\
             Read the demo's own stderr below before choosing one; if it is \
             empty, the demo got far enough to say nothing, which rules out 1.\n\
             --- the demo's stderr ---\n{stderr}"
        )
    }

    pub fn read_captured(file: &mut File) -> String {
        use std::os::unix::fs::FileExt;
        let mut bytes = Vec::new();
        let mut buf = [0u8; 8192];
        let mut at = 0u64;
        loop {
            match file.read_at(&mut buf, at) {
                Ok(0) => break,
                Ok(n) => {
                    bytes.extend_from_slice(&buf[..n]);
                    at += n as u64;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => panic!("read captured bytes at offset {at}: {e}"),
            }
        }
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
        // A listener reached by NAME can land on either loopback family. An
        // endpoint written `tcp/localhost:P` binds wherever the resolver puts
        // `localhost` FIRST, and a host whose /etc/hosts says `::1 localhost`
        // -- which the hosted runners do and this developer machine does not --
        // puts it on `[::1]`, where a `127.0.0.1` probe never arrives. The
        // child stays alive the whole time, so the timeout read
        // "genuinely slow to bind or hung" when nothing was slow and nothing
        // hung: measured on `zenohd_refuses_every_topology_the_validator_rejects`,
        // green here and red on every hosted run since R2112.
        //
        // Loopback is a closed set of two, so probe both rather than making all
        // 77 call sites spell out which family their endpoint resolved to.
        const LOOPBACK: [&str; 2] = ["127.0.0.1", "::1"];
        let deadline = Instant::now() + budget;
        loop {
            if LOOPBACK
                .iter()
                .any(|host| TcpStream::connect((*host, port)).is_ok())
            {
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
                    "did not start accepting tcp on either loopback family \
                     (127.0.0.1:{port} nor [::1]:{port}) within {budget:?} \
                     (process still alive — genuinely slow to bind or hung)"
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Every socket address `name:port` names, in the resolver's own order.
    ///
    /// R2136 — a NAME pins one HOST, not one ADDRESS, and the difference is
    /// what a listen-collision fixture stands on. `tcp/localhost:P` is ONE
    /// endpoint string that this developer machine resolves to one address and
    /// a host whose `/etc/hosts` carries `::1 localhost` resolves to two; a
    /// second zenohd handed the same endpoint then binds the family the first
    /// one left, and BOTH run. Measured, not inferred, by running the very
    /// binary under test under each resolver: `[::1]:P` for the first binder
    /// and `127.0.0.1:P` for the second, read out of `/proc/net/tcp{,6}`.
    ///
    /// So a caller that needs an endpoint to be genuinely exhausted must size
    /// its fixture from THIS, never from the one address a developer machine
    /// happens to show. An empty resolution is an `Err`, not an empty vector:
    /// a population of zero would let every derived assertion pass vacuously.
    pub fn resolve_endpoint_addrs(name: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = (name, port)
            .to_socket_addrs()
            .map_err(|e| format!("resolving {name}:{port} failed: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!(
                "{name}:{port} resolved to NO address — a fixture sized from an \
                 empty set proves nothing"
            ));
        }
        Ok(addrs)
    }

    /// Poll until EVERY address in `addrs` accepts TCP, while `children` live.
    ///
    /// The sibling of [`wait_for_tcp_accept_alive`] for the case that one
    /// address answering is not enough. That function returns as soon as
    /// either loopback family accepts, which is right when one child owns the
    /// port and wrong when several do: the first child up would satisfy the
    /// gate for all of them, and the fixture would race the one still binding.
    ///
    /// `Err` names the addresses still silent, so a timeout says which family
    /// never came up rather than only that something did not.
    pub fn wait_for_every_addr_accept_alive(
        children: &mut [&mut Child],
        addrs: &[SocketAddr],
        budget: Duration,
    ) -> Result<(), String> {
        use std::net::TcpStream;
        let deadline = Instant::now() + budget;
        loop {
            let silent: Vec<String> = addrs
                .iter()
                .filter(|a| TcpStream::connect(*a).is_err())
                .map(|a| a.to_string())
                .collect();
            if silent.is_empty() {
                return Ok(());
            }
            for (i, child) in children.iter_mut().enumerate() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return Err(format!(
                            "child #{i} exited before every address accepted \
                             (status: {status}); still silent: {}",
                            silent.join(", ")
                        ));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        return Err(format!("try_wait on child #{i} failed: {e}"));
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "these addresses never started accepting within {budget:?} \
                     (every child still alive): {}",
                    silent.join(", ")
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Poll `try_wait()` every 50 ms until the child EXITS or `budget` elapses,
    /// returning its status or a diagnosis.
    ///
    /// `Child::wait` blocks forever, which is the wrong shape for any child that
    /// can legitimately spin. Upstream's `z_ping.c` is exactly that: its
    /// `load_loop` busy-waits on an atomic that only advances when the echo
    /// arrives, with no timeout of its own, so a broken return path does not
    /// fail it — it pins a core and never returns. A lane that HANGS is worse
    /// than one that reds, because CI reports nothing at all until the job
    /// budget expires, so the bound belongs on this side.
    ///
    /// The caller keeps the child (this only borrows it), so a timeout can still
    /// be followed by [`graceful_terminate`] before the assertion fires.
    pub fn wait_for_exit(
        child: &mut Child,
        budget: Duration,
    ) -> Result<std::process::ExitStatus, String> {
        let deadline = Instant::now() + budget;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(e) => return Err(format!("try_wait on the spawned child failed: {e}")),
            }
            if Instant::now() >= deadline {
                return Err(format!("still running after {budget:?}"));
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

    /// The zenohd log line every ephemeral-port helper reads its port back from.
    ///
    /// R2230 (open-debt item 579) — MOVED here as one spelling, and moved off
    /// `"Zenoh can be reached at: tcp/127.0.0.1:"`, which the three helpers that
    /// wanted it each spelled for themselves.
    ///
    /// The old needle CANNOT MATCH on the pinned 1.10.0, and it is not a format
    /// change: upstream narrowed what that line is ABOUT. 1.5.0's
    /// `print_locators` iterated `get_locators()`; 1.10.0's iterates
    /// `get_locators_noloopback()` (`zenoh/src/net/runtime/orchestrator.rs:610`
    /// against `1.5.0:...:583`). Every helper here binds `tcp/127.0.0.1:0`
    /// because a test must be hermetic, so the line is now about exactly the
    /// locators these tests never have. Re-spelling the old needle would have
    /// been guessing at a line that no longer exists.
    ///
    /// `Listener added:` is the better needle on its own merits, which is why
    /// this is not a workaround. It is emitted where the listener is actually
    /// added (`orchestrator.rs:601`), it carries the RESOLVED endpoint with the
    /// kernel's port, it is byte-identical in 1.5.0 and 1.10.0, and it says the
    /// thing the callers' own budget message claims to be waiting for —
    /// "announcing its bound tcp listener". The reachability advertisement never
    /// did: a locator can be advertised for a listener that is not this one.
    ///
    /// ⚠ It is a `debug!`, so a helper using it must pin `RUST_LOG=z=debug`.
    /// Measured on the move: 32 lines of zenohd output at that level for a
    /// spawn, against 3 at info, so the capture cost is not a reason to prefer
    /// a line that cannot fire.
    pub const ZENOHD_LISTENER_LINE: &str = "Listener added: tcp/127.0.0.1:";

    /// zenohd's scout-listener announcement, printed from `bind_mcast_port` once
    /// the group socket is bound and joined.
    ///
    /// The group is spelled out so a zenohd whose `scouting/multicast/address`
    /// ever moved would fail the gate rather than silently never answering a
    /// Scout.
    ///
    /// R2230 (open-debt item 579) — MOVED here beside the listener line, and the
    /// text changed: 1.5.0 printed `"zenohd listening scout messages on {}"`
    /// and 1.10.0 prints `"Listening scout messages on {}"`
    /// (`orchestrator.rs:731` against `1.5.0:...:701`). ⚠ Unlike
    /// [`ZENOHD_LISTENER_LINE`], this one really IS a reword — same event, same
    /// level, different wording — which is why the two sit together: a reader
    /// who finds one stale should check the other, and the two failures need
    /// different repairs. Re-spelling is right here; it was wrong there.
    pub const ZENOHD_SCOUT_LINE: &str = "Listening scout messages on 224.0.0.224:7446";

    /// [`ZENOHD_LISTENER_LINE`] for a router asked to listen on EVERY interface.
    ///
    /// zenohd logs the address it was GIVEN, not the addresses that resolves to
    /// (measured: `-l tcp/0.0.0.0:0` prints `Listener added: tcp/0.0.0.0:44007`
    /// and then three `Zenoh can be reached at:` lines on real interfaces), so a
    /// caller reading the kernel's port back has to match the form it asked for.
    /// See `spawn_zenohd_multicast_scouting_on_any_interface` for why that
    /// spawn exists at all.
    pub const ZENOHD_ANY_LISTENER_LINE: &str = "Listener added: tcp/0.0.0.0:";

    /// Extract the port from zenohd's [`ZENOHD_LISTENER_LINE`] announcement
    /// (R311y411). Pure so it is unit-testable without a zenohd.
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

    /// The ONE line of a capture that carries `needle`.
    ///
    /// [`wait_for_substring`] hands back the WHOLE captured buffer — not the
    /// matching line, and not the tail from the needle onward. Measured in
    /// R311y472 while authoring the multilink leg: `captured.lines().next()`
    /// returned the child's startup banner and was then asserted against as if
    /// it were the awaited line, which reds a healthy run with a convincing but
    /// false diagnosis.
    pub fn line_with(captured: &str, needle: &str) -> Option<String> {
        captured
            .lines()
            .find(|line| line.contains(needle))
            .map(str::to_string)
    }

    /// One unicast session as ZENOH reports it in its `@/<zid>/router` adminspace
    /// answer: the peer's zid, its whatami, and how many PHYSICAL links zenoh has
    /// bound to that ONE transport.
    ///
    /// The link count is the whole point (R311y472): it is zenoh's own statement
    /// that it aggregated N links onto one session, which no amount of wz-side
    /// bookkeeping can reach.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ZenohSession {
        pub peer: String,
        pub whatami: String,
        pub links: usize,
    }

    /// Return the substring bracketed by `open`/`close` that STARTS at `from`
    /// (which must index the opening bracket), tracking nesting and string
    /// literals.
    ///
    /// A depth counter rather than a search for the first `close`, because a
    /// zenoh locator may legitimately contain one — `tcp/[::1]:7447` carries a
    /// `]` inside a JSON string, and a naive scan would cut the links array
    /// there and under-report.
    fn bracketed(s: &str, from: usize, open: u8, close: u8) -> Option<&str> {
        let bytes = s.as_bytes();
        if bytes.get(from) != Some(&open) {
            return None;
        }
        let mut depth = 0usize;
        let mut in_string = false;
        for (i, &b) in bytes.iter().enumerate().skip(from) {
            if in_string {
                if b == b'"' {
                    in_string = false;
                }
                continue;
            }
            match b {
                b'"' => in_string = true,
                _ if b == open => depth += 1,
                _ if b == close => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&s[from..=i]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Read the string value of `"<key>":"<value>"` out of a JSON object slice.
    fn string_field(obj: &str, key: &str) -> Option<String> {
        let marker = format!("\"{key}\":\"");
        let start = obj.find(&marker)? + marker.len();
        let end = obj[start..].find('"')? + start;
        Some(obj[start..end].to_string())
    }

    /// Parse zenoh's `@/<zid>/router` adminspace body into one entry per session.
    ///
    /// Deliberately STRUCTURAL rather than a substring count. The question is how
    /// many links sit under ONE session object, and a count of `"dst"` across the
    /// whole document answers a different one: it reads 2 for two SEPARATE
    /// single-link sessions, which is exactly the state a router that REFUSED the
    /// aggregation produces — i.e. exactly the confusion the multilink leg exists
    /// to rule out.
    ///
    /// Lives here rather than beside its caller because Layer C0's binary-dep
    /// discipline requires every `#[test]` in a `tests/` file that spawns
    /// binaries to be `#[ignore]`d, and a measuring instrument whose calibration
    /// never runs is not calibrated. In this crate's lib the units run in the
    /// ordinary Layer C1 workspace lane.
    pub fn parse_zenoh_admin_sessions(admin_body: &str) -> Vec<ZenohSession> {
        let marker = "\"sessions\":";
        let Some(idx) = admin_body.find(marker).map(|i| i + marker.len()) else {
            return Vec::new();
        };
        let Some(array) = bracketed(admin_body, idx, b'[', b']') else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut cursor = 1; // past the array's own '['
        while let Some(rel) = array[cursor..].find('{') {
            let start = cursor + rel;
            let Some(obj) = bracketed(array, start, b'{', b'}') else {
                break;
            };
            cursor = start + obj.len();
            let links = obj
                .find("\"links\":")
                .map(|i| i + "\"links\":".len())
                .and_then(|i| bracketed(obj, i, b'[', b']'))
                .map(|arr| arr.matches("\"dst\":").count())
                .unwrap_or(0);
            out.push(ZenohSession {
                peer: string_field(obj, "peer").unwrap_or_default(),
                whatami: string_field(obj, "whatami").unwrap_or_default(),
                links,
            });
        }
        out
    }

    /// The `RUST_LOG` filter the spawned `wz-ap-demo` children run with. `info` is the
    /// level every witness this crate asserts on is logged at, so it is the default —
    /// but a hardcoded level is also what blocks a diagnostic run: the topology
    /// witnesses report COUNTS (`peak 3 node(s)`), while the identity of a node and
    /// the locators it advertised are `debug` (`linkstate_forward`'s "discovered peer
    /// {zid} reachable at {locators}"). `WZ_TEST_DEMO_LOG` lets an investigation raise
    /// it without editing the harness.
    pub fn demo_log_filter() -> String {
        const FLOOR: &str = "wz_ap_demo=info";
        match std::env::var("WZ_TEST_DEMO_LOG") {
            Err(_) => "info".to_string(),
            // A bare level ("debug") already covers every module. A module-scoped
            // filter might not, and dropping `wz_ap_demo` removes the witnesses the
            // lanes assert on — a healthy run then fails with a convincing but FALSE
            // transport diagnosis. Append the floor so raising detail can only ADD.
            Ok(v) if v.contains("wz_ap_demo") || !v.contains('=') => v,
            Ok(v) => format!("{v},{FLOOR}"),
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
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        // R311y412 — REQUIRE a terminating non-digit, the same rule as the zenohd-side
        // `parse_announced_tcp_port`. A capture can be read mid-write, and a digit run
        // that ends at end-of-capture may be TRUNCATED (`337` for `33763`); the caller
        // would then probe a port nobody bound and blame the child. Panicking here
        // names the real condition instead.
        assert!(
            !digits.is_empty() && digits.len() < rest.len(),
            "unterminated port after '{marker}' — the capture was read mid-write, so \
             the digits may be truncated:\n{captured}"
        );
        digits
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
        // R311y412 — LIVENESS-aware, like the zenohd-side wait: a demo that dies at
        // startup (a bad flag, an unreadable cert) used to cost the full 10s and then
        // be misreported as "did not bind" — a corpse diagnosed as slow, with its exit
        // status never collected. Measured 10.03s -> 0.105s on an `exit 3` stand-in.
        let captured = wait_for_capture_alive(
            guard.child_mut(),
            &mut reader,
            Duration::from_secs(10),
            "binding its listen port",
            |c| c.contains(listen_marker).then(|| c.to_string()),
        )
        .unwrap_or_else(|e| {
            let _ = guard.child_mut().kill();
            let _ = guard.child_mut().wait();
            panic!("{label}: {e}");
        });
        let port = listen_port(&captured);
        (guard, reader, port)
    }

    /// A printable (alphanumeric) payload of `len` bytes for the fragmentation
    /// interop legs. It must be valid UTF-8 and free of shell/format specials
    /// because the pico CLIs print it via `printf("%.*s")` and the callers
    /// byte-match it in the child's stdout. The 62-char alphabet stepped by a
    /// coprime stride (7) has period 62, which is coprime to the 64-byte
    /// negotiated MTU those legs use — so a chunk-boundary reorder, duplicate
    /// or drop misaligns against the chunk grid instead of landing on a
    /// repeat, the way a short repeated pattern would. R311y439 narrowed this
    /// claim: the sequence is PERIODIC with period 62, not aperiodic, so a
    /// damage pattern that is an exact multiple of 62 long is invisible to it.
    /// What actually forbids that is the callers' pairing of full-value
    /// equality with an exact-LENGTH assertion — the stride only removes the
    /// short-period coincidences.
    ///
    /// R311y438 — lifted from `wz_fragment_tx_to_pico_zsub::frag_payload` into
    /// this SSOT when `wz_fragment_tx_zenohd_interop` became its second
    /// consumer, the same second-user trigger that lifted
    /// [`spawn_subscribed_zsub`] in R311y138. R311y439 added the third,
    /// `wz_fragment_rx_zenohd_interop`. All three depend on the SAME stride
    /// rationale, so a change for one must not silently leave the others on a
    /// weaker payload.
    pub fn frag_payload(len: usize) -> String {
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let bytes: Vec<u8> = (0..len)
            .map(|i| ALPHABET[(i * 7) % ALPHABET.len()])
            .collect();
        String::from_utf8(bytes).expect("alphanumeric is valid UTF-8")
    }

    /// The 5-bit transport-message-id field of a zenoh transport header
    /// (`wz-session-core/src/inbound.rs:236` — `header & 0x1F`). Both peers of
    /// every link this harness relays speak it: wz writes it through
    /// `wz_codecs::wire_const`, zenohd through `zenoh-protocol`'s `id` module
    /// (`commons/zenoh-protocol/src/transport/mod.rs:59-60` at zenoh 1.5.0,
    /// where `FRAME = 0x05` / `FRAGMENT = 0x06` match wz's constants exactly).
    const TRANSPORT_MID_MASK: u8 = 0x1F;

    /// R2200 (open-debt item 558) — the wire facts
    /// [`RelayFault::InterleaveConduitsAcceptorToDialer`] needs to tell one
    /// conduit from another, spelled here because this crate's LIB target does
    /// not depend on `wz-codecs` (only its tests do) and a lib-scope dependency
    /// added for three constants would reach `cargo doc` and every subset lane.
    ///
    /// Each is stated with BOTH implementations' authority, the same discipline
    /// [`TRANSPORT_MID_MASK`] is written with, and none of them is trusted on
    /// its own: the leg that uses this parser asserts that the priorities it
    /// reads MATCH the ones wz's own decoder reported for the same session, so
    /// a wrong constant here surfaces as a mismatch rather than as a silently
    /// wrong interleave.
    ///
    /// * `FRAGMENT` is `0x06` — `wz_codecs::wire_const::T_MID_FRAGMENT`, zenoh
    ///   `id::FRAGMENT` (`commons/zenoh-protocol/src/transport/mod.rs:59-60`).
    /// * `M` is `0x40`, "more fragments follow" —
    ///   `wz_codecs::wire_const::FLAG_T_FRAGMENT_M`.
    /// * `R` is `0x20`, "this fragment rides the RELIABLE channel" —
    ///   `wz_codecs::wire_const::FLAG_T_FRAGMENT_R`, and the bit wz's own
    ///   decoder reads into its chain key
    ///   (`wz-session-core/src/inbound.rs:670`).
    /// * `Z` is `0x80`, "an extension chain follows the body's fixed part" —
    ///   `wz_codecs::wire_const::FLAG_T_Z`.
    /// * the QoS extension is ext-id `0x1`, and the header packs
    ///   `id[0:3] | M[4] | enc[5:6] | Z[7]`
    ///   (`commons/zenoh-protocol/src/common/extension.rs:60-68`), so the id is
    ///   the low nibble. Its z64 body is a single `VLE(priority)`
    ///   (`wz-session-core/src/frame_encode.rs`, `write_qos_ext`).
    /// * `DEFAULT_PRIORITY` is `5` (`Priority::Data`), what a Frame or Fragment
    ///   carrying NO QoS ext means — zenoh omits the ext at the default, so
    ///   absence is a value and not a gap.
    const T_MID_FRAGMENT_LOCAL: u8 = 0x06;
    /// `FRAME` is `0x05` — `wz_codecs::wire_const::T_MID_FRAME`, zenoh
    /// `id::FRAME` (`commons/zenoh-protocol/src/transport/mod.rs:59-60` at
    /// zenoh 1.5.0). Spelled locally for the reason the block above gives, and
    /// trusted no more than those are: the leg reading it
    /// (`wz_negotiated_axes_zenohd_interop.rs`) cross-checks the SN this parser
    /// pulls off the wire against a value derived independently of the relay,
    /// so a wrong constant surfaces as a mismatch rather than as an empty list.
    const T_MID_FRAME_LOCAL: u8 = 0x05;
    const FLAG_FRAGMENT_MORE: u8 = 0x40;
    const FLAG_FRAGMENT_RELIABLE: u8 = 0x20;
    const FLAG_EXT_CHAIN: u8 = 0x80;
    const EXT_ID_MASK: u8 = 0x0F;
    const EXT_ID_QOS: u8 = 0x01;
    const DEFAULT_PRIORITY: u8 = 5;

    /// Which conduit a fragment rides, as the PAIR wz keys a reassembly chain
    /// on: `(reliable, priority)`
    /// (`wz-session-core/src/reassembly_dispatch.rs`, `ChainKey`).
    ///
    /// A pair rather than a priority because both halves are load-bearing and
    /// each is separately deniable. Two chains at the SAME priority and
    /// different reliabilities are two conduits; so are two at the same
    /// reliability and different priorities. A relay that read only the
    /// priority would report ONE conduit for the first pair and could then not
    /// tell an implementation that keys on both from one that drops the
    /// reliability bit — which is exactly the discrimination this parser exists
    /// to make possible.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    pub struct Conduit {
        /// The `ext_qos` priority, or the DEFAULT — 5, `Priority::Data`, the
        /// crate-private `DEFAULT_PRIORITY` — when the ext is absent.
        pub priority: u8,
        /// The header's `R` flag: the reliable channel, not the best-effort one.
        pub reliable: bool,
    }

    /// Read one base-128 VLE out of `bytes` at `at`, returning the value and
    /// the index just past it. `None` when the encoding runs off the end.
    fn read_vle(bytes: &[u8], mut at: usize) -> Option<(u64, usize)> {
        let mut value = 0u64;
        let mut shift = 0u32;
        while at < bytes.len() {
            let byte = bytes[at];
            at += 1;
            value |= u64::from(byte & 0x7F) << shift;
            if byte < 0x80 {
                return Some((value, at));
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        None
    }

    /// The [`Conduit`] of a batch whose FIRST transport message is a Fragment,
    /// or `None` when the batch does not open with one.
    ///
    /// The layout read here is `[header][VLE(sn)][ext chain][payload]`, and the
    /// QoS ext is FIRST in that chain when present because zenoh writes
    /// extensions in ascending id order and QoS is `0x1`
    /// (`wz-session-core/src/frame_encode.rs`, `write_qos_ext`'s doc). A header
    /// without the Z flag carries no chain at all, which means the DEFAULT
    /// priority rather than an unknown one. The reliability comes off the
    /// header byte itself and is therefore always readable, ext or no ext.
    ///
    /// Returns the DEFAULT priority rather than `None` for a fragment whose
    /// first extension is something else: `None` here means "not a fragment",
    /// and conflating the two would make a batch this parser did not understand
    /// look like a batch that was not a fragment — the quiet direction.
    pub fn fragment_conduit(batch: &[u8]) -> Option<Conduit> {
        let header = *batch.first()?;
        if header & TRANSPORT_MID_MASK != T_MID_FRAGMENT_LOCAL {
            return None;
        }
        let reliable = header & FLAG_FRAGMENT_RELIABLE != 0;
        let at_default = Conduit {
            priority: DEFAULT_PRIORITY,
            reliable,
        };
        if header & FLAG_EXT_CHAIN == 0 {
            return Some(at_default);
        }
        let (_sn, at) = read_vle(batch, 1)?;
        let ext_header = *batch.get(at)?;
        if ext_header & EXT_ID_MASK != EXT_ID_QOS {
            return Some(at_default);
        }
        let (priority, _) = read_vle(batch, at + 1)?;
        Some(Conduit {
            priority: priority as u8,
            reliable,
        })
    }

    /// Whether a fragment batch's header says more fragments follow.
    fn fragment_has_more(batch: &[u8]) -> bool {
        batch.first().is_some_and(|h| h & FLAG_FRAGMENT_MORE != 0)
    }

    /// A live [`spawn_counting_relay`] — the listening port a dialer aims at,
    /// plus the per-direction counters the relay accumulates.
    ///
    /// The two directions are named for the ROLES either side plays against the
    /// relay, not for wz and zenohd: the same relay serves a leg where wz is the
    /// dialer (R311y438, counting wz's own TX chain) and one where wz is the
    /// dialer but the counted chain flows the other way (R311y439, counting
    /// ZENOHD's TX chain). "Which direction is the foreign sender" is the
    /// caller's claim to make, so it is the caller that picks the accessor.
    pub struct CountingRelay {
        port: u16,
        dialer_to_acceptor: Arc<AtomicUsize>,
        acceptor_to_dialer: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
        held: Arc<AtomicUsize>,
        overtaken: Arc<AtomicUsize>,
        conduits: Arc<Mutex<BTreeSet<Conduit>>>,
        dialer_frame_sns: Arc<Mutex<Vec<u64>>>,
        recording: Recording,
        stalls: Arc<AtomicUsize>,
    }

    impl CountingRelay {
        /// The relay's own listening port. The dialer under test connects here
        /// instead of to the acceptor.
        pub fn port(&self) -> u16 {
            self.port
        }

        /// Counted batches flowing DIALER -> ACCEPTOR (for a wz dialer: wz's own
        /// transmit path).
        pub fn dialer_to_acceptor_count(&self) -> usize {
            self.dialer_to_acceptor.load(Ordering::Relaxed)
        }

        /// Counted batches flowing ACCEPTOR -> DIALER (for a wz dialer against a
        /// zenohd acceptor: the FOREIGN router's transmit path).
        pub fn acceptor_to_dialer_count(&self) -> usize {
            self.acceptor_to_dialer.load(Ordering::Relaxed)
        }

        /// Batches the [`RelayFault`] REMOVED from the stream. Zero under
        /// [`RelayFault::None`].
        ///
        /// A fault leg must assert on this. "The gap was recovered" is only a
        /// claim about recovery if a gap was actually induced; without this
        /// reading, a needle that never matched leaves the leg asserting an
        /// unbroken stream was unbroken, which passes for the wrong reason
        /// (the `== 0` calibration hazard `spawn_counting_relay` already
        /// guards for `counted_mid`).
        pub fn dropped_count(&self) -> usize {
            self.dropped.load(Ordering::Relaxed)
        }

        /// Fragment batches this relay HELD back under
        /// [`RelayFault::InterleaveConduitsAcceptorToDialer`]. Zero under every
        /// other fault.
        ///
        /// A leg must assert on this for the reason `dropped_count` gives for
        /// its own: an overlap that was never induced leaves the leg asserting
        /// that a sequential stream reassembles, which every implementation
        /// does, including the one the leg exists to refuse.
        pub fn held_count(&self) -> usize {
            self.held.load(Ordering::Relaxed)
        }

        /// Batches that OVERTOOK the held chain — a fragment on a different
        /// conduit forwarded while the first chain was still held back.
        ///
        /// This, not `held_count`, is what says the two chains actually
        /// OVERLAPPED: holding a chain and then releasing it with nothing in
        /// between is a delay, not an interleave, and it discriminates nothing.
        pub fn overtaken_count(&self) -> usize {
            self.overtaken.load(Ordering::Relaxed)
        }

        /// Every distinct [`Conduit`] this relay read off a FRAGMENT batch
        /// flowing acceptor -> dialer — the `(reliable, priority)` pair, not
        /// the priority alone, because that pair is what wz keys a chain on.
        ///
        /// The relay's own answer to "did the genuine side really split these
        /// across conduits", derived from the bytes by a parser that is not
        /// wz's. A leg cross-checks it against what wz's decoder reported: two
        /// independent readings of the same wire, and a leg whose only witness
        /// was wz's own decode would be asking wz whether wz was right.
        pub fn conduits_seen(&self) -> BTreeSet<Conduit> {
            self.conduits.lock().expect("relay conduit set").clone()
        }

        /// R2221 (open-debt item 568) — the sequence number of every `T_MID_FRAME`
        /// batch the DIALER put on the wire, in the order it put them there.
        ///
        /// # Why the wire and not the session
        ///
        /// `SessionLinkActions::negotiated_sn_mask()` answers what wz DECIDED the
        /// ring is. It cannot answer whether that decision reached the bytes, and
        /// those are two different claims — the second is the one a negotiated
        /// axis is FOR. This list is read by a parser that holds none of wz's
        /// session state: it takes the batch's first header, checks the 5-bit MID,
        /// and reads the VLE that follows it.
        ///
        /// # Why the DIALER direction only
        ///
        /// The dialer is wz in every leg built on this, and the claim is about
        /// what WZ emitted. The acceptor's own SNs live on the acceptor's ring
        /// and say nothing about whether wz adopted the negotiation.
        ///
        /// Fed on every pump whatever the [`RelayFault`] is, for the reason
        /// [`Self::conduits_seen`] gives for its own reading: what a peer put on
        /// the link is not a property of what this relay did to it.
        pub fn dialer_to_acceptor_frame_sns(&self) -> Vec<u64> {
            self.dialer_frame_sns
                .lock()
                .expect("relay frame sn list")
                .clone()
        }

        /// R2226 (open-debt item 575) — every batch this relay carried, in the
        /// order it READ them, tagged with which side wrote it and carrying the
        /// `[u16 LE len]` prefix.
        ///
        /// Suitable for [`crate::wire_tap::synthesise_pcap`], which is the
        /// point: a leg whose
        /// claim is "the FAR SIDE wrote these bytes" cannot make it from
        /// counters this crate maintains, and dissecting the recording puts a
        /// second, independent reader over the same wire.
        ///
        /// ⚠ READ order, not forwarded order, and the difference is the whole
        /// value under a fault. A recording taken after a hold would describe
        /// what the harness did with the bytes; this describes what the peer
        /// put on the link, which no relay behaviour changes.
        pub fn recording(&self) -> Vec<(Side, Vec<u8>)> {
            self.recording.lock().expect("relay recording").clone()
        }

        /// R2226 (open-debt item 575) — how many times
        /// [`RelayFault::StallAcceptorToDialerInsideAChain`] actually held.
        ///
        /// The anti-vacuity reading for that fault, and it is needed on BOTH
        /// arms of a pair built on it. A leg whose proof reds and whose twin
        /// greens could otherwise be reading "the fault worked" or "the fault
        /// never fired" — the second passes a `== 0` twin silently, which is
        /// the shape this crate's `counted_mid` assertion already exists to
        /// refuse one axis over.
        pub fn stalls(&self) -> usize {
            self.stalls.load(Ordering::Relaxed)
        }
    }

    /// What the relay does to the stream BESIDES forwarding and counting it.
    ///
    /// R311y443 — the counting relay converted "what crossed the wire" from an
    /// inference into a measurement. A fault does the converse: it makes the
    /// wire do something the peers cannot arrange between themselves, which is
    /// what a loss-recovery path needs before it can be witnessed at all. wz's
    /// advanced-pubsub retransmission only engages on a gap, and neither wz nor
    /// a foreign publisher will produce one on a healthy loopback TCP link.
    pub enum RelayFault {
        /// Forward every batch (the R311y438 / R311y439 behaviour).
        None,
        /// Drop the FIRST batch flowing ACCEPTOR -> DIALER whose bytes contain
        /// `needle`, then forward everything else verbatim.
        ///
        /// ## Why by CONTENT rather than by position
        ///
        /// The obvious fault is "drop the Nth batch carrying application data",
        /// and it cannot be written: there is no transport MID for a data push.
        /// Application messages ride INSIDE a `T_MID_FRAME` (`wz-codecs/src/
        /// lib.rs:496`), together with every Declare, Request and Response, so
        /// an Nth-frame rule drops whichever of those happened to be Nth —
        /// a different message on every run, and usually not a sample at all.
        ///
        /// Matching the payload instead makes the fault DETERMINISTIC and, more
        /// importantly, NAMED: the caller knows exactly which sample it removed,
        /// so both the recovery assertion ("that one came back") and its
        /// control twin ("that one is missing, and the miss count is 1") can be
        /// exact rather than statistical. It costs the caller one obligation —
        /// the needle must be unique to the batch it means, which for a burst
        /// payload like `[   8] GAPVAL` it is.
        ///
        /// FIRST match only, deliberately: the retransmitted copy carries the
        /// same bytes, so a drop-every-match rule would swallow the recovery
        /// reply too and no amount of retrying could ever succeed.
        DropFirstAcceptorToDialer {
            /// The byte sequence identifying the batch to remove.
            needle: Vec<u8>,
        },
        /// HOLD one whole fragment chain flowing ACCEPTOR -> DIALER until a
        /// fragment on a DIFFERENT [`Conduit`] has overtaken it, then release it
        /// in order.
        ///
        /// The chain held is the first to START once the direction has carried
        /// TWO conduits — not the first chain outright. The crate-private
        /// `interleave_step` carries the measurement that forced the
        /// distinction.
        ///
        /// ## Why the wire has to be made to do this
        ///
        /// A genuine router does NOT interleave two chains of its own accord.
        /// [`spawn_counting_relay`]'s own docs already record why — it flushes
        /// before it fragments and holds one mutex for the whole chain — and
        /// R2200 measured the consequence directly: two publishers at priority
        /// 1 and priority 6, both fragmenting to a 64-byte MTU on ONE link,
        /// arrive as `1 1 1 1 1 | 6 6 6 6 6 | 1 1 1 1 1 | ...`, strictly
        /// sequential.
        ///
        /// Sequential chains do not test what a per-channel reassembler is
        /// FOR. An implementation that keyed its reassembly on the peer alone,
        /// ignoring the conduit entirely, reassembles that stream correctly:
        /// each chain opens, completes and closes before the next begins. Only
        /// an OVERLAP separates the two implementations, and since neither peer
        /// will produce one, the transport in between has to.
        ///
        /// ## Why this is a legal thing for a wire to do
        ///
        /// Reordering ACROSS conduits is not a protocol violation — it is what
        /// a conduit IS. Each carries its own sequence-number space, and a
        /// receiver that could not tolerate one conduit's message arriving
        /// between two of another's would not survive any real network. Within
        /// one conduit this fault preserves order exactly: it holds a WHOLE
        /// chain and re-emits it in the order it arrived.
        ///
        /// That is also why it reads the [`Conduit`] rather than counting
        /// batches. A positional rule ("hold the Nth") cannot tell one conduit
        /// from another, so it would reorder WITHIN a chain, which IS a
        /// violation, and wz would reject it — a red that says nothing about
        /// reassembly. It reads BOTH halves for the same reason: two chains at
        /// one priority and different reliabilities are two conduits, and a
        /// rule that saw only the priority would call them one and reorder
        /// within.
        InterleaveConduitsAcceptorToDialer,
        /// R2226 (open-debt item 575) — STOP READING the acceptor -> dialer
        /// direction for `hold`, once a fragment chain has STARTED on it, then
        /// resume and forward everything in order.
        ///
        /// ## What this is for, and why nothing weaker reaches it
        ///
        /// `fragment_chains.aborted_sender_dropped` counts a sender that
        /// abandoned a chain mid-flight — the `0x3 Drop` marker. The only
        /// implementation that emits it in production is zenoh (Rust): wz's
        /// encoder has no production caller and zenoh-pico's single call site
        /// passes `false`. So the marker can only ever be witnessed by making a
        /// GENUINE zenoh abandon a chain, and this is the fault that makes it.
        ///
        /// Upstream emits it from ONE place, `zgetbatch_rets!`'s restore arm
        /// (`io/zenoh-transport/src/common/pipeline.rs:395-407` at zenoh 1.5.0),
        /// and reaching it needs THREE things at once:
        ///
        ///   1. the pipeline runs out of batches mid-fragmentation
        ///      (`s_ref.pull()` yields `None`), which is what STOPPING THE
        ///      READ produces: the far side's socket fills, its link task
        ///      blocks on `write`, and batches stop returning to the refill
        ///      queue;
        ///   2. the message is DROPPABLE — the deadline arm is taken only for
        ///      `msg.is_droppable()` (`pipeline.rs:823`), which is
        ///      `!is_reliable() || congestion_control == Drop`
        ///      (`commons/zenoh-protocol/src/network/mod.rs:162`). A Block
        ///      message takes the `wait_before_close` arm instead and the
        ///      session is TORN DOWN rather than marked;
        ///   3. ⚠ AT LEAST ONE FRAGMENT ALREADY EMITTED. The marker sits in the
        ///      `else` of `if fragment.ext_first.is_some()`: on the FIRST
        ///      fragment upstream merely resets the sequence number and emits
        ///      NOTHING. That is why this fault waits for a chain to start
        ///      before stalling, and it is also why a leg must assert
        ///      `begun > 0` before reading the drop counter — the two are the
        ///      same fact.
        ///
        /// ## Why the hold is on the READ and why that is legal
        ///
        /// A relay that stopped WRITING would still drain its upstream socket,
        /// so the far side would never block and never exhaust. Stopping the
        /// READ is what propagates back-pressure, which is the ordinary
        /// behaviour of a slow consumer — a receiver that stops reading for a
        /// moment is not violating anything, and a sender's reaction to it is
        /// exactly the production path under witness. NOTHING IS DROPPED,
        /// REORDERED OR REWRITTEN: every byte the far side wrote is forwarded,
        /// in order, after the hold.
        ///
        /// ## Aimed INSIDE the chain, not at a position
        ///
        /// The trigger is "the first batch whose first transport message is a
        /// `T_MID_FRAGMENT`", read by [`fragment_conduit`], not "the Nth
        /// batch". A positional rule would stall during the handshake or
        /// between chains, where no chain is in flight and upstream has nothing
        /// to abandon.
        StallAcceptorToDialerInsideAChain {
            /// How long to stop reading. Must exceed the sender's own
            /// `max_wait_before_drop_fragments` budget, which upstream defaults
            /// to 50000 µs (`DEFAULT_CONFIG.json5:626-632`), or the deadline
            /// never expires and the chain completes late instead of being
            /// abandoned.
            hold: Duration,
        },
    }

    /// Bind a TCP relay that a dialer under test connects to in place of
    /// `upstream_port`. It forwards both directions VERBATIM and counts, per
    /// direction, the streamed-link batches whose FIRST transport message
    /// carries `counted_mid`.
    ///
    /// ## Why a relay at all
    ///
    /// A cross-impl leg with a foreign peer on one end cannot normally observe
    /// what actually crossed the wire — it can only assert what arrived, and
    /// attribute the shape of the transmission "by construction". The relay
    /// converts that inference into a measurement, on either side, for about
    /// sixty lines. R311y438 introduced it for wz's own TX chain; R311y439
    /// pointed it at zenohd's.
    ///
    /// ## The envelope
    ///
    /// Both peers frame a streamed link as `[u16 LE len][batch]` — wz at
    /// `wz-runtime-tokio/src/stream_link.rs:161-169`, zenoh at
    /// `io/zenoh-transport/src/common/batch.rs:318` with `BatchSize = u16`
    /// (`commons/zenoh-protocol/src/transport/mod.rs:41`) and `L_LEN = 2`
    /// (`batch.rs:34`), both little-endian. Two shapes this parse would NOT
    /// survive, neither of which a fragmentation leg negotiates: the 4-byte
    /// lowlatency prefix (`stream_link.rs:154-160`), and the extra
    /// `BatchHeader` byte zenoh prepends under compression only
    /// (`batch.rs:101-110`, `H_LEN = BatchHeader::SIZE`) — which would shift
    /// the byte this counter reads as a transport header.
    ///
    /// ## What the count is, exactly
    ///
    /// It is the number of batches whose FIRST transport message carries
    /// `counted_mid` — NOT the number of such messages. For a fragment chain
    /// from either peer the two coincide, and neither coincidence is luck:
    ///
    ///   * wz hands the link exactly one encoded transport message per
    ///     `send_blocking` call (`stream_link.rs:142-173`).
    ///   * zenoh FLUSHES any partially-filled batch before it fragments — an
    ///     in-flight batch is moved out and a fresh one pulled
    ///     (`io/zenoh-transport/src/common/pipeline.rs:359-363`), the retry is
    ///     on what its own comment calls a "fully empty batch" (`:365`), and it
    ///     is that empty batch which `:373` reinserts for fragment #1. Every
    ///     later fragment is `move_batch`'d the moment it is encoded (`:416`),
    ///     so no other message joins it either. The whole path holds one mutex
    ///     (`:281`), so nothing interleaves.
    ///
    /// R311y439 measured this: 5 counted batches against 5
    /// `DriverLoopOutcome::Fragment` events wz's own parser reported for the
    /// same chain. An earlier draft of this doc hedged that the first fragment
    /// could share a batch and be UNDERCOUNTED; `pipeline.rs:359-365` refutes
    /// it, four lines above the range that draft cited.
    ///
    /// ## Preconditions the caller owns
    ///
    /// Two of these the relay cannot check, so they are stated rather than
    /// enforced — a caller that breaks one gets a HANG or a silently wrong
    /// count, not an error:
    ///
    ///   * ONE dial. The relay accepts exactly once; a second connection sits
    ///     unserved in the backlog. A redial leg needs an accept loop first.
    ///   * NOT a lowlatency link. That framing is a 4-byte prefix
    ///     (`stream_link.rs:154-160`), chosen at RUNTIME by an `AtomicBool`, so
    ///     no compile-time gate rules it out — and Layer Z already runs
    ///     lowlatency legs beside the fragmentation ones. Forwarding would stay
    ///     byte-exact (bytes are re-emitted in order), but the counts become
    ///     noise and a misparsed length stalls `read_exact`.
    ///
    /// The third — `counted_mid` must be a bare 5-bit MID, not a whole header
    /// byte — IS enforced below, because getting it wrong reads as zero
    /// forever, which reds a `>= N` arm loudly but passes a `== 0` calibration
    /// twin SILENTLY, disarming the one assertion whose entire job is to prove
    /// the counter discriminates.
    ///
    /// Blocking std sockets on their own threads, deliberately: this module is
    /// the harness SSOT for tests that are not all async, and it has no
    /// dev-dependencies available to it (tokio is one).
    pub fn spawn_counting_relay(
        upstream_port: u16,
        counted_mid: u8,
        fault: RelayFault,
    ) -> CountingRelay {
        assert_eq!(
            counted_mid & !TRANSPORT_MID_MASK,
            0,
            "counted_mid must be a bare 5-bit transport MID (e.g. T_MID_FRAGMENT 0x06), \
             not a header byte with its Z/M/R flags set — a flagged value never matches \
             and would leave a `== 0` calibration arm passing vacuously"
        );
        let interleave = matches!(fault, RelayFault::InterleaveConduitsAcceptorToDialer);
        // R2226 — the hold is NOT range-checked here, and that is deliberate.
        // Whether it outlasts upstream's own `max_wait_before_drop_fragments`
        // is the very thing a leg varies between its proof and its calibration
        // twin, so a helper that refused the short one would forbid the
        // control. The relation belongs where both numbers sit together; see
        // `UPSTREAM_DROP_FRAGMENT_BUDGET` in
        // `tests/wz_chain_drop_zenohd_interop.rs`.
        let stall = match &fault {
            RelayFault::StallAcceptorToDialerInsideAChain { hold } => Some(*hold),
            _ => None,
        };
        let needle = match fault {
            RelayFault::None
            | RelayFault::InterleaveConduitsAcceptorToDialer
            | RelayFault::StallAcceptorToDialerInsideAChain { .. } => None,
            RelayFault::DropFirstAcceptorToDialer { needle } => {
                assert!(
                    !needle.is_empty(),
                    "an empty needle is contained in every batch, so the fault would \
                     remove the first batch of the session — the handshake — rather \
                     than the message the caller meant"
                );
                Some(needle)
            }
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind counting relay");
        let port = listener.local_addr().expect("relay local_addr").port();
        let dialer_to_acceptor = Arc::new(AtomicUsize::new(0));
        let acceptor_to_dialer = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicUsize::new(0));
        let overtaken = Arc::new(AtomicUsize::new(0));
        let conduits = Arc::new(Mutex::new(BTreeSet::new()));
        let dialer_frame_sns = Arc::new(Mutex::new(Vec::new()));
        // R2226 — recorded on BOTH directions and under EVERY fault. A leg that
        // rebuilds the wire as a pcap needs the handshake as well as the data,
        // and the calibration twin needs a recording of exactly the same shape
        // as the proof or the two dissections are not comparable.
        let recording: Recording = Arc::new(Mutex::new(Vec::new()));
        let down_recording = Arc::clone(&recording);
        let up_recording = Arc::clone(&recording);
        let stalls = Arc::new(AtomicUsize::new(0));
        let down_stalls = Arc::clone(&stalls);
        let up = Arc::clone(&dialer_to_acceptor);
        let down = Arc::clone(&acceptor_to_dialer);
        let down_dropped = Arc::clone(&dropped);
        let down_interleave = interleave.then(|| InterleaveSinks {
            held: Arc::clone(&held),
            overtaken: Arc::clone(&overtaken),
        });
        // The conduit OBSERVATION is deliberately not part of the fault. It
        // rides every acceptor -> dialer pump whatever `fault` is, because
        // `conduits_seen()` answers "what did the far side put on this link",
        // which no relay behaviour changes. R2200's first draft fed it from
        // inside the interleave and the calibration twin could then never
        // report a conduit at all -- an instrument that only exists on the arm
        // it is meant to discriminate FROM.
        let down_conduits = Arc::clone(&conduits);
        let up_frame_sns = Arc::clone(&dialer_frame_sns);

        thread::spawn(move || {
            // An accept that never comes means the test finished without
            // dialing — the only silent return here, and a legitimate one.
            let Ok((dialer_side, _peer)) = listener.accept() else {
                return;
            };
            // Everything past this point is LOUD. A relay that dies quietly
            // reads downstream as "no fragments crossed the wire", which points
            // the investigation at the fragmenter instead of at the harness —
            // the failure mode every sibling spawn helper in this module
            // deliberately panics to avoid.
            let acceptor_side = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream_port))
                .expect("counting relay dials its upstream");
            // R2226 (open-debt item 575) — BOUND THE KERNEL'S OWN BUFFER when a
            // stall fault is configured.
            //
            // The stall works by back-pressure: the far side must run out of
            // room and block in `write`. Between it and this relay stand two
            // kernel buffers, and loopback ones auto-tune into the megabytes —
            // so without this the sender writes for far longer than any
            // reasonable hold, and the fault reads as inert. Bounding the
            // RECEIVE side is the half this process owns; the send side is
            // `so_sndbuf` on the router (see
            // `spawn_zenohd_shallow_tx_queue_on_ephemeral_tcp`).
            //
            // ⚠ Applied to EVERY stall-faulted relay, including one whose hold
            // is short. A calibration twin that differed from its proof in the
            // buffer size as well as the hold would vary two inputs, and the
            // leg could not attribute the difference to either.
            if stall.is_some() {
                bound_recv_buffer(&acceptor_side, STALL_RECV_BUFFER_BYTES);
            }
            let dialer_tx = dialer_side
                .try_clone()
                .expect("dup relay dialer-side handle");
            let acceptor_tx = acceptor_side
                .try_clone()
                .expect("dup relay acceptor-side handle");

            // The fault rides the ACCEPTOR -> DIALER pump only: the dialer under
            // test is the receiver whose recovery path a leg wants to exercise,
            // so the loss has to happen on what reaches it.
            thread::spawn(move || {
                pump_counting(
                    acceptor_side,
                    dialer_tx,
                    &down,
                    counted_mid,
                    PumpTaps {
                        needle: needle.as_deref(),
                        dropped: &down_dropped,
                        interleave: down_interleave.as_ref(),
                        conduits: Some(&down_conduits),
                        frame_sns: None,
                        stall: stall.map(|hold| (hold, &*down_stalls)),
                        recording: Some((&down_recording, Side::FromListener)),
                    },
                )
            });
            pump_counting(
                dialer_side,
                acceptor_tx,
                &up,
                counted_mid,
                PumpTaps {
                    recording: Some((&up_recording, Side::FromDialer)),
                    ..PumpTaps::faultless(&AtomicUsize::new(0), &up_frame_sns)
                },
            );
        });

        CountingRelay {
            port,
            dialer_to_acceptor,
            acceptor_to_dialer,
            dropped,
            held,
            overtaken,
            conduits,
            dialer_frame_sns,
            recording,
            stalls,
        }
    }

    /// Everything one direction of a relay does BESIDES forwarding and counting,
    /// and everywhere it reports.
    ///
    /// Grouped rather than passed as four more parameters because they are one
    /// thing — the taps on this direction — and because the DIALER -> ACCEPTOR
    /// direction takes none of them: `PumpTaps::inert(&counter)` says that at
    /// the call site, where four bare `None`s said only that four arguments
    /// existed. Faults ride the acceptor -> dialer pump alone (the dialer under
    /// test is the receiver whose recovery path a leg exercises), so this
    /// asymmetry is the normal case rather than a special one.
    struct PumpTaps<'a> {
        /// FIRST-match-only drop rule. `None` leaves the stream intact.
        needle: Option<&'a [u8]>,
        /// Where a dropped batch is counted. Only the needle rule writes it, so
        /// an inert direction can share one throwaway counter.
        dropped: &'a AtomicUsize,
        /// The interleave fault's counters. `None` under every other fault.
        interleave: Option<&'a InterleaveSinks>,
        /// Where every conduit a fragment rode is recorded — independent of
        /// `interleave`, because what the far side PUT on the link is not a
        /// property of what this relay did to it.
        conduits: Option<&'a Mutex<BTreeSet<Conduit>>>,
        /// Where the SN of every `T_MID_FRAME` batch on this direction is
        /// recorded, on the same terms as `conduits`. `None` leaves the reading
        /// off the direction entirely — see
        /// [`CountingRelay::dialer_to_acceptor_frame_sns`].
        frame_sns: Option<&'a Mutex<Vec<u64>>>,
        /// R2226 (open-debt item 575) — how long to STOP READING once a chain
        /// has started on this direction, and where the hold is COUNTED.
        /// `None` under every other fault.
        ///
        /// See [`RelayFault::StallAcceptorToDialerInsideAChain`] for why the
        /// stall is what makes a genuine sender abandon a chain, and why it is
        /// applied to the READ side rather than to the write.
        stall: Option<(Duration, &'a AtomicUsize)>,
        /// R2226 — where every batch this direction carried is recorded,
        /// verbatim and length prefix included, so a leg can rebuild the wire
        /// as a pcap and dissect it.
        ///
        /// Fed on the same terms as `conduits` and `frame_sns`: before any
        /// hold, outside the fault, and from the bytes rather than from either
        /// peer's state. A recording taken after the fault would be a record of
        /// what the harness did, and the claim this exists to support is about
        /// what the FAR SIDE wrote.
        recording: Option<(&'a Recording, Side)>,
    }

    impl<'a> PumpTaps<'a> {
        /// A direction that applies no FAULT: it forwards, counts, and records
        /// the frame sequence numbers it saw. `dropped` is still taken because
        /// the needle rule is what writes it and there is no needle here; a
        /// caller supplies a throwaway.
        ///
        /// Named for what it does NOT do rather than `inert`, which it was
        /// called while it also observed nothing. An observation is not a
        /// fault, and the two must stay separable — a reading available only on
        /// the arm it is meant to discriminate FROM is the instrument R2200
        /// had to move out of the interleave.
        fn faultless(dropped: &'a AtomicUsize, frame_sns: &'a Mutex<Vec<u64>>) -> Self {
            Self {
                needle: None,
                dropped,
                interleave: None,
                conduits: None,
                frame_sns: Some(frame_sns),
                stall: None,
                recording: None,
            }
        }
    }

    /// Where [`RelayFault::InterleaveConduitsAcceptorToDialer`] reports what it
    /// DID. Grouped rather than passed as two more arguments because they are
    /// one fact — what the interleave did to the ordering — and a pump given
    /// one of them and not the other could not answer for it.
    ///
    /// What the relay merely SAW is not here: `conduits_seen()` is fed by the
    /// pump regardless of fault, so the calibration twin can report the same
    /// conduits as the proof.
    struct InterleaveSinks {
        held: Arc<AtomicUsize>,
        overtaken: Arc<AtomicUsize>,
    }

    /// The interleave's own state, for one direction of one relay.
    #[derive(Default)]
    struct InterleaveState {
        /// The held chain's batches, in arrival order.
        held: Vec<(Vec<u8>, Vec<u8>)>,
        /// The conduit the held chain rides.
        conduit: Option<Conduit>,
        /// The held chain has seen its terminating fragment.
        closed: bool,
        /// Released; everything forwards verbatim from here on.
        done: bool,
        /// Batches seen since the hold began — the deadlock bound.
        since_hold: usize,
        /// Distinct conduits a fragment has ridden on this direction.
        ///
        /// The hold does not arm until there are TWO. R2200 measured why: the
        /// two genuine publishers come up SEQUENTIALLY (each spawn blocks until
        /// its child says it is publishing), so the first seconds of the link
        /// carry one conduit only. A hold armed there waits for an overtake
        /// that does not exist yet, hits the same-conduit release on the next
        /// chain, and retires having never interleaved — `overtaken == 0`, on a
        /// link where both conduits went on to appear.
        seen: BTreeSet<Conduit>,
        /// Conduits with a chain currently OPEN — a fragment said "more
        /// follows" and its terminator has not arrived.
        ///
        /// The hold arms at a chain START and never mid-chain: holding a chain's
        /// tail while its head has already gone past splits one chain across the
        /// release, which is a WITHIN-conduit reorder.
        open: BTreeSet<Conduit>,
    }

    /// How many batches may pass with the chain held before it is released
    /// unconditionally. A conduit that never appears would otherwise strand the
    /// held chain and hang the leg on a timeout, which reads as a wz defect;
    /// releasing instead leaves `overtaken_count()` at zero, which is a leg
    /// FAILURE with the right subject.
    const INTERLEAVE_BATCH_BOUND: usize = 256;

    /// Forward every `[u16 LE len][batch]` from `src` to `dst` byte-for-byte,
    /// bumping `counter` for each batch whose first transport message carries
    /// `counted_mid`. Returns when either side closes or errors.
    ///
    /// With `needle` set, the FIRST batch containing it is removed instead of
    /// forwarded and `dropped` is bumped once (see
    /// [`RelayFault::DropFirstAcceptorToDialer`]). A removed batch is NOT
    /// counted: the counters answer "what crossed", and a batch this pump
    /// swallowed did not. Under [`RelayFault::None`] nothing is removed, so
    /// both existing consumers read exactly the counts they did before.
    ///
    /// Removing a whole batch leaves both peers' TRANSPORT state healthy,
    /// which is why the fault can be this blunt — but the reason is that BOTH
    /// SIDES APPLY THE SAME HALF-WINDOW RULE, not that either side ignores
    /// sequence numbers. R311y443 first wrote it the second way and was wrong
    /// (R311y443-review, REVIEWER 1):
    ///
    ///   * a zenoh receiver runs every Frame / Fragment through `SeqNum::roll`
    ///     (`io/zenoh-transport/src/common/seq_num.rs:145-155`, called from
    ///     `unicast/universal/rx.rs:199-218`), which advances on ANY forward gap
    ///     inside the half-ring and rejects only a non-advancing SN. The lost
    ///     frame is a `trace` line and is never retransmitted — `gap()` beside
    ///     `roll` is still `#[cfg(test)]`, "once reliability is implemented".
    ///   * WZ GATES ITS UNICAST RX TOO, on the same predicate: `drive.rs:418`
    ///     (Frame) and `:481` (Fragment) call `admit_rx_frame_sn`
    ///     (`wz-session-core/src/session_actions.rs:2728`), which reaches
    ///     `RxSn::admit` -> `sn::precedes` (`wz-session-core/src/sn.rs:51-54`,
    ///     `:163-176`) — whose own doc calls it the per-channel UNICAST RX gate,
    ///     seeded from the OpenSyn/OpenAck `initial_sn`. `precedes` is
    ///     `distance != 0 && distance <= half(mask)`, i.e. `roll`'s rule, so a
    ///     forward gap is admitted and becomes the new baseline here as well.
    ///
    /// So the loss surfaces where the leg wants it — as a missing SAMPLE in the
    /// application's own sequencing — rather than as a dead session.
    ///
    /// TWO LIMITS ON THAT, both of which a future caller owns. Neither bites the
    /// R311y443 legs (an ~11-byte payload at 1 Hz from a single publisher), and
    /// both would be silent if they did:
    ///
    ///   * a batch inside a FRAGMENT chain is NOT one lost sample. It passes the
    ///     SN gate and then aborts the chain in the `ReassemblyDispatcher`
    ///     (`sn::consecutive`; `drive.rs:472-480` documents the two-stage check
    ///     in terms), so the WHOLE message is lost. A needle must name a payload
    ///     small enough not to fragment, or the leg must expect message loss.
    ///   * a batch may carry MORE than the message the needle named. Nothing
    ///     here stops a sender co-batching a Declare or a Response Final with
    ///     the matched sample, and removing those is a different failure mode
    ///     than the documented one.
    ///
    /// The counter is bumped BEFORE the forward, so any batch that reached the
    /// far side is already in the counter's modification order by the time the
    /// far side can act on it. That is what makes `Relaxed` sound here: a
    /// caller that observed a delivery cannot then read a count that excludes
    /// the chain which produced it.
    ///
    /// On exit it shuts the relayed halves down explicitly. `try_clone`
    /// duplicates the descriptor rather than the socket, so dropping one handle
    /// sends no FIN — without this, one side closing would leave the opposite
    /// pump blocked in `read_exact` and the far peer believing the connection
    /// is live. Today both consumers kill their zenohd immediately afterwards,
    /// which hides it; a leg that reuses a router, or one that needs the router
    /// to OBSERVE the disconnect, would hang.
    fn pump_counting(
        mut src: TcpStream,
        mut dst: TcpStream,
        counter: &AtomicUsize,
        counted_mid: u8,
        taps: PumpTaps<'_>,
    ) {
        let PumpTaps {
            needle,
            dropped,
            interleave,
            conduits,
            frame_sns,
            stall,
            recording,
        } = taps;
        use std::io::{Read, Write};
        use std::net::Shutdown;

        let mut prefix = [0u8; 2];
        let mut state = InterleaveState::default();
        let mut stalled = false;
        loop {
            if src.read_exact(&mut prefix).is_err() {
                break;
            }
            let mut batch = vec![0u8; u16::from_le_bytes(prefix) as usize];
            if src.read_exact(&mut batch).is_err() {
                break;
            }
            // R2226 — the RECORDING, first of the taps and before every rule
            // below, so what lands in it is what the far side wrote rather than
            // what this relay decided to do about it. Both the prefix and the
            // batch, because a pcap of one without the other does not parse.
            if let Some((recording, side)) = recording {
                let mut segment = Vec::with_capacity(2 + batch.len());
                segment.extend_from_slice(&prefix);
                segment.extend_from_slice(&batch);
                recording
                    .lock()
                    .expect("relay recording")
                    .push((side, segment));
            }
            // FIRST match only — the retransmitted copy carries the same bytes,
            // so a rule that kept matching would swallow the recovery reply and
            // make the induced loss unrecoverable by construction.
            if let Some(needle) = needle.filter(|_| dropped.load(Ordering::Relaxed) == 0) {
                if batch.windows(needle.len()).any(|w| w == needle) {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            if batch
                .first()
                .is_some_and(|header| header & TRANSPORT_MID_MASK == counted_mid)
            {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            // The COUNT above is taken before any hold, and deliberately: it
            // answers "what the far side put on the wire", which a relay that
            // delays a batch has not changed. Only the ORDER is this fault's
            // business.
            //
            // The conduit reading is taken on the same terms and in the same
            // place, so it is a property of the LINK rather than of the fault:
            // outside `state.done`, outside the `interleave` option, and before
            // any batch can be held back.
            if let Some(conduits) = conduits {
                if let Some(conduit) = fragment_conduit(&batch) {
                    conduits.lock().expect("relay conduit set").insert(conduit);
                }
            }
            // R2221 — the frame SN reading, on the same terms and in the same
            // place as the conduit reading above: before any hold, outside the
            // fault, and derived from the bytes rather than from either peer's
            // state. The layout is `[header][VLE(sn)]…`, the same prefix
            // `fragment_conduit` walks.
            if let Some(frame_sns) = frame_sns {
                if batch
                    .first()
                    .is_some_and(|header| header & TRANSPORT_MID_MASK == T_MID_FRAME_LOCAL)
                {
                    if let Some((sn, _)) = read_vle(&batch, 1) {
                        frame_sns.lock().expect("relay frame sn list").push(sn);
                    }
                }
            }
            // R2226 (open-debt item 575) — THE STALL, applied once, after a
            // chain has demonstrably started on this direction.
            //
            // Placed after every observation above and before the forward: the
            // batch that TRIGGERS the stall is itself recorded, counted and
            // forwarded normally, so the fault removes nothing. Sleeping here
            // means this thread also stops calling `read_exact`, which is the
            // mechanism — see the variant's docs for why back-pressure and not
            // a write-side delay is what makes a genuine sender abandon.
            if let Some((hold, stalls)) = stall.filter(|_| !stalled) {
                if fragment_conduit(&batch).is_some() {
                    stalled = true;
                    stalls.fetch_add(1, Ordering::Relaxed);
                    thread::sleep(hold);
                }
            }
            if let Some(sinks) = interleave.filter(|_| !state.done) {
                match interleave_step(&mut state, sinks, &prefix, &batch) {
                    // Held: nothing goes out for this batch.
                    Step::Hold => continue,
                    Step::Forward => {}
                    // The overtake: the OTHER conduit's batch goes out ahead of
                    // the chain still waiting behind it.
                    Step::ForwardThenRelease => {
                        if dst.write_all(&prefix).is_err() || dst.write_all(&batch).is_err() {
                            break;
                        }
                        if release_held(&mut dst, &mut state).is_err() {
                            break;
                        }
                        continue;
                    }
                    // Retirement WITHOUT an overtake: the held chain goes out
                    // FIRST and this batch follows it. Emitting them the other
                    // way round is what the fault must never do -- both cases
                    // that reach here are same-conduit or bound-driven, where
                    // going first would reorder within one conduit.
                    Step::ReleaseThenForward => {
                        if release_held(&mut dst, &mut state).is_err() {
                            break;
                        }
                    }
                }
            }
            if dst.write_all(&prefix).is_err() || dst.write_all(&batch).is_err() {
                break;
            }
        }
        // A held chain must not die with the pump: the dialer would see a
        // truncated chain and report a reassembly failure that the RELAY
        // caused. Flushing on the way out keeps every red this leg can produce
        // attributable to wz.
        if interleave.is_some() && !state.held.is_empty() {
            use std::io::Write;
            for (p, b) in std::mem::take(&mut state.held) {
                if dst.write_all(&p).is_err() || dst.write_all(&b).is_err() {
                    break;
                }
            }
        }
        let _ = src.shutdown(Shutdown::Read);
        let _ = dst.shutdown(Shutdown::Write);
    }

    /// What [`interleave_step`] decided for one batch.
    enum Step {
        /// Buffered; emit nothing now.
        Hold,
        /// Emit this batch normally.
        Forward,
        /// Emit this batch, then the whole held chain behind it. The OVERTAKE,
        /// and the only step that reorders anything.
        ForwardThenRelease,
        /// Emit the whole held chain, then this batch behind it. Retirement in
        /// arrival order, reordering nothing.
        ReleaseThenForward,
    }

    /// Write the held chain out in arrival order and retire the interleave.
    ///
    /// Shared by both release steps so "the held chain leaves in the order it
    /// arrived" is written once: the two steps differ in where THIS batch goes
    /// relative to the chain, never in the chain's own order.
    fn release_held(
        dst: &mut TcpStream,
        state: &mut InterleaveState,
    ) -> Result<(), std::io::Error> {
        use std::io::Write;
        let released = std::mem::take(&mut state.held);
        state.done = true;
        for (p, b) in released {
            dst.write_all(&p)?;
            dst.write_all(&b)?;
        }
        Ok(())
    }

    /// Advance the interleave for one batch.
    ///
    /// The rule, stated once: once TWO conduits are known to ride this link,
    /// hold the next WHOLE fragment chain that starts; forward anything that is
    /// not on its conduit; the first fragment that IS on another conduit goes
    /// out first and the held chain follows it.
    ///
    /// ## Why the hold waits for the second conduit
    ///
    /// Because arming earlier retires the fault before it can fire. The two
    /// genuine publishers come up one after the other, so the link's first
    /// seconds carry ONE conduit; a hold armed there has nothing to be
    /// overtaken by, meets the same-conduit release on the very next chain, and
    /// retires with `overtaken == 0` on a link where the second conduit does
    /// arrive a moment later. MEASURED, R2200: the first draft armed on the
    /// first fragment and both arms of the leg failed on exactly that.
    ///
    /// Waiting is not a weaker fault. `overtaken >= 1` is still what the proof
    /// asserts, and it is still unreachable unless two chains genuinely
    /// overlapped -- the wait only stops the fault from being spent before its
    /// subject exists.
    ///
    /// Two cases release without interleaving, and both must, because holding
    /// forever is a hang and a hang reads as a wz defect:
    ///   * the same conduit starts a SECOND chain. Emitting it ahead of the
    ///     held one would reorder WITHIN a conduit, which is the violation this
    ///     fault exists not to commit — hence [`Step::ReleaseThenForward`],
    ///     which puts the held chain back in front of it.
    ///   * [`INTERLEAVE_BATCH_BOUND`] batches pass with nothing to overtake.
    ///
    /// Neither bumps `overtaken`, so a leg asserting on it fails rather than
    /// passing on a stream that never overlapped.
    fn interleave_step(
        state: &mut InterleaveState,
        sinks: &InterleaveSinks,
        prefix: &[u8; 2],
        batch: &[u8],
    ) -> Step {
        let Some(conduit) = fragment_conduit(batch) else {
            // Not a fragment. It rides its own conduit's ordering, not the held
            // chain's, so it never waits.
            return Step::Forward;
        };
        // Read BEFORE the open-set is updated: a batch begins a chain exactly
        // when its conduit had none in flight.
        let starts_chain = !state.open.contains(&conduit);
        if fragment_has_more(batch) {
            state.open.insert(conduit);
        } else {
            state.open.remove(&conduit);
        }
        state.seen.insert(conduit);

        if state.conduit.is_none() {
            // Not yet armed. Both conditions are necessary and neither is
            // sufficient: a second conduit must exist to overtake with, and the
            // batch must OPEN a chain rather than continue one.
            if state.seen.len() < 2 || !starts_chain {
                return Step::Forward;
            }
            state.conduit = Some(conduit);
            state.closed = !fragment_has_more(batch);
            state.held.push((prefix.to_vec(), batch.to_vec()));
            sinks.held.fetch_add(1, Ordering::Relaxed);
            return Step::Hold;
        }
        state.since_hold += 1;
        if state.since_hold > INTERLEAVE_BATCH_BOUND {
            return Step::ReleaseThenForward;
        }
        if state.conduit == Some(conduit) {
            if state.closed {
                // A second chain on the SAME conduit: release rather than
                // reorder within it.
                return Step::ReleaseThenForward;
            }
            state.closed = !fragment_has_more(batch);
            state.held.push((prefix.to_vec(), batch.to_vec()));
            sinks.held.fetch_add(1, Ordering::Relaxed);
            return Step::Hold;
        }
        // A different conduit, and the held chain is still behind it. This is
        // the overlap the leg is for.
        sinks.overtaken.fetch_add(1, Ordering::Relaxed);
        if state.closed {
            Step::ForwardThenRelease
        } else {
            // The held chain is not complete yet, so keep holding and let this
            // one past — the strongest form of the overlap, both chains open.
            Step::Forward
        }
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
    /// (R311y439 re-attached the prose above, which R311y438 had stranded on
    /// `frag_payload` by inserting that helper mid-doc-comment.)
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
                    .stderr(Stdio::from(
                        out_writer.try_clone().expect("dup stderr handle"),
                    ))
                    .stdout(Stdio::from(out_writer))
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
                    .stderr(Stdio::from(
                        out_writer.try_clone().expect("dup stderr handle"),
                    ))
                    .stdout(Stdio::from(out_writer))
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

    /// R2200 (open-debt item 558) — spawn the CORE zenoh `z_pub` example as a
    /// client of a router, publishing on a NAMED CONDUIT, returned once it has
    /// started publishing (`"Putting Data"`).
    ///
    /// ## Why a second publisher helper instead of a flag on the first
    ///
    /// The two binaries share neither their argument spelling (`-v` vs `-p` for
    /// the value) nor their capabilities, and only this one can be told which
    /// conduit to publish on. It has no priority FLAG either — but it has
    /// `--cfg`, and `qos/publication` is a real config path whose entries carry
    /// BOTH halves of a conduit, a `priority` and a `reliability`
    /// (`target/zenohd/DEFAULT_CONFIG.json5`, the commented `qos.publication`
    /// block). MEASURED against a live router before this helper was written:
    /// two of these, at `real_time` and `data_low`, put priority 1 and priority
    /// 6 fragment chains on ONE link.
    ///
    /// Both halves are parameters because wz keys a reassembly chain on the
    /// PAIR, and a helper that fixed the reliability could only ever witness
    /// half of that key. `reliability` takes zenoh's own spelling — `reliable`
    /// or `best_effort`.
    ///
    /// The `key_exprs` of the overwrite is the publisher's own key, so the rule
    /// cannot reach anything else on the session. `key` is refused if it
    /// carries a quote or a backslash: the config is assembled as JSON5 text
    /// here, and a key that could close the string would silently produce a
    /// DIFFERENT rule rather than an error.
    ///
    /// No retry loop, unlike the pico helper: that one absorbs a foreign
    /// one-shot's open transient (`"Unable to open session!"`, which pico does
    /// not self-retry). This binary is the Rust session, which retries its own
    /// connect, so a retry here would only mask a real failure to reach the
    /// router.
    /// R2226 (open-debt item 575) — a genuine `z_pub` that names
    /// `congestion_control: "drop"`, for a leg whose subject is what the ROUTER
    /// does when its pipeline runs dry.
    ///
    /// # Why the congestion control is named rather than inherited
    ///
    /// It decides which arm upstream takes when a batch cannot be obtained.
    /// `pipeline.rs:823` reaches the deadline — and therefore the `0x3 Drop`
    /// marker — only for `msg.is_droppable()`, which is `!is_reliable() ||
    /// congestion_control == Drop`
    /// (`commons/zenoh-protocol/src/network/mod.rs:162`). A **Block** message
    /// takes the `wait_before_close` arm instead: the transport is TORN DOWN
    /// and nothing is marked. A leg that let this default would be one config
    /// change away from witnessing a session teardown and calling it an
    /// abandoned chain.
    ///
    /// Separate from [`spawn_publishing_zenoh_zpub`] rather than a parameter on
    /// it, because that helper's callers vary priority and reliability and are
    /// indifferent to this field; giving them all a fourth qos argument would
    /// make four legs state a value none of them is about.
    pub fn spawn_publishing_zenoh_zpub_dropping(
        z_pub: &Path,
        key: &str,
        payload: &str,
        endpoint: &str,
        mut mk_stdout: impl FnMut() -> File,
    ) -> ChildGuard {
        assert!(
            !key.contains('"') && !key.contains('\\'),
            "key {key:?} would not survive being written into the JSON5 qos rule"
        );
        let cfg = format!(
            "qos/publication:[{{\"key_exprs\":[\"{key}\"],\
             \"config\":{{\"congestion_control\":\"drop\"}}}}]"
        );
        let out = mk_stdout();
        let out_writer = out.try_clone().expect("dup z_pub stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_pub client (zenoh core example, congestion_control=drop)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(z_pub)
                .args([
                    "-k", key, "-p", payload, "-e", endpoint, "-m", "client", "--cfg", &cfg,
                ])
                .stderr(Stdio::from(
                    out_writer.try_clone().expect("dup stderr handle"),
                ))
                .stdout(Stdio::from(out_writer))
                .spawn()
                .expect("spawn zenoh z_pub via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains("Putting Data") {
                return child;
            }
            if Instant::now() >= deadline {
                let _ = child.child_mut().kill();
                let _ = child.child_mut().wait();
                panic!(
                    "zenoh z_pub did not start publishing on {key} with \
                     congestion_control=drop within 12s; captured: {cap}"
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn spawn_publishing_zenoh_zpub(
        z_pub: &Path,
        key: &str,
        payload: &str,
        endpoint: &str,
        priority: &str,
        reliability: &str,
        mut mk_stdout: impl FnMut() -> File,
    ) -> ChildGuard {
        assert!(
            !key.contains('"') && !key.contains('\\'),
            "key {key:?} would not survive being written into the JSON5 qos rule"
        );
        let cfg = format!(
            "qos/publication:[{{\"key_exprs\":[\"{key}\"],\
             \"config\":{{\"priority\":\"{priority}\",\
             \"reliability\":\"{reliability}\"}}}}]"
        );
        let out = mk_stdout();
        let out_writer = out.try_clone().expect("dup z_pub stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_pub client (zenoh core example)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(z_pub)
                .args([
                    "-k", key, "-p", payload, "-e", endpoint, "-m", "client", "--cfg", &cfg,
                ])
                .stderr(Stdio::from(
                    out_writer.try_clone().expect("dup stderr handle"),
                ))
                .stdout(Stdio::from(out_writer))
                .spawn()
                .expect("spawn zenoh z_pub via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains("Putting Data") {
                return child;
            }
            if Instant::now() >= deadline {
                let _ = child.child_mut().kill();
                let _ = child.child_mut().wait();
                panic!(
                    "zenoh z_pub did not start publishing on {key} at priority \
                     {priority} / {reliability} within 12s; captured: {cap}"
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
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
                    .stderr(Stdio::from(
                        out_writer.try_clone().expect("dup stderr handle"),
                    ))
                    .stdout(Stdio::from(out_writer))
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
                    .stderr(Stdio::from(
                        out_writer.try_clone().expect("dup stderr handle"),
                    ))
                    .stdout(Stdio::from(out_writer))
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
                    .stderr(Stdio::from(
                        out_writer.try_clone().expect("dup stderr handle"),
                    ))
                    .stdout(Stdio::from(out_writer))
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
                    .stderr(Stdio::from(
                        out_writer.try_clone().expect("dup stderr handle"),
                    ))
                    .stdout(Stdio::from(out_writer))
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

    /// R311y413 — the DISCOVERING form of [`spawn_zenohd`], and the one to reach for.
    ///
    /// zenohd binds `tcp/127.0.0.1:0` and this returns the port the kernel gave it, so
    /// no caller names a port that another process may already hold. Keep the
    /// port-taking [`spawn_zenohd`] only where the port must be NAMED in advance —
    /// today that is the same-port RESPAWN in `wz_reconnect_zenohd_pico_interop`,
    /// whose whole subject is a fresh process reachable at the endpoint the killed one
    /// used. There the first spawn can still discover, and its port is what the second
    /// is given.
    pub fn spawn_zenohd_on_ephemeral_tcp(
        mut mk_probe_stderr: impl FnMut() -> File,
    ) -> (ChildGuard, u16) {
        let (guard, port) = spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_binary(),
            "zenohd (reference router)",
            None,
            &[],
            None,
        );
        // R311pi — close the TCP-accept-vs-handshake-ready gap with a real wz session,
        // exactly as the port-taking form does.
        wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), &mut mk_probe_stderr);
        (guard, port)
    }

    /// R311y433 — [`spawn_zenohd_on_ephemeral_tcp`] with per-batch lz4
    /// COMPRESSION enabled on the unicast transport, the foreign oracle for the
    /// `transport-compression` / `session-extcompression` cross-impl leg.
    ///
    /// `transport/unicast/compression/enabled` defaults to FALSE
    /// (`zenoh-config-1.5.0` `src/defaults.rs:241-245`), so this override is what
    /// makes zenohd offer Z_EXT_COMPRESSION (0x6) back on its InitAck and then
    /// lz4-wrap / un-wrap every post-establishment batch on the link. No cargo
    /// feature is needed on the router: `transport_compression` rides zenoh's
    /// DEFAULT feature set (`zenoh-1.5.0/Cargo.toml`), so the STOCK
    /// `target/zenohd/zenohd` speaks it — unlike the unixpipe / vsock oracles,
    /// this leg needs no variant build.
    ///
    /// The un-configured [`spawn_zenohd_on_ephemeral_tcp`] is this helper's TWIN:
    /// the same wz `--compression` dial against it negotiates `false`, which is
    /// what makes the negotiation assertion a discriminator rather than a
    /// tautology.
    pub fn spawn_zenohd_compression_on_ephemeral_tcp(
        mut mk_probe_stderr: impl FnMut() -> File,
    ) -> (ChildGuard, u16) {
        let (guard, port) = spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
            &zenohd_binary(),
            "zenohd (reference router, compression)",
            None,
            &[],
            None,
            &["transport/unicast/compression/enabled:true"],
        );
        wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), &mut mk_probe_stderr);
        (guard, port)
    }

    /// R311y435 — a zenohd with BOTH the lean transport and per-batch lz4
    /// compression enabled: the foreign oracle for the COMPOSED
    /// lowlatency x compression cross-impl leg.
    ///
    /// The pair is configurable upstream, which is what makes this leg possible
    /// rather than theoretical. zenoh sets `is_lowlatency` on the transport
    /// config and `is_compression` on the link `BatchConfig` independently
    /// (`zenoh-transport-1.5.0` `unicast/establishment/open.rs:689` and `:701`),
    /// and the exclusivity check at `unicast/manager.rs:264` names QOS, not
    /// compression — hence the third override here, which is the same one
    /// [`spawn_zenohd_lowlatency`] passes and for the same reason: qos is ON by
    /// default, so a lowlatency router that does not disable it fails to build.
    ///
    /// What this router will NOT do is decompress a lean link. Its lean rx path
    /// reads only `config.batch.mtu` (`unicast/lowlatency/link.rs:161`), so a
    /// peer that lz4-wraps a lean wire is unreadable to it — which is precisely
    /// the defect R311y434 fixed and the reason this oracle exists. It accepts
    /// the 0x6 ext on the handshake and then ignores it on the data path.
    pub fn spawn_zenohd_lowlatency_compression_on_ephemeral_tcp(
        mut mk_probe_stderr: impl FnMut() -> File,
    ) -> (ChildGuard, u16) {
        let (guard, port) = spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
            &zenohd_binary(),
            "zenohd (reference router, lowlatency + compression)",
            None,
            &[],
            None,
            &[
                "transport/unicast/lowlatency:true",
                "transport/unicast/qos/enabled:false",
                "transport/unicast/compression/enabled:true",
            ],
        );
        wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), &mut mk_probe_stderr);
        (guard, port)
    }

    /// R2221 (open-debt item 568) / R2224 (item 572) — spawn a zenohd whose
    /// FRAME SN RING and whose QOS are both named, the foreign oracle for the
    /// negotiated-axes pairs.
    ///
    /// # Why the ROUTER carries the non-default value and not wz
    ///
    /// `Resolution` is `min()`ed on both sides
    /// (`io/zenoh-transport/src/unicast/establishment/accept.rs:198-213` at
    /// zenoh 1.5.0 — `res.set(Field::FrameSN, i_fsn_res.min(m_fsn_res))`), so
    /// the SMALLER advertisement wins. Put the small value on wz and the
    /// negotiated ring equals wz's own advertisement, which an implementation
    /// that ignored the peer's InitAck entirely would also produce: the leg
    /// would pass while measuring nothing. Put it on the ROUTER and the
    /// negotiated ring is a number that exists ONLY on zenohd's side of the
    /// wire until its InitAck carries it back.
    ///
    /// `resolution` is one of zenoh's own spellings — `"8bit"`, `"16bit"`,
    /// `"32bit"`, `"64bit"` (`commons/zenoh-protocol/src/core/resolution.rs:32-35`).
    /// The DEFAULT is `"32bit"` (`DEFAULT_CONFIG.json5:590`), so the
    /// un-configured [`spawn_zenohd_on_ephemeral_tcp`] is this helper's twin
    /// and the calibration arm of any pair built on it.
    ///
    /// ⚠ The probe session `wait_for_zenohd_handshake_ready` opens runs against
    /// THIS router, so the resolution has to be one a wz handshake survives.
    /// That is not a limitation to work around — a value that broke the probe
    /// would break the leg too, and finding out here is finding out earlier.
    ///
    /// # Both keys on every arm, including the ones that ask for the default
    ///
    /// R2224 (open-debt item 572) added `qos_enabled`.
    /// `transport/unicast/qos/enabled` defaults to TRUE
    /// (`DEFAULT_CONFIG.json5:547-549`), so a `qos: true` arm could be spelled
    /// by saying nothing at all. R2204's finding is why it is not: two arms
    /// that differ in WHICH HELPER THEY CALLED differ in more than the value
    /// under test, and "the default happens to be the value I wanted" is a
    /// premise that stops being true the day upstream moves it. Here the two
    /// arms of a pair differ in ONE BOOLEAN and the router is told both keys
    /// either way.
    ///
    /// ⚠ R2225 — THIS HELPER SUPERSEDED AN SN-ONLY ONE, and the round that
    /// added the QoS parameter left the older `spawn_zenohd_sn_resolution_on_ephemeral_tcp`
    /// behind with a doc sentence claiming it "stays for the callers that need
    /// only it". MEASURED: it had none — its one caller was the very fixture
    /// that had just moved to this helper. The sentence was a justification
    /// written for a population nobody counted, which is the class this tree
    /// keeps paying for; the helper is gone and passing `qos_enabled: true`
    /// spells its behaviour explicitly, which this doc already argues is the
    /// better shape.
    /// R2226 (open-debt item 575) — a zenohd whose TX path holds AS LITTLE AS
    /// UPSTREAM ALLOWS, the foreign oracle for the abandoned-chain witness.
    ///
    /// # What is configured, and why both keys are the same kind of knob
    ///
    /// * `transport/link/tx/queue/size/data`, from its default of 2 down to 1
    ///   (`DEFAULT_CONFIG.json5:615-624`; the legal range is 1..=16). One batch
    ///   object per priority means the sender cannot start the next fragment
    ///   until the link has WRITTEN the previous one and returned it.
    /// * `transport/link/tcp/so_sndbuf`, from the kernel's default down to
    ///   `SO_SNDBUF_BYTES` (`DEFAULT_CONFIG.json5:705-712`). Without it a
    ///   stalled reader has to be out-waited by megabytes of kernel buffer
    ///   before a single `write` blocks, and the run-up dominates the leg.
    ///
    /// BOTH are knobs about CAPACITY — how far a sender gets before it runs out
    /// of room — and NEITHER says anything about what it does then.
    ///
    /// ⚠ THE DROP DEADLINE IS LEFT AT ITS DEFAULT, and that is the leg's point
    /// rather than an oversight. `max_wait_before_drop_fragments` (50000 µs,
    /// `DEFAULT_CONFIG.json5:626-632`) is what decides whether a stalled sender
    /// ABANDONS the chain or waits the stall out, so tuning it would make the
    /// router's willingness to abandon a property of this harness. Left alone,
    /// the marker that reaches the wire is upstream acting on its own shipped
    /// policy, and the only thing a leg varies is whether the link stalls at
    /// all — which is what lets its calibration twin differ in exactly one
    /// input.
    pub fn spawn_zenohd_shallow_tx_queue_on_ephemeral_tcp(
        mut mk_probe_stderr: impl FnMut() -> File,
    ) -> (ChildGuard, u16) {
        let sndbuf = format!("transport/link/tcp/so_sndbuf:{SO_SNDBUF_BYTES}");
        let (guard, port) = spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
            &zenohd_binary(),
            "zenohd (reference router, shallow tx path)",
            None,
            &[],
            None,
            &["transport/link/tx/queue/size/data:1", sndbuf.as_str()],
        );
        wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), &mut mk_probe_stderr);
        (guard, port)
    }

    /// How small a stall-faulted relay asks the kernel to make its RECEIVE
    /// buffer on the upstream socket.
    ///
    /// The counterpart of [`SO_SNDBUF_BYTES`]: between a blocked reader and a
    /// sender that must run out of room stand two kernel buffers, and both have
    /// to be bounded or the sender writes megabytes before it blocks.
    pub const STALL_RECV_BUFFER_BYTES: usize = 16384;

    /// Ask the kernel for a small receive buffer on `sock`.
    ///
    /// R2226 (open-debt item 575). `std::net` exposes no `SO_RCVBUF`, and this
    /// is the whole of why `libc` is reached for here. The kernel is free to
    /// round the request up — Linux doubles it for bookkeeping and enforces its
    /// own floor — so the result is a BOUND and not a setting, which is all the
    /// stall needs.
    ///
    /// A failure is not fatal and not silent: the fault still forwards
    /// correctly, it just may not make the sender block, and the leg's own
    /// assertions are what report that. Panicking here would turn a portability
    /// question into a test failure in a place that cannot explain it.
    fn bound_recv_buffer(sock: &TcpStream, bytes: usize) {
        use std::os::fd::AsRawFd;
        let size = bytes as libc::c_int;
        // SAFETY: `sock` owns a valid fd for the duration of the call, and
        // `size` is a live `c_int` of exactly the length passed.
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::addr_of!(size).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            eprintln!(
                "counting relay: SO_RCVBUF({bytes}) was refused by the kernel; a \
                 stall fault may not make the sender block"
            );
        }
    }

    /// How small [`spawn_zenohd_shallow_tx_queue_on_ephemeral_tcp`] asks the
    /// kernel to make the router's TCP send buffer.
    ///
    /// Small enough that a stalled reader blocks the sender within a few
    /// fragments, and left as a named constant because a leg's payload has to
    /// exceed it comfortably — the two numbers are one decision.
    pub const SO_SNDBUF_BYTES: usize = 4096;

    pub fn spawn_zenohd_sn_resolution_and_qos_on_ephemeral_tcp(
        resolution: &str,
        qos_enabled: bool,
        mut mk_probe_stderr: impl FnMut() -> File,
    ) -> (ChildGuard, u16) {
        let sn = format!("transport/link/tx/sequence_number_resolution:\"{resolution}\"");
        let qos = format!("transport/unicast/qos/enabled:{qos_enabled}");
        let (guard, port) = spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
            &zenohd_binary(),
            "zenohd (reference router, sn resolution + qos)",
            None,
            &[],
            None,
            &[sn.as_str(), qos.as_str()],
        );
        wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), &mut mk_probe_stderr);
        (guard, port)
    }

    /// R311y472 — spawn a zenohd whose unicast transport AGGREGATES up to
    /// `max_links` physical links per peer, the foreign oracle for the
    /// `transport-multilink` cross-impl leg.
    ///
    /// `transport/unicast/max_links` defaults to **1**
    /// (`zenoh-config-1.5.0` `src/defaults.rs`), and that default is what makes
    /// the aggregation observable at all: zenoh only builds its `MultiLink`
    /// establishment state — and therefore only offers the 0x4 ext on its
    /// InitAck — when the configured budget is `> 1`
    /// (`MultiLink::make(.., is_multilink)`). Below the budget a second link
    /// from an already-known zid is REFUSED, so the link count zenoh reports
    /// for a peer tracks THIS knob rather than anything the dialer asserts.
    ///
    /// No cargo feature is needed on the router: `transport_multilink` rides
    /// zenoh's DEFAULT feature set, so the STOCK `target/zenohd/zenohd` speaks
    /// it — like the compression oracle, and unlike the unixpipe / vsock ones
    /// which needed variant builds.
    ///
    /// The un-configured [`spawn_zenohd_on_ephemeral_tcp`] is this helper's
    /// TWIN: the SAME wz `--max-links 2` peer dialed twice against it lands ONE
    /// link and its second dial is refused, which is what makes the two-link
    /// assertion a discriminator rather than a tautology.
    pub fn spawn_zenohd_multilink_on_ephemeral_tcp(
        max_links: usize,
        mut mk_probe_stderr: impl FnMut() -> File,
    ) -> (ChildGuard, u16) {
        let cfg = format!("transport/unicast/max_links:{max_links}");
        let (guard, port) = spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
            &zenohd_binary(),
            "zenohd (reference router, multilink)",
            None,
            &[],
            None,
            &[cfg.as_str()],
        );
        wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), &mut mk_probe_stderr);
        (guard, port)
    }

    /// R311y374 — spawn a zenohd that DIALS a wz `ws/...` acceptor
    /// (`-e ws/<wz_ws_endpoint>`) while also listening on an OS-assigned tcp port (RETURNED beside the guard) for a
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
    pub fn spawn_zenohd_ws_dialer(wz_ws_endpoint: &str) -> (ChildGuard, u16) {
        spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_binary(),
            "zenohd (ws dialer)",
            Some(wz_ws_endpoint),
            &[],
            None,
        )
    }

    /// R311y375 — spawn a zenohd that DIALS a wz `tls/...` acceptor
    /// (`-e tls/<wz>`) while listening on an OS-assigned tcp port (RETURNED beside the guard) for a pico client. The
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
    pub fn spawn_zenohd_tls_dialer(wz_tls_endpoint: &str, ca_cert_path: &str) -> (ChildGuard, u16) {
        let cfg_path = format!("{ca_cert_path}.dialer.zenohd.json5");
        let cfg = format!(
            "{{ transport: {{ link: {{ tls: {{ \
             root_ca_certificate: {ca_cert_path:?}, verify_name_on_connect: false }} }} }} }}"
        );
        std::fs::write(&cfg_path, cfg).expect("write zenohd tls dialer config");
        spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_binary(),
            "zenohd (tls dialer)",
            Some(wz_tls_endpoint),
            &[],
            Some(&cfg_path),
        )
    }

    /// R311y401 — spawn a zenohd that DIALS a wz `quic/<ip:port>` acceptor
    /// (`-e quic/<wz>`) while listening on an OS-assigned tcp port (RETURNED beside the guard) for a pico client. The
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
        ca_cert_path: &str,
    ) -> (ChildGuard, u16) {
        let cfg_path = format!("{ca_cert_path}.dialer.zenohd.json5");
        let cfg = format!(
            "{{ transport: {{ link: {{ tls: {{ \
             root_ca_certificate: {ca_cert_path:?}, verify_name_on_connect: false }} }} }} }}"
        );
        std::fs::write(&cfg_path, cfg).expect("write zenohd quic dialer config");
        spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_binary(),
            "zenohd (quic dialer)",
            Some(wz_quic_endpoint),
            &[],
            Some(&cfg_path),
        )
    }

    /// R311y411 — spawn a zenohd that DIALS `dial_locator` while listening on an
    /// OS-ASSIGNED loopback TCP port, and return BOTH the guard and the port zenohd
    /// ACTUALLY bound (for the readiness probe and for pointing pico clients at it).
    ///
    /// ## Why the port is discovered, not chosen
    ///
    /// Every zenohd dialer used to take a caller-CHOSEN `tcp_port`, by one of two
    /// routes, and R311y412 retired both in favour of this one.
    ///
    /// The first was arithmetic: `wz_port.wrapping_add(1)`, justified in-comment by
    /// "a UDP and a TCP port live in different protocol namespaces, so they cannot
    /// collide". That rules out a collision with wz's OWN socket, not with the rest of
    /// the machine. The second was `PortReservation::pick` — bind an ephemeral port,
    /// read it, drop the listener, hand the number to the child. That is better (a
    /// `bind(0)` never returns a port still in TIME_WAIT) but NOT sufficient, and the
    /// difference was measured rather than argued: under an external process cycling
    /// loopback ephemeral sockets, the reserve-then-release lanes failed 5/210
    /// (`wz_udp_acceptor`) and 3/210 (`wz_unixsock_acceptor`) with this exact
    /// signature, while the discovery lanes here were 0/330. The window between the
    /// release and the child's bind is real and losable. `wz_port + 1` is an ordinary port in the ephemeral range, and any
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
    /// There is no way to hand a child process a port that is guaranteed free — every
    /// reserve-then-release scheme only narrows the same TOCTOU window, and zenohd's
    /// CLI offers no fd-inheritance or socket-activation flag to close it. So this
    /// helper inverts the direction: zenohd binds `tcp/127.0.0.1:0`, the KERNEL picks
    /// a free port and the child never lets go of it, and the test reads the number
    /// back from zenohd's own [`crate::common::ZENOHD_LISTENER_LINE`] log line.
    /// Nothing is guessed, so there is no window to lose. Readiness is still the
    /// `wait_for_tcp_accept_alive` probe on the discovered port, so callers keep the
    /// same guarantee.
    ///
    /// `PortReservation` survives for the ports this route cannot serve — a wz-side
    /// listen the test must name BEFORE the process starts. Where the child can be
    /// made to announce, this helper is strictly better.
    ///
    /// `config_path` is the optional `--config` JSON5 (trust anchors, routing mode);
    /// the caller writes it. The capture the port is parsed out of is OWNED here —
    /// this lib crate cannot depend on the dev-only `tempfile`, so it opens a
    /// pid+counter-unique file under the temp dir and unlinks it before returning.
    /// Keeping it internal is what lets every sibling dialer delegate without
    /// threading a capture handle through its own signature.
    /// A private (writer, reader) pair over one unlinked capture file for a
    /// spawned zenohd's stdout, so a helper can PARSE what the child announced.
    ///
    /// R311y428 — lifted out of [`spawn_zenohd_dialer_on_ephemeral_tcp`] when
    /// [`spawn_zenohd_multicast_scouting_on_ephemeral_tcp`] became a second
    /// caller (the same second-user trigger that lifted `spawn_subscribed_zsub`
    /// in R311y138). The security note is the reason it is a function and not a
    /// copy: `create_new` = O_CREAT|O_EXCL, because the name is predictable and
    /// a plain create FOLLOWS a symlink someone may have planted at that path in
    /// a world-writable temp dir, truncating whatever it points at. O_EXCL fails
    /// on any existing path, symlink included, so the attack becomes a loud
    /// error rather than a silent write to a victim file. (`tempfile` gets this
    /// right, but it is a dev-dependency and this is the lib target.)
    fn zenohd_stdout_capture() -> (File, File) {
        // Unique per spawn: several zenohds can be live in one test process.
        static CAPTURE_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = CAPTURE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let capture_path =
            std::env::temp_dir().join(format!("wz-zenohd-dialer-{}-{seq}.log", std::process::id()));
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&capture_path)
            .unwrap_or_else(|e| panic!("create zenohd capture file {capture_path:?}: {e}"));
        let reader = File::open(&capture_path);
        // Unlink NOW so the file cannot outlive the spawn even if the caller panics —
        // and BEFORE the reader is unwrapped, so a failed open leaks nothing.
        let _ = std::fs::remove_file(&capture_path);
        // The CHILD's stdout fd keeps the inode alive from here on; the parent's own
        // `writer` is closed right after `spawn`, and `reader` dies with the caller.
        let reader =
            reader.unwrap_or_else(|e| panic!("open zenohd capture file {capture_path:?}: {e}"));
        (writer, reader)
    }

    pub fn spawn_zenohd_dialer_on_ephemeral_tcp(
        zenohd_bin: &std::path::Path,
        label: &'static str,
        dial_locator: Option<&str>,
        extra_listens: &[String],
        config_path: Option<&str>,
    ) -> (ChildGuard, u16) {
        spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
            zenohd_bin,
            label,
            dial_locator,
            extra_listens,
            config_path,
            &[],
        )
    }

    /// R311y433 — [`spawn_zenohd_dialer_on_ephemeral_tcp`] plus per-key
    /// `--cfg <path>:<json5>` overrides, for a leg whose subject is a zenohd
    /// CONFIG toggle rather than a listener shape (compression, lowlatency, …).
    ///
    /// Added as a widened sibling rather than a sixth parameter on the existing
    /// entrypoint: that one has callers across several feature-gated legs, and a
    /// local `cargo test` does not compile all of them, so a signature change
    /// there is a break this crate cannot see. The five-argument form now
    /// delegates here with no overrides, so both spellings share ONE body and the
    /// port-discovery / liveness reasoning below is not duplicated.
    pub fn spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
        zenohd_bin: &std::path::Path,
        label: &'static str,
        dial_locator: Option<&str>,
        extra_listens: &[String],
        config_path: Option<&str>,
        extra_cfgs: &[&str],
    ) -> (ChildGuard, u16) {
        use super::common::ZENOHD_LISTENER_LINE as LISTEN_LINE;

        let (writer, mut reader) = zenohd_stdout_capture();
        let mut command = Command::new(zenohd_bin);
        command
            // PIN the log level. This helper is the only one in the crate that reads
            // zenohd's LOG rather than probing its socket, so the announcement it
            // parses is a functional dependency, not diagnostics: zenohd builds its
            // filter with `EnvFilter::try_from_default_env()`, so an inherited
            // `RUST_LOG=warn` silently filters the line away and every leg then burns
            // its full budget on a healthy process. `spawn_on_ephemeral_port` pins the
            // same variable for the wz demo for the same reason.
            //
            // R2230 (open-debt item 579) — `info` -> `debug`, because
            // `ZENOHD_LISTENER_LINE` is a `debug!` and the `info!` line this used
            // to read stopped covering loopback in 1.10.0. Read that constant for
            // why the needle moved rather than being re-spelled.
            .env("RUST_LOG", "z=debug")
            .arg("-l")
            .arg("tcp/127.0.0.1:0")
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            // R311y606 — stderr goes to the SAME capture as stdout rather than
            // to /dev/null. zenohd's readiness needles are log lines and the
            // filter can send them either way; discarding one half made a
            // failed spawn unanswerable.
            .stderr(Stdio::from(
                writer.try_clone().expect("dup zenohd stderr handle"),
            ))
            .stdout(Stdio::from(writer));
        // Additional listeners (e.g. a unixpipe endpoint alongside the tcp one). Only a
        // TCP announcement carries the `tcp/127.0.0.1:` needle, so a non-tcp extra
        // listen can never be mistaken for the port being discovered.
        if let Some(dial) = dial_locator {
            command.arg("-e").arg(dial);
        }
        for listen in extra_listens {
            command.arg("-l").arg(listen);
        }
        if let Some(cfg) = config_path {
            command.arg("--config").arg(cfg);
        }
        // R311y433 — per-key `--cfg KEY:VALUE` overrides. argv ORDER relative to
        // `--config` is irrelevant: zenohd loads the config file first and only
        // then applies every `--cfg` pair via `insert_json5` (`zenohd-1.5.0`
        // `src/main.rs:111-114` then `:251-266`), so a key override always wins
        // over the file. Appended last purely so the spawn command reads in that
        // same precedence order.
        for cfg in extra_cfgs {
            command.arg("--cfg").arg(cfg);
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
                 was filtered out of zenohd's log — this helper pins RUST_LOG=z=debug for \
                 exactly that reason, so a hit here means the line MOVED. R2230 is the \
                 worked example: 1.10.0 did not reword it, it narrowed the OLD needle to \
                 non-loopback locators, which these hermetic helpers never have. Read \
                 `common::ZENOHD_LISTENER_LINE` before re-spelling anything)"
            )
        });
        if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET)
        {
            panic!("{label}: {e}");
        }
        (guard, port)
    }

    /// R311y428 — spawn a zenohd that ANSWERS multicast SCOUTs, listening on an
    /// OS-assigned tcp port (RETURNED beside the guard).
    ///
    /// Every other zenohd helper in this module passes `--no-multicast-scouting`;
    /// this one deliberately does not, so the router runs its default
    /// `scouting/multicast/enabled: true` responder on `224.0.0.224:7446` and a
    /// wz `--scout` finds it. The locator its HELLO advertises is the tcp
    /// listener discovered here, which is what lets a caller assert that wz
    /// dialed something it was NEVER TOLD — the port is chosen by the kernel and
    /// travels to wz only through zenohd's own Hello.
    ///
    /// WHY THIS IS A SEPARATE HELPER rather than a flag on
    /// [`spawn_zenohd_dialer_on_ephemeral_tcp`]: its READINESS GATE is different,
    /// and the difference is load-bearing. zenoh binds its unicast listeners
    /// BEFORE it binds the scouting group (`start_router` calls `bind_listeners`
    /// at zenoh `net/runtime/orchestrator.rs:255`, then `start_scout` at :260),
    /// so the tcp-accept gate the sibling helpers use can pass while nothing is
    /// listening on the group yet. A scout emitted into that window is a lost
    /// datagram — nothing retransmits it, and the peer's later readiness cannot
    /// recover it. So this additionally waits for zenohd's OWN
    /// [`crate::common::ZENOHD_SCOUT_LINE`] announcement, printed from inside
    /// `bind_mcast_port` once the socket is bound and joined. Both needles come
    /// out of one capture, so the wait costs nothing extra. (R2230 moved the
    /// text into that constant, where the version it was measured against is
    /// recorded beside it — a line quoted inline is a line nobody re-measures.)
    pub fn spawn_zenohd_multicast_scouting_on_ephemeral_tcp(
        label: &'static str,
    ) -> (ChildGuard, u16) {
        spawn_zenohd_multicast_scouting_with_args(label, &[])
    }

    /// R311y846 — the same spawn with EXTRA argv, for the mirror direction.
    ///
    /// The no-argument form above spawns zenohd in its default ROUTER mode,
    /// which answers scouts and never dials one: a router's
    /// `scouting/multicast/autoconnect` default is the EMPTY list
    /// (`DEFAULT_CONFIG.json5:149`, `{ router: [], peer: ["router", "peer"], …}`).
    /// So a test that needs zenohd to DISCOVER something and connect to it must
    /// pass `--mode peer`, and that is the argv this exists to carry. Kept as a
    /// separate entry point rather than a changed signature so the R311y428 call
    /// site is byte-identical and the two directions cannot drift apart in what
    /// they consider "a scouting zenohd".
    pub fn spawn_zenohd_multicast_scouting_with_args(
        label: &'static str,
        extra_args: &[&str],
    ) -> (ChildGuard, u16) {
        spawn_zenohd_multicast_scouting_listening_on(
            label,
            "tcp/127.0.0.1:0",
            super::common::ZENOHD_LISTENER_LINE,
            extra_args,
        )
    }

    /// R2230 (open-debt item 579) — the same scouting router LISTENING ON EVERY
    /// INTERFACE, for the one caller that needs the Hello to carry a locator.
    ///
    /// # Why a loopback listener stopped being enough
    ///
    /// The pinned 1.10.0 chooses a scout reply's locators by WHO ASKED:
    /// `get_hello_locators` returns `get_locators()` for a loopback peer and
    /// `get_locators_noloopback()` for everyone else
    /// (`zenoh/src/net/runtime/orchestrator.rs:1283`, its own comment: "public
    /// locators intentionally exclude loopback"). 1.5.0 had no such fork — it
    /// answered `get_locators()` unconditionally (`1.5.0:...:1165`).
    ///
    /// A multicast scout does not arrive from loopback. zenoh-pico's default
    /// locator names no interface (`Z_CONFIG_MULTICAST_LOCATOR_DEFAULT`,
    /// `vendor/zenoh-pico/include/zenoh-pico/config.h.in:133`), so the kernel
    /// sends it from a real interface and zenohd sees a non-loopback peer. A
    /// router listening only on `127.0.0.1` therefore answers with an EMPTY
    /// locator list — measured: the real zenoh-pico `z_scout` found the router,
    /// printed its zid and `whatami: "Router"`, and `locators: []`.
    ///
    /// # Why this is the repair and not a workaround
    ///
    /// The leg that needs this compares wz's C-ABI rendering of a Hello against
    /// the real zenoh-pico's rendering of THE SAME Hello, and what makes it
    /// sharp is that the locator carries a port the kernel chose and neither
    /// scout was told. Both survive: `tcp/0.0.0.0:0` is still a kernel-assigned
    /// ephemeral port, and both scouts still receive one Hello from one router.
    /// Only the ADDRESS in the locator changes, from the loopback literal to
    /// whichever interfaces the host has — which is the thing the comparison
    /// never depended on.
    ///
    /// ⚠ Stated rather than hidden: this binds the ephemeral port on every
    /// interface for the life of the leg, where the loopback form did not. That
    /// is the cost, and it is the smaller one — the alternative is a leg whose
    /// oracle can no longer see anything, which its own anti-vacuity guard
    /// correctly refuses to call a pass.
    pub fn spawn_zenohd_multicast_scouting_on_any_interface(
        label: &'static str,
    ) -> (ChildGuard, u16) {
        spawn_zenohd_multicast_scouting_on_any_interface_with_args(label, &[])
    }

    /// R2246 — the any-interface spawn with EXTRA argv.
    ///
    /// ⚠ R2230's doc above says this listen address is for "the ONE caller that
    /// needs the Hello to carry a locator". That was measured against the pico
    /// leg and it was not the whole population: `wz_scout_zenohd_interop`'s
    /// `wz_scout_discovers_zenohd_over_multicast_and_opens_the_advertised_locator`
    /// needs it for exactly the same reason and was left on the loopback form,
    /// where 1.10.0 answers its multicast scout with an empty locator list. It
    /// went red on every hosted run from the pin move onward and was masked by a
    /// compile error in the same lane until R2243 cleared that.
    ///
    /// The population is derivable rather than remembered: of the three callers
    /// of the loopback form, the other two (`zenohd_scouts_wz_interop`,
    /// `zenohd_scouts_wz_router_interop`) run the OPPOSITE direction — zenohd
    /// asks and wz answers — so zenohd's own locators never reach an assertion
    /// there. Direction is the discriminator, not the count.
    ///
    /// A separate entry point rather than a changed signature, for the reason
    /// `spawn_zenohd_multicast_scouting_with_args` gives one screen up: the
    /// existing call sites stay byte-identical.
    pub fn spawn_zenohd_multicast_scouting_on_any_interface_with_args(
        label: &'static str,
        extra_args: &[&str],
    ) -> (ChildGuard, u16) {
        spawn_zenohd_multicast_scouting_listening_on(
            label,
            "tcp/0.0.0.0:0",
            super::common::ZENOHD_ANY_LISTENER_LINE,
            extra_args,
        )
    }

    /// The body the three scouting entry points share.
    ///
    /// `listen` and `listen_needle` travel TOGETHER because they are one fact:
    /// the needle is how the kernel's choice of port is read back out of
    /// zenohd's own log, and it must name the address that was asked for. Split
    /// across two call sites they could disagree, and the failure would be a
    /// spawn that waits out its whole budget on a healthy router.
    fn spawn_zenohd_multicast_scouting_listening_on(
        label: &'static str,
        listen: &str,
        listen_needle: &str,
        extra_args: &[&str],
    ) -> (ChildGuard, u16) {
        use super::common::ZENOHD_SCOUT_LINE as SCOUT_LINE;
        let listen_line = listen_needle;

        let (writer, mut reader) = zenohd_stdout_capture();
        let mut command = Command::new(zenohd_binary());
        command
            // PIN the log level for the same reason the dialer helper does: both
            // readiness needles are LOG lines, so an inherited `RUST_LOG=warn`
            // would filter them away and the spawn would burn its full budget on
            // a perfectly healthy router.
            //
            // R2230 (open-debt item 579) — `info` -> `debug`, with the port
            // needle. `SCOUT_LINE` is unaffected either way: `debug` is the more
            // permissive filter, so a level that carries the new needle carries
            // the old ones too.
            .env("RUST_LOG", "z=debug")
            .arg("-l")
            .arg(listen)
            .arg("--rest-http-port")
            .arg("none")
            // R311y606 — stderr goes to the SAME capture as stdout rather than
            // to /dev/null. zenohd's readiness needles are log lines and the
            // filter can send them either way; discarding one half made a
            // failed spawn unanswerable.
            .stderr(Stdio::from(
                writer.try_clone().expect("dup zenohd stderr handle"),
            ))
            .stdout(Stdio::from(writer));
        // LAST, so a caller can override anything above it: zenohd's clap parse
        // keeps the final occurrence, and the readiness needles this helper waits
        // on are what constrain what a caller may sensibly override.
        //
        // ⚠ `-l` is the one flag a caller must NOT pass here: zenohd APPENDS
        // listeners rather than replacing them, so an extra `-l` gives the
        // router a second port while `listen_needle` still reads the first. The
        // listen address is a parameter of this function for exactly that
        // reason.
        command.args(extra_args);
        let mut guard = ChildGuard::wrap(
            label,
            command
                .spawn()
                .expect("spawn zenohd multicast-scouting router"),
        );
        // ONE wait for BOTH needles: the port is only reported once the scout
        // announcement is also present, so a caller that got a port has a router
        // whose group socket is bound and joined.
        let port = wait_for_capture_alive(
            guard.child_mut(),
            &mut reader,
            ZENOHD_TCP_ACCEPT_BUDGET,
            "announcing its bound tcp listener AND its scout listener",
            |captured| {
                if !captured.contains(SCOUT_LINE) {
                    return None;
                }
                parse_announced_tcp_port(captured, listen_line)
            },
        )
        .unwrap_or_else(|e| {
            panic!(
                "{label}: {e}\n\
                 (both needles are zenohd log lines: {listen_line:?} and \
                 {SCOUT_LINE:?}. A live process with a capture holding only the \
                 first means multicast scouting did not come up — check that no \
                 --no-multicast-scouting reached this spawn; a capture with \
                 neither means the log FORMAT moved.)"
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
    /// an OS-assigned tcp port (RETURNED beside the guard) for a pico client. The DATAGRAM twin of
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
        ca_cert_path: &str,
    ) -> (ChildGuard, u16) {
        let cfg_path = format!("{ca_cert_path}.dialer.zenohd.json5");
        let cfg = format!(
            "{{ transport: {{ link: {{ tls: {{ \
             root_ca_certificate: {ca_cert_path:?}, verify_name_on_connect: false }} }} }} }}"
        );
        std::fs::write(&cfg_path, cfg).expect("write zenohd quic-datagram dialer config");
        spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_binary(),
            "zenohd (quic-datagram dialer)",
            Some(&format!("quic/{wz_quic_datagram_addr}?rel=0")),
            &[],
            Some(&cfg_path),
        )
    }

    /// R311y398 — spawn a zenohd that DIALS a wz `unixsock-stream/<path>` acceptor
    /// (`-e unixsock-stream/<path>`) while also listening on an OS-assigned tcp port (RETURNED beside the guard) for a
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
    pub fn spawn_zenohd_unixsock_dialer(wz_unixsock_path: &str) -> (ChildGuard, u16) {
        spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_binary(),
            "zenohd (unixsock dialer)",
            Some(&format!("unixsock-stream/{wz_unixsock_path}")),
            &[],
            None,
        )
    }

    /// R311y399 — spawn a zenohd that DIALS a wz `udp/...` acceptor
    /// (`-e udp/<wz_udp_endpoint>`) while also listening on an OS-assigned tcp port (RETURNED beside the guard) for a
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
    pub fn spawn_zenohd_udp_dialer(wz_udp_endpoint: &str) -> (ChildGuard, u16) {
        spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_binary(),
            "zenohd (udp dialer)",
            Some(wz_udp_endpoint),
            &[],
            None,
        )
    }

    /// R311y400 — spawn a VSOCK-enabled zenohd that DIALS a wz `vsock/<cid>:<port>`
    /// acceptor (`-e vsock/<cid>:<port>`) while listening on an OS-assigned tcp port (RETURNED beside the guard) for a
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
    pub fn spawn_zenohd_vsock_dialer(wz_vsock_endpoint: &str) -> (ChildGuard, u16) {
        spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_vsock_binary(),
            "zenohd (vsock dialer)",
            Some(wz_vsock_endpoint),
            &[],
            None,
        )
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
        mk_probe_stderr: impl FnMut() -> File,
    ) -> (ChildGuard, u16) {
        // R311y412 — LISTENER-only (no `-e`), so the shared discovery primitive takes
        // `None` for the dial locator and the unixpipe endpoint as an extra listen.
        // Only a TCP announcement carries the needle, so the unixpipe listen cannot be
        // mistaken for the port being discovered.
        let (guard, tcp_port) = spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_unixpipe_binary(),
            "zenohd (unixpipe+tcp listener)",
            None,
            &[format!("unixpipe/{unixpipe_base}")],
            None,
        );
        if !wait_for_unixpipe_request_fifo(unixpipe_base, Duration::from_secs(15)) {
            panic!(
                "zenohd did not create the unixpipe request FIFO {unixpipe_base}_uplink within 15s"
            );
        }
        // Close the TCP-accept-vs-handshake-ready gap with a real wz session (the
        // R311pi discipline in spawn_zenohd_listeners); the wz probe dials TCP, so
        // it needs no unixpipe feature.
        wait_for_zenohd_handshake_ready(&format!("tcp/127.0.0.1:{tcp_port}"), mk_probe_stderr);
        (guard, tcp_port)
    }

    /// R311y393 — spawn a UNIXPIPE-enabled zenohd that DIALS a wz `unixpipe/<base>`
    /// acceptor (`-e unixpipe/<base>`) while listening on an OS-assigned tcp port (RETURNED beside the guard) for a
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
    pub fn spawn_zenohd_unixpipe_dialer(wz_unixpipe_base: &str) -> (ChildGuard, u16) {
        spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_unixpipe_binary(),
            "zenohd (unixpipe dialer)",
            Some(&format!("unixpipe/{wz_unixpipe_base}")),
            &[],
            None,
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
    use super::common::{
        configured_zid_value, face_zid_value, hello_zid_value, line_with,
        parse_zenoh_admin_sessions, still_running_reason, wait_for_tcp_accept_alive, ChildGuard,
        ZenohSession, ZENOHD_TCP_ACCEPT_BUDGET,
    };

    /// R2118 (open-debt item 507) — the stalled message offers HYPOTHESES and
    /// reaches no verdict.
    ///
    /// The property item 507 is about, asserted rather than intended. A message
    /// that names one cause as THE reason is what sent R2086's diagnosis to the
    /// build while the demo was exiting 2 over its own argv, and the fix for
    /// that is not a better sentence — it is a shape a test can hold down.
    ///
    /// Runs with no process, no socket and no daemon: the message is a function
    /// of its input, which is what makes it assertable at all, and why it is
    /// here rather than beside the leg that renders it.
    #[test]
    fn the_stalled_message_offers_hypotheses_rather_than_a_verdict() {
        let text = still_running_reason("qos and lowlatency are mutually exclusive");

        // The marker, and MORE THAN ONE cause under it. A single numbered line
        // is a verdict wearing a list's clothes.
        assert!(text.contains("possible causes:"), "{text}");
        let numbered = (1..=9)
            .filter(|n| text.contains(&format!("\n{n}. ")))
            .count();
        assert!(
            numbered >= 2,
            "a single hypothesis under the marker is still a verdict: {text}"
        );

        // It says the child is ALIVE, so the reader is not sent looking for an
        // exit that the other arm would have reported with its status.
        assert!(text.contains("STILL RUNNING"), "{text}");

        // And the child's own words are carried through, which is the half that
        // ends the guessing: this is the line R2086 needed and had to get by
        // running the demo by hand.
        assert!(
            text.contains("qos and lowlatency are mutually exclusive"),
            "the child's own stderr must reach the message: {text}"
        );

        // CONTROL — an EMPTY stderr still produces the marker and the causes,
        // so the message does not degrade to nothing on the run where the child
        // said nothing. That run is a finding too, and the text says which
        // hypothesis it rules out.
        let quiet = still_running_reason("");
        assert!(quiet.contains("possible causes:"), "{quiet}");
        assert!(quiet.contains("rules out 1"), "{quiet}");
    }

    /// R2059 (open-debt item 421) — the recorded e2e zid widths are the widths
    /// the helper actually produces, and the record is the whole roster.
    ///
    /// Both directions. A row whose width the helper does not produce is a
    /// record that has stopped describing the test it names; a scouting e2e
    /// added with a third width and no row here is the drift the item asks to
    /// be prevented, and the pinned set is what makes that visible.
    #[test]
    fn the_scouting_e2e_zid_widths_are_the_widths_their_helper_builds() {
        use super::common::{per_process_zid_hex, SCOUTING_E2E_ZID_WIDTHS};

        assert!(
            !SCOUTING_E2E_ZID_WIDTHS.is_empty(),
            "a record of nothing describes nothing"
        );
        for (test, bytes) in SCOUTING_E2E_ZID_WIDTHS {
            let hex = per_process_zid_hex("abcd", *bytes);
            assert_eq!(
                hex.len(),
                bytes * 2,
                "{test} is recorded as a {bytes}-byte zid and the helper built \
                 {} hex chars",
                hex.len()
            );
            assert!(
                (1..=16).contains(bytes),
                "{test}'s width {bytes} is not one a length nibble can name"
            );
        }

        // The SET, pinned: three widths out of sixteen (R2094 added the third),
        // and the doc on `SCOUTING_E2E_ZID_WIDTHS` says why that is a
        // foreign-witness claim rather than a reading of the axis. The
        // deterministic sweep lives in `wz_session_core::scouting_message`.
        let widths: Vec<usize> = SCOUTING_E2E_ZID_WIDTHS.iter().map(|(_, b)| *b).collect();
        assert_eq!(
            widths,
            vec![16, 4, 8],
            "the scouting e2e no longer walk the widths this record names"
        );
    }

    /// A face line as `wz-ap-demo` renders one, for the three tests below.
    fn face_line(zid_hex: &str) -> String {
        format!("face 0 UP (peer 127.0.0.1:54310, zid {zid_hex}) whatami Some(Peer)")
    }

    /// THE DETERMINISTIC REPRODUCTION of open-debt item 417.
    ///
    /// A probabilistic defect cannot be judged by re-running the e2e — that is a
    /// dice roll, not a discriminator, which is the lesson item 393 recorded
    /// about a different intermittent. So the rule is lifted out of the e2e and
    /// fed the short zid directly. The fixture is the zid hosted run
    /// 32411221953 actually failed on: 30 characters, because its top byte is
    /// zero.
    #[test]
    fn a_short_zid_is_still_recognised_as_a_zenohd_face() {
        let short = "e77a27c47363d6d97990a76230cc58";
        assert_eq!(short.len(), 30, "the fixture must be the SHORT rendering");
        let expected = u128::from_str_radix(short, 16).expect("the fixture parses");
        assert_eq!(
            face_zid_value(&face_line(short)),
            Some(expected),
            "a zid whose leading nibble is zero renders in fewer than 32 \
             characters and is still the same node; this is exactly what hosted \
             run 32411221953 reported as a failure"
        );
    }

    /// The other half: the rule must still TELL NODES APART. A rule that
    /// accepted anything would satisfy the test above, so this pins the
    /// negative.
    #[test]
    fn a_different_zid_is_not_taken_for_a_zenohd_face() {
        let zenohd = u128::from_str_radix("e77a27c47363d6d97990a76230cc58", 16).expect("parses");
        let wz_demo = "70730001";
        assert_ne!(
            face_zid_value(&face_line(wz_demo)),
            Some(zenohd),
            "a wz demo zid must not be read as the zenohd face's"
        );
        assert_eq!(
            face_zid_value(&face_line(wz_demo)),
            Some(u128::from_str_radix(wz_demo, 16).expect("parses")),
            "and it must still parse to its own value"
        );
    }

    /// THE DETERMINISTIC REPRODUCTION of open-debt item 420 — the sibling
    /// shape, whose marker and terminator both differ.
    ///
    /// The fixture is a real measurement: pinning `id:"3f1c8341"` on a
    /// multicast-scouting zenohd produced
    /// `hellos=[v9 router zid=41831c3f locators=[...]]`, eight characters, and
    /// the old `len() == 32` assertion failed on it. A legal zenohd zid whose
    /// top byte is zero produces the same shape once in 256 runs.
    #[test]
    fn a_scouted_hello_zid_is_read_by_value_whatever_its_width() {
        let line = "wz-ap-demo: scouted peer locator tcp/127.0.0.1:38693 \
                    (scout_emit=1, record_hello=1) \
                    hellos=[v9 router zid=41831c3f locators=[tcp/127.0.0.1:38693]]";
        assert_eq!(
            hello_zid_value(line),
            Some(u128::from_str_radix("41831c3f", 16).expect("parses")),
            "the hex run must end at the first non-hex character, so a short \
             zid followed by ` locators=[..]` still reads as its own value"
        );
        // And it is the value the config produced: same relationship item 417
        // measured on the other line, re-measured here rather than assumed.
        assert_eq!(
            hello_zid_value(line),
            Some(configured_zid_value("3f1c8341")),
            "a zid configured as 3f1c8341 renders here as 41831c3f — the bytes \
             reversed, exactly as on the face line"
        );
    }

    /// The negative half: a marker that is not present, and a marker followed
    /// by no hex, must both come back `None` rather than as some number.
    #[test]
    fn a_line_without_a_zid_yields_no_zenohd_value() {
        assert_eq!(hello_zid_value("no marker here"), None);
        assert_eq!(hello_zid_value("hellos=[v9 router zid= locators=[]]"), None);
    }

    /// The endianness fact, pinned because it is FOREIGN BEHAVIOUR the e2e
    /// depends on and would otherwise re-learn by failing.
    ///
    /// Measured against a real zenohd during R311y903: `--cfg id:"2e0db2ae"`
    /// produced `face 0 UP (... zid aeb20d2e)`. If upstream stops reversing,
    /// this reds here — beside the reason — instead of in an e2e whose message
    /// would only say two numbers differ.
    #[test]
    fn a_configured_zenohd_zid_renders_with_its_bytes_reversed() {
        assert_eq!(
            configured_zid_value("2e0db2ae"),
            u128::from_str_radix("aeb20d2e", 16).expect("parses"),
            "zenoh holds the configured id bytes little-endian and renders \
             `u128::from_le_bytes`, so the rendering is the config with its \
             bytes reversed"
        );
    }
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

    /// R311y413 — a parent poll must not rewind the WRITER's position.
    ///
    /// The crate's capture handles are overwhelmingly `try_clone()` duplicates of the
    /// handle given to the child as stdout. `try_clone` is `dup(2)`: one open file
    /// description, hence ONE offset shared by both. A seeking reader sets that offset
    /// to 0 for the duration of its read, and a write landing in that window goes to
    /// the START of the file, destroying output already captured.
    ///
    /// The window is microseconds, so a single-threaded test cannot expose it (the
    /// read restores the offset to EOF before the next write). This twin forces it: a
    /// writer thread appends continuously while the main thread polls, and every line
    /// must survive. RED-verified — with the seeking reader this loses lines.
    #[test]
    fn read_captured_does_not_rewind_a_shared_offset_writer() {
        use std::io::Write;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        const LINES: usize = 400;
        let path =
            std::env::temp_dir().join(format!("wz-shared-offset-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // read+write, exactly what `tempfile::tempfile()` hands the capture sites
        // before they `try_clone` it for the child.
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create shared-offset capture");
        // THE hazardous arrangement, on purpose: shared offset.
        let mut reader = writer.try_clone().expect("dup the capture handle");
        let _ = std::fs::remove_file(&path);

        let done = Arc::new(AtomicBool::new(false));
        let writer_done = Arc::clone(&done);
        let scribe = thread::spawn(move || {
            let mut w = writer;
            for i in 0..LINES {
                writeln!(w, "line{i:04}").expect("child-side write");
            }
            writer_done.store(true, Ordering::Release);
        });
        // Poll like `wait_for_substring` does, but without its sleep, to maximise the
        // number of reads that overlap a write.
        while !done.load(Ordering::Acquire) {
            let _ = super::common::read_captured(&mut reader);
        }
        scribe.join().expect("scribe thread");
        let last = super::common::read_captured(&mut reader);

        let missing: Vec<usize> = (0..LINES)
            .filter(|i| !last.contains(&format!("line{i:04}\n")))
            .collect();
        assert!(
            missing.is_empty(),
            "a poll must not rewind the writer — {} of {LINES} lines were overwritten \
             (first missing: {:?}). A seeking reader on a SHARED offset does this.",
            missing.len(),
            missing.first()
        );
    }

    /// The capture pair the PRODUCTION helper builds: writer via `create_new`
    /// (O_EXCL), reader via a separate `open`, file unlinked immediately — two
    /// independent open file descriptions, so the offsets cannot interfere.
    fn shipped_capture_pair(tag: &str) -> (std::fs::File, std::fs::File) {
        let path =
            std::env::temp_dir().join(format!("wz-capture-twin-{tag}-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create twin capture");
        let reader = std::fs::File::open(&path).expect("open twin capture");
        let _ = std::fs::remove_file(&path);
        (writer, reader)
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
        // R2230 (open-debt item 579) — the fixture drives the needle the helpers
        // ACTUALLY look for, rather than a fourth copy of a string. It had been a
        // literal, and when the real needle moved this test kept passing against
        // a line no zenohd emits any more: a torn-read guard proven over a
        // fiction. The parser is generic over its needle, so nothing here needed
        // the literal in the first place.
        use super::common::{parse_announced_tcp_port, ZENOHD_LISTENER_LINE as NEEDLE};

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

        // The SHIPPED arrangement: two independent open file descriptions (writer via
        // create_new, reader via open), NOT `try_clone`, which shares the file OFFSET
        // so a reader rewind can destroy the child's already-written output. A twin
        // built on the abandoned shape would not be evidence for what ships.
        let (writer, mut reader) = shipped_capture_pair("corpse");
        let mut child = Command::new("sh")
            .args(["-c", "echo starting; exit 3"])
            .stderr(Stdio::from(writer.try_clone().expect("dup stderr handle")))
            .stdout(Stdio::from(writer))
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

        // Same shipped create/open pair as the corpse twin above.
        let (writer, mut reader) = shipped_capture_pair("live");
        // Announce only after a delay, so the wait genuinely polls; then stay alive.
        let child = Command::new("sh")
            .args([
                "-c",
                "sleep 0.3; echo \"reached at: tcp/127.0.0.1:41059\"; sleep 30",
            ])
            .stderr(Stdio::from(writer.try_clone().expect("dup stderr handle")))
            .stdout(Stdio::from(writer))
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

    /// R311y472 — the multilink leg's measuring instrument, calibrated against a
    /// body captured VERBATIM from a live zenohd rather than a hand-drawn shape.
    #[test]
    fn parses_the_aggregated_shape_zenohd_actually_emits() {
        let body = "{\"locators\":[\"tcp/127.0.0.1:47447\"],\"metadata\":null,\"plugins\":{},\
            \"sessions\":[{\"links\":[{\"dst\":\"tcp/127.0.0.1:49538\",\"src\":\"tcp/127.0.0.1:47447\"},\
            {\"dst\":\"tcp/127.0.0.1:49548\",\"src\":\"tcp/127.0.0.1:47447\"}],\"peer\":\"2007370\",\
            \"weight\":null,\"whatami\":\"peer\"},{\"links\":[{\"dst\":\"tcp/127.0.0.1:33334\",\
            \"src\":\"tcp/127.0.0.1:47447\"}],\"peer\":\"4030201\",\"weight\":null,\
            \"whatami\":\"client\"}],\"version\":\"v1.5.0\",\"zid\":\"7ad3ed7c\"}";
        assert_eq!(
            parse_zenoh_admin_sessions(body),
            vec![
                ZenohSession {
                    peer: "2007370".into(),
                    whatami: "peer".into(),
                    links: 2,
                },
                ZenohSession {
                    peer: "4030201".into(),
                    whatami: "client".into(),
                    links: 1,
                },
            ]
        );
    }

    /// The state a router that REFUSED the aggregation produces, and the one a
    /// document-wide `"dst"` count would misread as success: TWO separate
    /// single-link sessions, not one two-link session.
    #[test]
    fn two_separate_single_link_sessions_are_not_one_aggregated_session() {
        let body = "{\"sessions\":[{\"links\":[{\"dst\":\"tcp/1\",\"src\":\"tcp/0\"}],\
            \"peer\":\"2007370\",\"whatami\":\"peer\"},{\"links\":[{\"dst\":\"tcp/2\",\
            \"src\":\"tcp/0\"}],\"peer\":\"2007370\",\"whatami\":\"peer\"}]}";
        let sessions = parse_zenoh_admin_sessions(body);
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().all(|s| s.links == 1));
    }

    /// A `]` inside a locator STRING must not terminate the links array — the
    /// reason the scan tracks depth and string literals instead of taking the
    /// first closing bracket.
    #[test]
    fn an_ipv6_locator_does_not_truncate_the_links_array() {
        let body =
            "{\"sessions\":[{\"links\":[{\"dst\":\"tcp/[::1]:7447\",\"src\":\"tcp/[::1]:1\"},\
            {\"dst\":\"tcp/[fe80::2]:7447\",\"src\":\"tcp/[::1]:1\"}],\"peer\":\"2007370\",\
            \"whatami\":\"peer\"}]}";
        assert_eq!(
            parse_zenoh_admin_sessions(body).first().map(|s| s.links),
            Some(2)
        );
    }

    /// [`line_with`] must return the line carrying the needle, NOT the first
    /// line of the capture — the defect measured while authoring R311y472.
    #[test]
    fn line_with_returns_the_needles_line_not_the_first() {
        let captured = "peer: listening on 127.0.0.1:41287\nADVERTISED SELF LOCATOR tcp/x\n\
                        peer: link AGGREGATED to zid abc (live links now 2)\n";
        assert_eq!(
            line_with(captured, "link AGGREGATED to zid").as_deref(),
            Some("peer: link AGGREGATED to zid abc (live links now 2)")
        );
        assert_eq!(line_with(captured, "no such needle"), None);
    }
}

/// R311y759 (carry N65) — the WIRE TAP: bytes a foreign implementation wrote,
/// carried to the analyzer without a capture hook and without `CAP_NET_RAW`.
///
/// ## Why this exists at all
///
/// Measured at R311y759: the analyzer carried 649 passing tests and ZERO of them
/// used bytes wz did not author. No `.pcap` in the tree, no `include_bytes!` of a
/// real capture, no lane feeding a foreign process's output to `wz-capture` —
/// while Layers Z and E were already driving a real `zenohd` and a real
/// zenoh-pico. A decoder graded only against its own encoder cannot detect a
/// misreading the two share, which is the one failure this workspace's rule
/// ("the oracle anchor is stock traffic, not wz") exists to prevent.
///
/// ## The shape
///
/// A relay sits between the two processes: each side dials or accepts as it
/// normally would, and every byte is recorded as it is forwarded. No production
/// code learns about capture — a witness satisfied by a hook that exists only for
/// it proves nothing — and no privileged socket is involved, which is what keeps
/// `wz_runtime_tokio::live_capture`'s AF_PACKET tap `#[ignore]`d and unrunnable
/// in CI.
///
/// ## The envelope is synthesised, and that is stated rather than implied
///
/// STOCK: every byte above TCP. SYNTHESISED: Ethernet / IPv4 / TCP, because a
/// userspace relay cannot observe headers the kernel wrote. The envelope is the
/// vehicle and not the claim — decapsulation already has coverage over seven link
/// types, and what had never been tested is the layer above it.
pub mod wire_tap {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    /// Which endpoint wrote a recorded segment.
    ///
    /// Named by ROLE rather than by implementation, because the roles swap
    /// between witnesses: against zenoh-pico the foreign process dials and wz
    /// accepts, and against `zenohd` it is the other way round.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Side {
        /// Written by whoever DIALLED the proxy.
        FromDialer,
        /// Written by whoever the proxy dialled — the upstream listener.
        FromListener,
    }

    /// Segments in the order the proxy forwarded them, which is the order the
    /// wire carried them. Interleaving across directions is preserved because
    /// the handshake's alternation is part of what is being witnessed.
    pub type Recording = Arc<Mutex<Vec<(Side, Vec<u8>)>>>;

    fn pump(mut from: TcpStream, mut to: TcpStream, side: Side, log: Recording) {
        let mut buf = [0u8; 64 * 1024];
        loop {
            match from.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    // Record BEFORE forwarding. A segment forwarded but not
                    // recorded shrinks the capture silently, which makes every
                    // downstream assertion weaker instead of failing.
                    let segment = buf[..n].to_vec();
                    log.lock().expect("recording lock").push((side, segment));
                    if to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = to.shutdown(Shutdown::Write);
    }

    /// Start a relay in front of `upstream_port`. Returns the port to dial and
    /// the recording both directions land in.
    ///
    /// One connection only: every witness built on this relays a single session,
    /// and accepting a second would interleave two streams into one recording
    /// with no way to tell them apart.
    pub fn tap_proxy(upstream_port: u16) -> (u16, Recording) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tap proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        let log: Recording = Arc::new(Mutex::new(Vec::new()));
        let log_thread = Arc::clone(&log);
        std::thread::spawn(move || {
            let Ok((client, _)) = listener.accept() else {
                return;
            };
            let Ok(server) = TcpStream::connect(("127.0.0.1", upstream_port)) else {
                return;
            };
            let c_read = client.try_clone().expect("clone client");
            let c_write = client;
            let s_read = server.try_clone().expect("clone server");
            let s_write = server;
            let up_log = Arc::clone(&log_thread);
            let down_log = Arc::clone(&log_thread);
            let up = std::thread::spawn(move || pump(c_read, s_write, Side::FromDialer, up_log));
            let down =
                std::thread::spawn(move || pump(s_read, c_write, Side::FromListener, down_log));
            let _ = up.join();
            let _ = down.join();
        });
        (port, log)
    }

    const ETHERTYPE_IPV4: u16 = 0x0800;
    const IPPROTO_TCP: u8 = 6;
    /// R2050 — the multicast half of this module writes UDP.
    const IPPROTO_UDP: u8 = 17;

    /// Wrap one recorded segment as Ethernet / IPv4 / TCP.
    ///
    /// R311y886 (open-debt item 357) — THE CHECKSUMS ARE REAL, and the comment
    /// that used to stand here was a false claim about another crate that would
    /// have stopped the next reader from looking.
    ///
    /// It said: "Checksums are left zero: `wz-capture`'s TCP path does not
    /// verify them, so computing them would assert nothing this harness is
    /// about." Measured, that path verifies BOTH the IPv4 and the TCP checksum
    /// and reports each as valid / invalid / absent. A zero is not absence
    /// either — neither protocol has a declining form — so every capture this
    /// function synthesised read as corrupt on both axes, and the sentence
    /// above is the reason nobody checked.
    ///
    /// The lengths and sequence numbers were always real, because reassembly
    /// reads them; now the checksums are too, because something else does.
    fn tcp_packet(src_port: u16, dst_port: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        const HOST: [u8; 4] = [127, 0, 0, 1];
        let mut pkt = Vec::with_capacity(14 + 20 + 20 + payload.len());
        pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let total_len = (20 + 20 + payload.len()) as u16;
        pkt.extend_from_slice(&[0x45, 0x00]);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, IPPROTO_TCP, 0x00, 0x00]);
        pkt.extend_from_slice(&HOST);
        pkt.extend_from_slice(&HOST);
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&[0x50, 0x18]);
        pkt.extend_from_slice(&8192u16.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(payload);
        // Filled in place, over the frame this function has already laid: the
        // IPv4 header starts 14 bytes in and the segment 20 bytes after that.
        wz_packet_fixtures::fill_ipv4_checksum(&mut pkt[14..34]);
        wz_packet_fixtures::fill_tcp_checksum(HOST, HOST, &mut pkt[34..]);
        pkt
    }

    /// One IPv4/UDP frame carrying `payload`, from `src` to a MULTICAST group.
    ///
    /// R2050 — the datagram sibling of [`tcp_packet`], and it exists because a
    /// multicast JOIN cannot be reached through the tap at all: `tap_proxy` is a
    /// TCP relay and zenoh's multicast transport is UDP, so the three witnesses
    /// that share this module had no way to feed the analyzer a FOREIGN Join.
    ///
    /// The destination MAC is the IPv4 multicast mapping (`01:00:5e` plus the
    /// low 23 bits of the group), not a made-up address: `wz-capture` reads the
    /// L2 header, and a frame whose MAC contradicts its IP destination is a
    /// capture no tool would have produced.
    fn udp_multicast_packet(
        src_port: u16,
        group: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        const HOST: [u8; 4] = [127, 0, 0, 1];
        let mut pkt = Vec::with_capacity(14 + 20 + 8 + payload.len());
        // 01:00:5e:xx:xx:xx — RFC 1112 §6.4, low 23 bits of the group.
        pkt.extend_from_slice(&[0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]]);
        pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        let total_len = 20 + udp_len;
        pkt.extend_from_slice(&[0x45, 0x00]);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        // No DF on a multicast datagram, and TTL 1 is what a link-local group
        // gets: this is the shape a real capture of `iface=lo` holds.
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 1, IPPROTO_UDP, 0x00, 0x00]);
        pkt.extend_from_slice(&HOST);
        pkt.extend_from_slice(&group);
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(payload);
        wz_packet_fixtures::fill_ipv4_checksum(&mut pkt[14..34]);
        wz_packet_fixtures::fill_udp_checksum(HOST, group, &mut pkt[34..]);
        pkt
    }

    /// Wrap recorded multicast datagrams as a pcap the analyzer can open.
    ///
    /// R2050. One packet per datagram, in the order they arrived, because on a
    /// datagram link the datagram IS the framing unit — there is no stream to
    /// rebuild and no sequence numbers to thread. That is also why a decoded
    /// message's `stream_offset` is the PACKET INDEX here (`DatagramDissection`
    /// says so on `frames`), which is what lets a caller resolve a message back
    /// to the bytes it recorded.
    pub fn synthesise_multicast_pcap(
        datagrams: &[Vec<u8>],
        src_port: u16,
        group: [u8; 4],
        dst_port: u16,
    ) -> Vec<u8> {
        let packets: Vec<Vec<u8>> = datagrams
            .iter()
            .map(|d| udp_multicast_packet(src_port, group, dst_port, d))
            .collect();
        let borrowed: Vec<(u32, u32, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (1, i as u32, p.as_slice()))
            .collect();
        wz_capture::pcap::write(wz_capture::link::LINKTYPE_ETHERNET, &borrowed)
    }

    /// What a single-byte damage sweep found, by outcome.
    ///
    /// The three counts are kept apart because they answer different questions
    /// and one of them is the answer: `vanished` and `still_clean` are both
    /// "the Err arm was not reached", and collapsing them would hide that the
    /// first is the analyzer refusing to frame at all while the second is the
    /// analyzer correctly not caring.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct DamageSweep {
        /// Byte positions visited. Zero means the verdict is about nothing.
        pub swept: usize,
        /// Positions where at least one frame came back `Err`.
        pub yielded_err: usize,
        /// R2053 (open-debt item 371) — the capture did not PARSE at all.
        ///
        /// Split out of the old fused `vanished`, and the split is the point.
        /// That one counter was incremented at THREE different sites, and the
        /// three are different outcomes: the pcap reader refusing the file, the
        /// reader accepting it and finding no flow, and a flow existing with the
        /// damaged direction emptied. A move BETWEEN them was invisible, which
        /// is exactly what item 371 says may have happened when
        /// [`synthesise_pcap`] started writing REAL checksums (R311y886): a
        /// flipped byte now breaks a checksum as well as a field, so the
        /// outcome can shift from "the decoder objected" to "the capture never
        /// got that far" with every assertion in the tree still green.
        pub pcap_rejected: usize,
        /// The pcap parsed and the reader found NO flow in it.
        pub no_flow: usize,
        /// A flow existed and the damaged direction had no frames left — the
        /// assembler desynchronised and that half disappeared.
        pub direction_lost: usize,
        /// Positions the decoder had no objection to, which is usually correct:
        /// a byte inside a payload is not the transport decoder's business.
        pub still_clean: usize,
    }

    impl DamageSweep {
        /// The three ways a position can leave no readable frame, summed.
        ///
        /// Kept so a reader can still ask the coarse question, but it is a
        /// DERIVED view now rather than the thing that is counted -- the
        /// difference being that the three parts remain available to say WHICH.
        pub fn vanished(&self) -> usize {
            self.pcap_rejected + self.no_flow + self.direction_lost
        }

        /// Every visited position landed in exactly one bucket.
        ///
        /// An invariant of the classifier rather than a property of any capture,
        /// so it holds on every recording and reds if a future arm forgets to
        /// count. Nothing asserted this while the buckets were fused; a dropped
        /// case would simply have made the totals disagree with nobody looking.
        pub fn is_exhaustive(&self) -> bool {
            self.yielded_err + self.vanished() + self.still_clean == self.swept
        }
    }

    /// Flip every byte of one half of a recording in turn and classify what the
    /// dissector does with the result.
    ///
    /// R311y764 (carry N64). Both wire witnesses reject any transport message
    /// that comes back `Err`, and R311y759 measured that TWO hand-picked damage
    /// offsets never reached that arm — one desynchronised a direction into
    /// disappearing, the other landed in a payload and correctly changed
    /// nothing. So the assertion those witnesses exist to make was carried as
    /// unproven: a check nobody has seen fire may be a check that cannot fire,
    /// and then its green is a statement about nothing.
    ///
    /// Two offsets are not an answer to that, so this sweeps the space. It
    /// establishes EXISTENCE and deliberately reports no offset — an offset
    /// would be pinned to one handshake's length and would drift the first time
    /// the foreign implementation changed it.
    ///
    /// `side` is the half to damage, and it should be the FOREIGN one: damaging
    /// wz's own bytes would ask whether wz's decoder objects to wz's encoder,
    /// which is the self-witness this whole harness exists to escape.
    pub fn sweep_single_byte_damage(
        recording: &[(Side, Vec<u8>)],
        side: Side,
        dialer_port: u16,
        listener_port: u16,
    ) -> DamageSweep {
        let mut sweep = DamageSweep::default();
        for seg_index in 0..recording.len() {
            if recording[seg_index].0 != side {
                continue;
            }
            for byte_index in 0..recording[seg_index].1.len() {
                let mut damaged = recording.to_vec();
                damaged[seg_index].1[byte_index] ^= 0xFF;
                sweep.swept += 1;
                let pcap = synthesise_pcap(&damaged, dialer_port, listener_port);
                let Ok(dissection) = wz_capture::Dissection::from_pcap(&pcap) else {
                    sweep.pcap_rejected += 1;
                    continue;
                };
                let flows = dissection.flows();
                let Some(flow) = flows.first() else {
                    sweep.no_flow += 1;
                    continue;
                };
                // The damaged half is whichever direction carries the port the
                // damaged side was synthesised onto. Derived from the flow key
                // for the same reason the witnesses derive their labels: `low`
                // is the lesser endpoint by (addr, port), so with one address
                // it is decided by the two port constants (R311y761).
                let damaged_port = u32::from(match side {
                    Side::FromDialer => dialer_port,
                    Side::FromListener => listener_port,
                });
                let damaged_direction = if flow.flow.low.port == damaged_port {
                    wz_capture::Direction::A
                } else {
                    wz_capture::Direction::B
                };
                let errors = flow.frames.iter().filter(|f| f.frame.is_err()).count();
                let surviving = flow
                    .frames
                    .iter()
                    .filter(|f| f.direction == damaged_direction)
                    .count();
                if errors > 0 {
                    sweep.yielded_err += 1;
                } else if surviving == 0 {
                    sweep.direction_lost += 1;
                } else {
                    sweep.still_clean += 1;
                }
            }
        }
        sweep
    }

    /// Turn a recording into a pcap, preserving forwarding order.
    ///
    /// The two ports are the SYNTHESISED endpoints, not the real ones: the real
    /// dialer port is ephemeral and the proxy sits between, so neither side's
    /// actual port describes the conversation being reconstructed.
    pub fn synthesise_pcap(
        recording: &[(Side, Vec<u8>)],
        dialer_port: u16,
        listener_port: u16,
    ) -> Vec<u8> {
        let packets = synthesise_packets(recording, dialer_port, listener_port);
        let borrowed: Vec<(u32, u32, &[u8])> = packets
            .iter()
            .map(|(s, f, p)| (*s, *f, p.as_slice()))
            .collect();
        wz_capture::pcap::write(wz_capture::link::LINKTYPE_ETHERNET, &borrowed)
    }

    /// R2221 (open-debt item 569) — the PACKETS [`synthesise_pcap`] writes,
    /// before they are written, as `(ts_sec, ts_usec, ethernet frame)`.
    ///
    /// Lifted out of `synthesise_pcap` on its second consumer rather than
    /// copied into it. A live tap door takes PACKETS and not a file
    /// (`wz_dissect_live_push`), so a witness that drives it needs the same
    /// envelope — and a second copy of the envelope rules would drift from this
    /// one the first time either moved, which is exactly what the module docs
    /// say the shared harness exists to prevent. `synthesise_pcap` is now this
    /// function plus the pcap header, so the two witnesses cannot disagree
    /// about what the wire looked like.
    pub fn synthesise_packets(
        recording: &[(Side, Vec<u8>)],
        dialer_port: u16,
        listener_port: u16,
    ) -> Vec<(u32, u32, Vec<u8>)> {
        let mut dialer_seq: u32 = 1;
        let mut listener_seq: u32 = 1;
        let mut packets: Vec<(u32, u32, Vec<u8>)> = Vec::new();
        for (index, (side, bytes)) in recording.iter().enumerate() {
            let pkt = match side {
                Side::FromDialer => {
                    let p = tcp_packet(dialer_port, listener_port, dialer_seq, bytes);
                    dialer_seq = dialer_seq.wrapping_add(bytes.len() as u32);
                    p
                }
                Side::FromListener => {
                    let p = tcp_packet(listener_port, dialer_port, listener_seq, bytes);
                    listener_seq = listener_seq.wrapping_add(bytes.len() as u32);
                    p
                }
            };
            packets.push((1, index as u32, pkt));
        }
        packets
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// R2053 (open-debt item 371) — THE DAMAGE SWEEP'S CLASSIFICATION,
        /// MEASURED IN A LANE THAT ALWAYS RUNS.
        ///
        /// # The two halves of the item
        ///
        /// R311y886 made [`synthesise_pcap`] write REAL checksums, which
        /// changed the sweep's INPUT: a flipped byte now breaks a checksum as
        /// well as a field, so a position can move from "the decoder objected"
        /// to "the capture never parsed". Nobody re-measured the split. And the
        /// only consumer is `zenohd_wire_dissection.rs`, which asserts
        /// `swept > 0` and `yielded_err > 0` — so a move between the other
        /// buckets keeps every assertion green — and it is `#[ignore]`d behind
        /// a real zenohd, so the unmeasured classification sat behind an
        /// interop lane.
        ///
        /// This test answers both. The recording is CRAFTED rather than
        /// captured, from `wz-session-wire-fixtures`' own Init/Open bytes, so
        /// the numbers below are deterministic and this runs in the ordinary
        /// `cargo test -p wz-integration-tests` lane.
        ///
        /// # What is pinned, and what deliberately is not
        ///
        /// The exact per-bucket counts ARE pinned, because on a crafted
        /// recording they are a property of the classifier rather than of a
        /// capture that varies run to run. That is the whole value: a shift
        /// caused by a change to the pcap envelope, the analyzer, or the
        /// classifier reds HERE, with the bucket named, instead of being
        /// absorbed by a `> 0`.
        ///
        /// MEASURED, not predicted — the first run of this test printed the
        /// split and the literals below were written from it.
        #[test]
        fn the_damage_sweeps_classification_is_pinned_on_a_crafted_handshake() {
            use wz_session_wire_fixtures as fixtures;

            const COOKIE: &[u8] = &[0xC0, 0xC1, 0xC2, 0xC3];
            // FRAMED, because the fixtures are BARE messages and this pcap is a
            // TCP stream. zenoh's streamed links prefix every batch with a
            // 16-bit little-endian length; the fixture crate omits it because
            // its own consumers feed a framer directly. Leaving it off decoded
            // to ZERO frames, which the anti-vacuity assertion below caught on
            // the first run -- the framing is stated here rather than assumed.
            let framed = |msg: Vec<u8>| -> Vec<u8> {
                let mut out = Vec::with_capacity(2 + msg.len());
                out.extend_from_slice(&(msg.len() as u16).to_le_bytes());
                out.extend_from_slice(&msg);
                out
            };
            let recording = vec![
                (Side::FromDialer, framed(fixtures::craft_initsyn_wire())),
                (
                    Side::FromListener,
                    framed(fixtures::craft_initack_wire(COOKIE)),
                ),
                (
                    Side::FromDialer,
                    framed(fixtures::craft_opensyn_wire(COOKIE)),
                ),
            ];

            // ANTI-VACUITY BEFORE ANYTHING ELSE: the undamaged recording must
            // dissect into frames, or every classification below is about a
            // capture the analyzer could not read in the first place.
            let clean = synthesise_pcap(&recording, 40_000, 7447);
            let d = wz_capture::Dissection::from_pcap(&clean)
                .expect("the crafted handshake must parse before it is damaged");
            let flows = d.flows();
            assert_eq!(flows.len(), 1, "one crafted conversation is one flow");
            assert!(
                !flows[0].frames.is_empty(),
                "the crafted handshake decoded to NO frames, so a sweep over it \
                 would be classifying nothing"
            );

            for side in [Side::FromDialer, Side::FromListener] {
                let sweep = sweep_single_byte_damage(&recording, side, 40_000, 7447);
                eprintln!("damage sweep over {side:?}: {sweep:?}");
                assert!(
                    sweep.swept > 0,
                    "{side:?}: the sweep visited no byte, so its verdict is \
                     about nothing"
                );
                // THE INVARIANT, which nothing asserted while the three
                // no-frame outcomes were fused into one counter: every visited
                // position lands in exactly one bucket.
                assert!(
                    sweep.is_exhaustive(),
                    "{side:?}: the buckets do not account for every swept \
                     position, so one arm is not counting: {sweep:?}"
                );
            }

            let dialer = sweep_single_byte_damage(&recording, Side::FromDialer, 40_000, 7447);
            let listener = sweep_single_byte_damage(&recording, Side::FromListener, 40_000, 7447);
            assert_eq!(
                (dialer, listener),
                (DIALER_SPLIT, LISTENER_SPLIT),
                "the damage sweep's classification MOVED. This is item 371's \
                 subject: the split is a property of the classifier plus the \
                 pcap envelope plus the analyzer, and until this test existed \
                 the only consumer asserted `yielded_err > 0` -- which stays \
                 green through any rearrangement of the rest. Re-measure, \
                 decide whether the move is intended, and update these literals \
                 in the same round rather than widening the assertion."
            );
        }

        /// The measured split for the dialer's half of the crafted handshake.
        ///
        /// Written from the run's output, not predicted — and the two ZEROS are
        /// the round's finding rather than filler. Item 371 supposed that
        /// R311y886's real checksums may have moved positions into "the capture
        /// never parsed", because a flipped byte now breaks a checksum as well
        /// as a field. It CANNOT: [`sweep_single_byte_damage`] damages the
        /// RECORDING and then calls [`synthesise_pcap`], which computes the IP
        /// and TCP checksums over the damaged bytes. Every pcap it hands the
        /// reader is checksum-clean by construction, so `pcap_rejected` is
        /// structurally zero and `no_flow` with it. The premise was plausible
        /// and is false, and pinning the zeros is what keeps it answered.
        const DIALER_SPLIT: DamageSweep = DamageSweep {
            swept: 22,
            yielded_err: 4,
            pcap_rejected: 0,
            no_flow: 0,
            direction_lost: 3,
            still_clean: 15,
        };
        /// The measured split for the listener's half. See [`DIALER_SPLIT`].
        const LISTENER_SPLIT: DamageSweep = DamageSweep {
            swept: 17,
            yielded_err: 2,
            pcap_rejected: 0,
            no_flow: 0,
            direction_lost: 3,
            still_clean: 12,
        };

        /// R311y888 (open-debt item 363) — THE PCAP THIS MODULE SYNTHESISES IS
        /// CHECKSUM-CLEAN, in both directions.
        ///
        /// # Why this module needed a witness more than most
        ///
        /// Until R311y886 the builder above wrote ZEROS, under a comment
        /// asserting that `wz-capture`'s TCP path did not verify them. It
        /// verifies both axes. So the pcap this harness hands a reader was
        /// corrupt on both of them, the comment is why nobody checked, and the
        /// only assertions in this crate that touch these captures are about
        /// the damage sweep — which classifies OUTCOMES and would read a
        /// wholly-corrupt corpus as its own baseline.
        ///
        /// Two segments, one per direction, because they take different
        /// branches of the builder's port arguments and a pseudo-header built
        /// from the wrong pair is self-consistent and wrong.
        #[test]
        fn the_synthesised_pcap_is_checksum_clean() {
            let recording = vec![
                (Side::FromDialer, b"hello from the dialer".to_vec()),
                (Side::FromListener, b"and the listener".to_vec()),
            ];
            let pcap = synthesise_pcap(&recording, 40_000, 7447);

            let d = wz_capture::Dissection::from_pcap(&pcap).expect("the pcap parses");
            let h = d.health();
            assert_eq!(
                (h.ip_checksum_invalid, h.transport_checksum_invalid),
                (0, 0),
                "a harness that synthesises a corrupt capture makes every \
                 finding read against it suspect"
            );
            assert_eq!(
                (h.ip_checksum_valid, h.transport_checksum_valid),
                (2, 2),
                "and BOTH directions must have been verified on BOTH axes, or \
                 the zeros above say only that nothing was checked"
            );
        }
    }
}

/// R2048 — how a walked extension entry becomes an assertable row, in ONE
/// place.
///
/// # Why this is in the library and not in each witness
///
/// Three foreign-witness tests read a capture the same way: walk every
/// transport message, find every `ext` entry, attribute it to the message that
/// CARRIED it, and flatten what the walker made of its body into something an
/// assertion can hold a value against. Each had its own copy, and the copies
/// had already diverged the way copies do — R2046 found that `Field::find` is
/// depth-first and hands back a SUB-EXTENSION's `value` for a walked body,
/// fixed it in one file, and left the same call standing in another. Worse,
/// the file it was left in carries a doc comment ARGUING the lookup is safe:
/// true of `ext_name`, which `walk_ext_entry` pushes ahead of the body, and
/// false of `value`, which a walked body does not push at all.
///
/// Same reasoning as [`wire_tap`]: the envelope rules are one fact, and two
/// copies of them drift the moment one witness needs something the other does
/// not.
pub mod ext_bodies {
    use wz_session_core::dissect::{Field, FieldValue};
    use wz_session_core::passive::Direction;

    /// The `encoding` bits of an extension entry, as `walk_ext_entry` reports
    /// them: a UNIT body has none, a Z64 body is one VLE, a ZBuf body is a
    /// length and that many bytes.
    pub const ENC_UNIT: u64 = 0;
    /// See [`ENC_UNIT`].
    pub const ENC_Z64: u64 = 1;
    /// See [`ENC_UNIT`].
    pub const ENC_ZBUF: u64 = 2;

    // R2223 (open-debt item 573) — `MESSAGE_NAMES` LIVED HERE AND IS GONE.
    //
    // It was fourteen words with a doc claiming to be "every transport MID
    // (`wire_const::T_MID_*`) plus every network one, checked against them
    // rather than extended by one", and NOTHING in the tree checked it. That
    // sentence was written by the round that repaired R2050's missing `Join`;
    // it described the intention and no mechanism, so the next drift would have
    // been as silent as that one.
    //
    // Two defects, and the second is why the repair is a move and not a test.
    // This crate is `publish = false`, so the only vocabulary of message names
    // this workspace held was one no consumer could reach — while a consuming
    // surface splitting traffic by message had to write its own list by hand.
    // The words now live in `wz_session_core::dissect::MessageName`, are
    // declared to a C consumer as the field document's `message` family, and
    // are held to what BOTH dispatchers do with all thirty-two values a MID can
    // take by `the_message_vocabulary_is_the_one_the_dispatchers_produce`.

    /// The fields `walk_ext_entry` pushes for EVERY entry whatever the body —
    /// the envelope, not a reading of it.
    ///
    /// Excluded from [`Body::read`] so that an empty `read` means "this body
    /// got no walker output", a claim more than one witness rests on. `value`
    /// is excluded here and surfaced separately as [`Body::value`], because for
    /// a SCALAR body the value IS the whole reading while for a walked one it
    /// is the span the reading stands in for.
    pub const ENVELOPE: &[&str] = &[
        "header",
        "ext_id",
        "m",
        "encoding",
        "z",
        "ext_name",
        "value",
        "value_len",
    ];

    /// One reading a walker produced.
    ///
    /// [`Group`](Reading::Group) exists so that "the body was walked into a
    /// subtree" and "the body got no walker at all" are DIFFERENT entries
    /// rather than two ways of contributing nothing.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Reading {
        /// A name this build resolved from the bits (`"Block"`, `"AllComplete"`).
        Label(String),
        /// A single bit (`express`, `complete`, `absent_to_receiver`).
        Flag(bool),
        /// A number (`distance`, `read_as`, a scalar Z64 body).
        Number(u64),
        /// Raw bytes — how `user`, `hmac` and a public key's limbs come back.
        Bytes(Vec<u8>),
        /// Text a walker resolved.
        Text(String),
        /// A walked sub-structure and its child count.
        Group(usize),
    }

    impl core::fmt::Display for Reading {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Reading::Label(v) => write!(f, "{v}"),
                Reading::Flag(v) => write!(f, "{v}"),
                Reading::Number(v) => write!(f, "{v}"),
                // Rendered as text when it is text, because `user` is and a
                // failure message naming it in hex would be unreadable.
                Reading::Bytes(v) => match core::str::from_utf8(v) {
                    Ok(s) if !s.is_empty() && s.chars().all(|c| !c.is_control()) => {
                        write!(f, "{s:?}")
                    }
                    _ => write!(f, "<{} byte(s)>", v.len()),
                },
                Reading::Text(v) => write!(f, "{v:?}"),
                Reading::Group(n) => write!(f, "<{n} field(s)>"),
            }
        }
    }

    impl Reading {
        /// The reading a field carries, or `None` for an opaque one.
        pub fn of(field: &Field) -> Option<Reading> {
            match &field.value {
                FieldValue::Label(v) => Some(Reading::Label(v.to_string())),
                FieldValue::Flag(v) => Some(Reading::Flag(*v)),
                FieldValue::Bits(v) | FieldValue::Uint(v) => Some(Reading::Number(*v)),
                FieldValue::Bytes(v) => Some(Reading::Bytes(v.clone())),
                FieldValue::Text(v) => Some(Reading::Text(v.to_string())),
                FieldValue::Nested(children) => Some(Reading::Group(children.len())),
                FieldValue::Opaque => None,
            }
        }
    }

    /// How far under an entry [`Body::read`] reaches.
    ///
    /// Not a preference: the two answers are about different subjects. An auth
    /// method body is a GROUP whose assertable fields (`user`, `hmac`) are its
    /// children, so a one-level fold reports `usrpwd=<4 field(s)>` and has
    /// nothing to hold against a username. A Z64 witness wants the opposite —
    /// one level, so a nested chain's readings do not appear to belong to the
    /// entry above them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Depth {
        /// This entry's own children only.
        Shallow,
        /// Every reading below the envelope, at any depth, EXCLUDING nested
        /// `ext` entries — those become rows of their own.
        Deep,
    }

    /// One extension body the capture carried, flattened for assertion.
    #[derive(Debug, Clone)]
    pub struct Body {
        /// Which half wrote it.
        pub direction: Direction,
        /// The message that carried it — the innermost group the published
        /// message vocabulary (`wz_session_core::dissect::MessageName`) names.
        pub carrier: String,
        /// `ext_name`: which row of `wz_session_core::ext_name`'s table this is.
        pub name: String,
        /// The entry's `encoding` bits. Kept OUT of [`Self::read`] because it
        /// is envelope rather than a reading — but kept, because one id can
        /// carry three of them across a handshake and that is assertable.
        pub encoding: Option<u64>,
        /// The entry's OWN `value`, when the walk left one standing.
        ///
        /// A scalar body has no walked group and the value IS its whole
        /// reading; a walked body's `value` is replaced by the group. Read with
        /// [`own_child`] and never with `Field::find` — see
        /// [`assert_no_entry_borrows_a_descendants_value`].
        pub value: Option<Reading>,
        /// What the walker made of the body, minus [`ENVELOPE`].
        pub read: Vec<(String, Reading)>,
    }

    impl Body {
        /// The first reading under this entry with this name.
        pub fn reading(&self, name: &str) -> Option<&Reading> {
            self.read.iter().find(|(n, _)| n == name).map(|(_, v)| v)
        }

        /// Every reading name under this entry, in tree order.
        pub fn read_names(&self) -> Vec<&str> {
            self.read.iter().map(|(n, _)| n.as_str()).collect()
        }

        /// One line naming this row and everything it carries.
        pub fn describe(&self) -> String {
            let read = self
                .read
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join(", ");
            let value = match &self.value {
                Some(v) => format!(" value={v}"),
                None => String::new(),
            };
            format!(
                "{:?} {}/{} enc={:?}{value} read=[{read}]",
                self.direction, self.carrier, self.name, self.encoding
            )
        }
    }

    /// This entry's OWN child by name — NOT `Field::find`, which is depth-first
    /// and RECURSIVE.
    ///
    /// R2046. The difference is silent for `ext_name` and `encoding`, which
    /// `walk_ext_entry` pushes before any body so the direct child wins the
    /// search by accident of ordering. It is not silent for `value`: a walked
    /// ZBuf body has no direct `value` at all, so a recursive search descends
    /// into the body and returns a SUB-EXTENSION's number. An `auth` chain then
    /// reports its first method's value as its own.
    pub fn own_child<'f>(field: &'f Field, name: &str) -> Option<&'f Field> {
        match &field.value {
            FieldValue::Nested(children) => children.iter().find(|c| c.name == name),
            _ => None,
        }
    }

    fn fold_deep(field: &Field, out: &mut Vec<(String, Reading)>) {
        if let FieldValue::Nested(children) = &field.value {
            for child in children {
                if ENVELOPE.contains(&child.name.as_ref()) {
                    continue;
                }
                // A nested `ext` is a sub-extension: `collect` gives it its own
                // row, so folding it here too would report it twice.
                if child.name == "ext" || child.name == "extensions" {
                    continue;
                }
                if let Some(r) = Reading::of(child) {
                    out.push((child.name.to_string(), r));
                }
                fold_deep(child, out);
            }
        }
    }

    fn fold_shallow(field: &Field) -> Vec<(String, Reading)> {
        match &field.value {
            FieldValue::Nested(children) => children
                .iter()
                .filter(|c| !ENVELOPE.contains(&c.name.as_ref()))
                .filter_map(|c| Reading::of(c).map(|r| (c.name.to_string(), r)))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Collect every `ext` entry under `field`, attributing each to the
    /// innermost enclosing message group.
    pub fn collect(
        field: &Field,
        direction: Direction,
        carrier: &str,
        depth: Depth,
        out: &mut Vec<Body>,
    ) {
        // R2223 (item 573) — asked of the PUBLISHED vocabulary. The local list
        // this used to test against is gone; see the comment where it stood.
        let carrier = match wz_session_core::dissect::MessageName::named(&field.name) {
            Some(message) => message.name(),
            None => carrier,
        };
        if field.name == "ext" {
            if let Some(FieldValue::Label(name)) = own_child(field, "ext_name").map(|f| &f.value) {
                let read = match depth {
                    Depth::Shallow => fold_shallow(field),
                    Depth::Deep => {
                        let mut acc = Vec::new();
                        fold_deep(field, &mut acc);
                        acc
                    }
                };
                out.push(Body {
                    direction,
                    carrier: carrier.to_string(),
                    name: name.to_string(),
                    encoding: match own_child(field, "encoding").map(|f| &f.value) {
                        Some(FieldValue::Bits(v)) | Some(FieldValue::Uint(v)) => Some(*v),
                        _ => None,
                    },
                    value: own_child(field, "value").and_then(Reading::of),
                    read,
                });
            }
        }
        if let FieldValue::Nested(children) = &field.value {
            for child in children {
                collect(child, direction, carrier, depth, out);
            }
        }
    }

    /// Walk every message of `flow` and collect its extension bodies.
    ///
    /// A message whose bytes cannot be sliced or whose walk fails is SKIPPED
    /// rather than reported. The set assertion each witness makes is what stops
    /// a silent skip from emptying the capture: a walk that failed everywhere
    /// yields an empty set and reds there.
    pub fn bodies_of(flow: &wz_capture::FlowDissection, depth: Depth) -> Vec<Body> {
        let mut out = Vec::new();
        for frame in flow.frames.iter() {
            let Ok(bytes) = flow.message_bytes(frame) else {
                continue;
            };
            let Ok(walked) = wz_session_core::dissect::dissect_transport_message(bytes, 0) else {
                continue;
            };
            collect(&walked, frame.direction, "?", depth, &mut out);
        }
        out
    }

    /// Every row, one per line.
    pub fn dump(bodies: &[Body]) -> String {
        bodies
            .iter()
            .map(|b| format!("  {}", b.describe()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The SET of `ext_name`s this capture carried, held against a claim, BOTH
    /// ways.
    ///
    /// Asserted before any claim about a reading: a body that vanished leaves
    /// an assertion about nothing, and a body that APPEARED is a foreign
    /// reading going unjudged. `witnessed` must be sorted and deduplicated.
    pub fn assert_witnessed_set(bodies: &[Body], witnessed: &[&str], what: &str) {
        let mut seen: Vec<&str> = bodies.iter().map(|b| b.name.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen,
            witnessed,
            "the extension bodies {what} are not the set that file asserts. A \
             difference either way means an assertion below is about nothing, \
             or a foreign reading is going unjudged. Whole capture:\n{}",
            dump(bodies)
        );
    }

    /// NO ENTRY IS CREDITED WITH A DESCENDANT'S NUMBER.
    ///
    /// R2046. Surfacing [`Body::value`] made a witness able to say what a
    /// scalar body holds, and in the same stroke able to say something FALSE:
    /// the obvious way to fetch that field is `Field::find`, which is
    /// depth-first, and an `auth` entry's body is a CHAIN whose members have
    /// values of their own.
    ///
    /// The rule is exact rather than approximate, and reads off
    /// `walk_ext_entry`:
    ///
    /// * ENC_UNIT — no body bytes exist at all, so ANY value is borrowed.
    /// * ENC_ZBUF, walked — `fields.push(walked.unwrap_or(value))` pushes
    ///   exactly one of the two, so a walked body leaves no `value` behind.
    /// * ENC_ZBUF not walked / ENC_Z64 — a value of its own is exactly right,
    ///   and these rows are why the rule is not "no row has a value".
    pub fn assert_no_entry_borrows_a_descendants_value(bodies: &[Body]) {
        let walked = |b: &Body| {
            b.read
                .iter()
                .any(|(n, r)| n == &b.name && matches!(r, Reading::Group(_)))
        };
        let mut swept = 0usize;
        for body in bodies {
            let why = if body.encoding == Some(ENC_UNIT) {
                "a UNIT extension has no body bytes at all"
            } else if body.encoding == Some(ENC_ZBUF) && walked(body) {
                "a walked ZBuf body replaces the entry's `value` rather than \
                 standing beside it"
            } else {
                continue;
            };
            swept += 1;
            assert!(
                body.value.is_none(),
                "this entry reports a value it cannot own -- {why}. The number \
                 belongs to something BELOW it, which means the lookup that \
                 fetched it descended out of the entry:\n  {}\nwhole \
                 capture:\n{}",
                body.describe(),
                dump(bodies)
            );
        }
        // A rule that sweeps nothing is green for the wrong reason.
        assert!(
            swept >= 2,
            "only {swept} row(s) of this capture could carry a borrowed value, \
             so the rule above is close to vacuous:\n{}",
            dump(bodies)
        );
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use wz_session_core::dissect::Span;

        fn f(name: &'static str, value: FieldValue) -> Field {
            Field {
                name: name.into(),
                span: Span { start: 0, end: 1 },
                value,
            }
        }

        /// R2061 (open-debt item 483) — the `own_child` fix, held down WITHOUT
        /// an oracle.
        ///
        /// # Why this had to be written
        ///
        /// R2046 found `Field::find` handing an ext entry a DESCENDANT's
        /// `value` — an `auth` chain reporting its first method's nonce as its
        /// own — and R2048 lifted the fix into [`own_child`]. Measured in R2061:
        /// reverting [`collect`] to the recursive `find` reds NOTHING in this
        /// crate's library tests and NOTHING in the Z64 foreign witness. The
        /// only thing that catches it is a capture carrying a nested chain,
        /// which is the auth witness, which is a gated e2e behind three foreign
        /// binaries.
        ///
        /// So the fix that this whole item is about was defended by an oracle
        /// and by nothing else. This test is the deterministic half: a
        /// hand-built entry whose walked body contains a nested entry with its
        /// own `value`, which is exactly the shape `find` descends into.
        #[test]
        fn an_entrys_own_value_is_never_a_nested_entrys() {
            // The inner entry: a Z64 body standing beside its own `value`.
            let inner = f(
                "ext",
                FieldValue::Nested(vec![
                    f("ext_name", FieldValue::Label("usrpwd".into())),
                    f("encoding", FieldValue::Bits(ENC_Z64)),
                    f("value", FieldValue::Uint(0x0BAD_F00D)),
                ]),
            );
            // The outer entry: a WALKED ZBuf body, so it has no `value` of its
            // own -- the walked group replaced it -- and the only `value`
            // anywhere below it belongs to `inner`.
            let outer = f(
                "ext",
                FieldValue::Nested(vec![
                    f("ext_name", FieldValue::Label("auth".into())),
                    f("encoding", FieldValue::Bits(ENC_ZBUF)),
                    f("auth", FieldValue::Nested(vec![inner])),
                ]),
            );
            let carrier = f("Init", FieldValue::Nested(vec![outer]));

            let mut bodies = Vec::new();
            collect(&carrier, Direction::A, "?", Depth::Shallow, &mut bodies);

            // ANTI-VACUITY: both entries must have been collected, or the
            // assertion below is about a tree the walk never entered.
            let names: Vec<&str> = bodies.iter().map(|b| b.name.as_str()).collect();
            assert_eq!(names, vec!["auth", "usrpwd"], "both entries: {names:?}");

            let auth = &bodies[0];
            assert!(
                auth.value.is_none(),
                "the outer entry's body was WALKED, so it owns no `value`; this \
                 one borrowed {:?} from the entry below it",
                auth.value
            );
            assert_eq!(
                bodies[1].value,
                Some(Reading::Number(0x0BAD_F00D)),
                "and the inner entry must still report its own"
            );
        }
    }
}

/// R2227 (open-debt item 575) — a SECOND reader over a recorded batch's
/// FRAGMENT extension chain, and the control group that keeps its negatives
/// meaningful.
///
/// ## Why a second reader at all
///
/// `tests/wz_chain_drop_zenohd_interop.rs` measures what a genuine `zenohd`
/// puts on the wire when it abandons a fragment chain, and its headline is that
/// the `0x3 Drop` marker is NOT there. Asking wz's own dissector would make the
/// census vouch for itself, so the walk here is written against upstream's
/// extension envelope directly — `[Z|ENC(2)|ID(5)]`, whose body shape the ENC
/// bits give — which both implementations encode identically.
///
/// ## Why it lives in the lib rather than beside the leg that uses it
///
/// Because its control group has to RUN, and in that file it could not. Layer
/// C0 requires `#[ignore]` of every `#[test]` in a binary-dep fixture, and
/// Layer Z runs those with `-- --ignored`, which selects an un-ignored one
/// never — so a control group written next to the leg would be gated out of the
/// default lane by C0 and out of Z by the flag. That is R311y479's "a witness in
/// no lane" class, and this module takes the same repair a prior round took for
/// `the_stalled_message_offers_hypotheses_rather_than_a_verdict`: the assertion
/// moved to the lib, where it needs no zenohd, no demo and no socket, and
/// `cargo test --workspace` reaches it.
///
/// ## What the control group is FOR
///
/// The leg's finding is a ZERO. A walk that structurally cannot reach `0x3`
/// reports exactly the same zero as a wire that does not carry one, so without
/// a control group the leg's conclusion would rest on this reader rather than
/// on the router. MEASURED, and it corrected the guess that prompted it: the
/// defect that survives every assertion the leg was filed with is a narrowed ID
/// MASK, not a reordered chain walk. Reordering takes `first_marked` down too —
/// upstream never writes First and Drop on one batch, so both are last on
/// theirs — and the leg's own `first_marked >= 1` precondition reds on it. With
/// `EXT_MID_MASK` narrowed to `0x1E` instead, `0x2` still matches itself while
/// `0x3` folds onto it and can never match: both arms keep `first_marked` (1
/// and 7), both keep `drop_marked == 0`, every pre-existing assertion passes,
/// and only `drop_reader_alive_on` reds.
pub mod fragment_ext {
    use super::wire_tap::Side;

    /// `[Z|ENC(2)|ID(5)]` — the ext envelope's id field, upstream's
    /// `iext::EID_MASK` (`commons/zenoh-protocol/src/common/extension.rs`).
    pub const EXT_MID_MASK: u8 = 0x1F;
    /// The "another ext follows" bit, upstream's `iext::FLAG_Z`. The LAST ext in
    /// a chain has it CLEAR, which is why [`fragment_ext_offset`] tests `wanted`
    /// BEFORE it tests this.
    pub const EXT_Z_FLAG: u8 = 0x80;
    /// The two encoding bits that say how long the ext body is.
    pub const EXT_ENC_MASK: u8 = 0x60;

    /// The fragment ext ids upstream defines, from
    /// `commons/zenoh-protocol/src/transport/fragment.rs:94-97`.
    pub const EXT_ID_FIRST: u8 = 0x2;
    /// The chain-abandon marker. See [`EXT_ID_FIRST`].
    pub const EXT_ID_DROP: u8 = 0x3;

    /// Read a batch's fragment ext chain and report WHERE `wanted` sits in it —
    /// the index of its envelope byte, or `None`.
    ///
    /// Takes the batch WITHOUT its `[u16 LE len]` frame.
    ///
    /// Returns `None` for anything it cannot walk, including a reserved
    /// encoding: a skip it cannot compute would put the cursor somewhere
    /// arbitrary, and a marker "found" there means nothing.
    ///
    /// ⚠ IT RETURNS AN OFFSET RATHER THAN A BOOL SO THE READER CAN BE MUTATED
    /// ON THE ROUTER'S OWN BYTES — see [`drop_reader_alive_on`].
    ///
    /// ⚠ THE ORDER OF THE TWO TESTS IN THE LOOP IS LOAD-BEARING. Upstream
    /// writes `ext_drop` LAST (`commons/zenoh-codec/src/transport/fragment.rs:65-76`
    /// — QoS, then First, then Drop), so the Drop envelope is the one whose `Z`
    /// bit is clear and testing `Z` first makes `0x3` undiscoverable.
    pub fn fragment_ext_offset(batch: &[u8], fragment_mid: u8, wanted: u8) -> Option<usize> {
        let &header = batch.first()?;
        if header & EXT_MID_MASK != fragment_mid || header & EXT_Z_FLAG == 0 {
            return None;
        }
        // `[header][VLE(sn)][ext chain]`.
        let mut at = skip_vle(batch, 1)?;
        loop {
            let &ext = batch.get(at)?;
            let envelope = at;
            at += 1;
            if ext & EXT_MID_MASK == wanted {
                return Some(envelope);
            }
            at = match (ext & EXT_ENC_MASK) >> 5 {
                // unit: the ext IS its own value, no body follows
                0 => at,
                // z64: one VLE
                1 => skip_vle(batch, at)?,
                // zbuf: a VLE length and that many bytes
                2 => {
                    let next = skip_vle(batch, at)?;
                    let (len, _) = read_vle_at(batch, at)?;
                    next + len as usize
                }
                _ => return None,
            };
            if ext & EXT_Z_FLAG == 0 {
                return None;
            }
        }
    }

    /// Whether `wanted` is in the batch's fragment ext chain.
    pub fn fragment_ext_present(batch: &[u8], fragment_mid: u8, wanted: u8) -> bool {
        fragment_ext_offset(batch, fragment_mid, wanted).is_some()
    }

    fn read_vle_at(bytes: &[u8], mut at: usize) -> Option<(u64, usize)> {
        let mut value = 0u64;
        let mut shift = 0u32;
        while let Some(&byte) = bytes.get(at) {
            at += 1;
            value |= u64::from(byte & 0x7F) << shift;
            if byte < 0x80 {
                return Some((value, at));
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        None
    }

    fn skip_vle(bytes: &[u8], at: usize) -> Option<usize> {
        read_vle_at(bytes, at).map(|(_, next)| next)
    }

    /// How many recorded batches on the LISTENER's direction carry `wanted`.
    ///
    /// Segments arrive `[u16 LE len][batch]`, which is why the walk starts at
    /// byte 2.
    pub fn ext_marked_batches(
        recording: &[(Side, Vec<u8>)],
        fragment_mid: u8,
        wanted: u8,
    ) -> usize {
        ext_marked_batches_from(recording, Side::FromListener, fragment_mid, wanted)
    }

    /// R2238 (open-debt item 580) — the same walk over EITHER direction.
    ///
    /// [`ext_marked_batches`] pins the listener's side because its callers ask
    /// about a foreign ROUTER's transmit path. A leg asking what wz itself put
    /// on the wire needs [`Side::FromDialer`], and pointing the existing
    /// helper at a direction it does not serve would be a silent zero — the
    /// "a dead probe and a negative result look the same" shape this tree
    /// keeps paying for. So the direction becomes an argument and the old
    /// name stays as the listener-side wrapper its callers already read.
    pub fn ext_marked_batches_from(
        recording: &[(Side, Vec<u8>)],
        side: Side,
        fragment_mid: u8,
        wanted: u8,
    ) -> usize {
        recording
            .iter()
            .filter(|(s, _)| *s == side)
            .filter(|(_, segment)| {
                segment.len() > 2 && fragment_ext_present(&segment[2..], fragment_mid, wanted)
            })
            .count()
    }

    /// Take a batch the LISTENER really wrote that carries ext `0x2`, re-label
    /// that one envelope byte `0x3`, and report whether the same walk then
    /// finds it.
    ///
    /// This is the anti-vacuity half of a `drop_marked == 0` reading, taken on
    /// the arm's OWN bytes rather than on a shape a fixture invented. `None`
    /// when the recording carries no `0x2` batch at all — a caller that has
    /// already required a chain START has excluded that.
    ///
    /// One byte differs from what upstream WOULD have sent had its encode
    /// survived: its Drop batch is its First batch's envelope with `0x2`
    /// replaced by `0x3`, both being `zextunit!` bodies
    /// (`commons/zenoh-protocol/src/transport/fragment.rs:94-97`). So this is
    /// not a synthesised marker standing in for a genuine one — it is the
    /// genuine chain-start batch, re-labelled, and it asserts about the READER
    /// only. What crossed the wire is still what `ext_marked_batches` says.
    pub fn drop_reader_alive_on(recording: &[(Side, Vec<u8>)], fragment_mid: u8) -> Option<bool> {
        let (_, segment) = recording.iter().find(|(side, segment)| {
            *side == Side::FromListener
                && segment.len() > 2
                && fragment_ext_present(&segment[2..], fragment_mid, EXT_ID_FIRST)
        })?;
        let batch = &segment[2..];
        let at = fragment_ext_offset(batch, fragment_mid, EXT_ID_FIRST)?;
        let mut relabelled = batch.to_vec();
        // Only the id field moves; `Z` and the encoding bits stay as the writer
        // wrote them, which is what makes this the batch upstream WOULD have
        // sent.
        relabelled[at] = (relabelled[at] & !EXT_MID_MASK) | EXT_ID_DROP;
        Some(fragment_ext_present(&relabelled, fragment_mid, EXT_ID_DROP))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// `id::FRAGMENT` at zenoh 1.5.0, and `wz_codecs::wire_const::T_MID_FRAGMENT`.
        /// Passed in rather than imported so this module carries no dependency
        /// on a codec crate for a single byte.
        const FRAGMENT_MID: u8 = 0x06;

        /// ⚠ THE BYTES BELOW ARE WRITTEN AS LITERALS ON PURPOSE. Assembling
        /// them from `EXT_Z_FLAG` / `EXT_ENC_MASK` / `EXT_MID_MASK` would build
        /// the fixture out of the very constants under test, and a walk that
        /// mis-defines one would then be checked against a fixture that
        /// mis-defines it the same way — the "a table compared against its own
        /// length" trap. Each literal is spelled out against upstream's
        /// definition on the line that uses it.
        ///
        /// `FRAGMENT` with the `Z` flag set: `id::FRAGMENT | flag::Z`
        /// (`commons/zenoh-protocol/src/transport/fragment.rs:19-22` for
        /// `Z == 1 << 7`).
        const HEADER_Z: u8 = 0x86;
        /// The same header WITHOUT `Z`, so no ext chain follows it.
        const HEADER_NO_Z: u8 = 0x06;
        /// A one-byte VLE carrying sn 7 — any value below 0x80 encodes as itself.
        const SN: u8 = 0x07;

        /// The literal headers must stay the message id the walk tests against;
        /// if they diverged, every fixture below would be walking a message the
        /// reader rejects and would go green by rejecting it.
        #[test]
        fn the_fixture_header_is_the_fragment_message_id() {
            assert_eq!(HEADER_Z & 0x1F, FRAGMENT_MID);
            assert_eq!(HEADER_NO_Z & 0x1F, FRAGMENT_MID);
        }

        /// THE ONE THAT MATTERS. Upstream writes `ext_drop` LAST, and the last
        /// ext in a chain carries `Z == 0`. So the Drop envelope is `0x03`: unit
        /// encoding (`zextunit!(0x3, false)`,
        /// `commons/zenoh-protocol/src/transport/fragment.rs:97`), id 3, `Z`
        /// clear.
        #[test]
        fn reader_finds_a_drop_that_is_the_last_ext() {
            let batch = [HEADER_Z, SN, 0x03];
            assert!(
                fragment_ext_present(&batch, FRAGMENT_MID, EXT_ID_DROP),
                "the walk did not find a `0x3 Drop` that is the chain's LAST \
                 ext, which is the only position upstream ever writes it in"
            );
            assert_eq!(
                fragment_ext_offset(&batch, FRAGMENT_MID, EXT_ID_DROP),
                Some(2)
            );
        }

        /// Drop behind a `z64` ext, which is where it lands when the writer's
        /// QoS is not `DEFAULT`: `0xA1` is `Z | ENC(z64) | id 1`
        /// (`QoS = zextz64!(0x1, true)`), its body one VLE, then `0x03`.
        #[test]
        fn reader_finds_a_drop_after_a_z64_ext() {
            let batch = [HEADER_Z, SN, 0xA1, 0x00, 0x03];
            assert!(
                fragment_ext_present(&batch, FRAGMENT_MID, EXT_ID_DROP),
                "the walk lost the chain skipping a z64 ext body, so a Drop \
                 behind a non-default QoS would never be counted"
            );
            assert_eq!(
                fragment_ext_offset(&batch, FRAGMENT_MID, EXT_ID_DROP),
                Some(4)
            );
        }

        /// Drop behind a `unit` ext: `0x82` is `Z | ENC(unit) | id 2`, no body,
        /// then `0x03`. Upstream never writes First and Drop on the same batch
        /// — the emit site is the `else` of `if fragment.ext_first.is_some()` —
        /// but the walk's unit-skip is exercised by nothing else, and an
        /// off-by-one there is the second way a `0x3` goes missing.
        #[test]
        fn reader_finds_a_drop_after_a_unit_ext() {
            let batch = [HEADER_Z, SN, 0x82, 0x03];
            assert!(
                fragment_ext_present(&batch, FRAGMENT_MID, EXT_ID_DROP),
                "the walk lost the chain skipping a unit ext, so a Drop behind \
                 one would never be counted"
            );
            assert_eq!(
                fragment_ext_offset(&batch, FRAGMENT_MID, EXT_ID_DROP),
                Some(3)
            );
        }

        /// THE NARROWING CONTROL. The three arms above would all pass a walk
        /// that ignored `wanted` and returned the first envelope it reached.
        /// These say the id is actually compared.
        #[test]
        fn reader_does_not_report_a_drop_that_is_absent() {
            let first_only = [HEADER_Z, SN, 0x02];
            assert!(
                fragment_ext_present(&first_only, FRAGMENT_MID, EXT_ID_FIRST),
                "the walk did not find the `0x2 First` that IS on this batch"
            );
            assert!(
                !fragment_ext_present(&first_only, FRAGMENT_MID, EXT_ID_DROP),
                "the walk reported a `0x3 Drop` on a batch carrying only \
                 `0x2 First`, so it is not comparing the id at all"
            );
            let qos_only = [HEADER_Z, SN, 0x21, 0x00];
            assert!(
                !fragment_ext_present(&qos_only, FRAGMENT_MID, EXT_ID_DROP),
                "the walk reported a `0x3 Drop` on a batch carrying only a QoS ext"
            );
        }

        /// A header without `Z` has no ext chain at all, and a walk that read
        /// one anyway would be reading the fragment PAYLOAD as envelopes —
        /// where a `0x03` byte occurs constantly. That is the direction that
        /// would make a RED look like upstream had been fixed.
        #[test]
        fn reader_refuses_a_batch_whose_header_declares_no_exts() {
            let batch = [HEADER_NO_Z, SN, 0x03];
            assert!(
                !fragment_ext_present(&batch, FRAGMENT_MID, EXT_ID_DROP),
                "the walk read an ext chain off a header that declares none, so \
                 it is reading payload bytes as envelopes"
            );
        }

        /// A chain that promises another ext and ends is not a chain the walk
        /// may guess at — nothing found, rather than a marker found past the
        /// end.
        #[test]
        fn reader_refuses_a_truncated_chain() {
            let batch = [HEADER_Z, SN, 0x82];
            assert!(
                !fragment_ext_present(&batch, FRAGMENT_MID, EXT_ID_DROP),
                "the walk found something past the end of a truncated ext chain"
            );
        }

        /// A recorded segment carries its `[u16 LE len]` frame, and the walk
        /// starts past it. A reader that forgot the frame would find the length
        /// bytes where the header belongs.
        fn framed(batch: &[u8]) -> Vec<u8> {
            let mut out = (batch.len() as u16).to_le_bytes().to_vec();
            out.extend_from_slice(batch);
            out
        }

        /// The re-labelling probe finds a Drop where the router wrote a First,
        /// and reports the DIALLER's batches as no evidence at all — the
        /// direction matters, because only the listener is the router here.
        #[test]
        fn the_relabelling_probe_is_alive_on_a_listener_first_batch() {
            let recording = vec![
                (Side::FromDialer, framed(&[HEADER_Z, SN, 0x02])),
                (Side::FromListener, framed(&[HEADER_Z, SN, 0x02])),
            ];
            assert_eq!(
                drop_reader_alive_on(&recording, FRAGMENT_MID),
                Some(true),
                "re-labelling a listener's `0x2 First` envelope to `0x3` did \
                 not make the walk find it"
            );
            let dialler_only = vec![(Side::FromDialer, framed(&[HEADER_Z, SN, 0x02]))];
            assert_eq!(
                drop_reader_alive_on(&dialler_only, FRAGMENT_MID),
                None,
                "a `0x2` on the DIALLER's side was accepted as the router's"
            );
        }

        /// And it reports `None` — not `Some(false)` — when there is no chain
        /// start to re-label. The two are different findings: `None` says the
        /// probe had no subject, `Some(false)` says the reader is broken, and
        /// collapsing them would let an arm that never fragmented read as one
        /// whose reader is dead.
        #[test]
        fn the_relabelling_probe_reports_no_subject_rather_than_a_failure() {
            let no_chain = vec![(Side::FromListener, framed(&[HEADER_Z, SN, 0x21, 0x00]))];
            assert_eq!(drop_reader_alive_on(&no_chain, FRAGMENT_MID), None);
        }
    }
}
