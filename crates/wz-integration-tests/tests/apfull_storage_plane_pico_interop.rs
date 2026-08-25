// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y496 — the §5.24 STORAGE plane COMPOSED on the AP-full binary, witnessed
//! end-to-end by a real zenoh-pico: pico CONFIGURES a storage, pico WRITES to it,
//! and a later pico READS its own write back out of it.
//!
//! ## What was missing, and it was not coverage
//!
//! `storage-mgr-multi-storage-host` (y362), `adminspace-config-hotreload` (y277)
//! and the filesystem volume (y282) each already had a witness. What none of them
//! had is the plane on the KITCHEN-SINK binary, and the reason is the same one
//! R311y488/y489/y491 found one plane over: `wz/preset-ap-full` carried four of
//! the seventeen §5.11/§5.24 storage atoms — `storage-backend`, `-aligner`,
//! `-history`, `-replication` — while the whole storage MANAGER
//! (`storage-mgr-*`, seven atoms) and every backend implementation
//! (`storage-backend-filesystem`, `-memory-volume`, `-volume-trait`,
//! `-capability`) were compiled OUT. The preset's own header comment claimed
//! "all storage".
//!
//! ## The defect that membership hid
//!
//! `run_storage_host` binds once and accepts one pico one-shot at a time, so a
//! `z_put` and a `z_get` are DIFFERENT sessions. A storage was spawned by
//! `add_storage(&session, ..)` on whichever transient client session happened to
//! carry the `storage-add`, and its capture subscriber and queryable died with
//! that session. The run-mode's own doc named this: the storage stayed
//! STATE-observable (`storage_manager` reported `Started`) but served no data
//! across the session boundary. So the admin plane could say a storage was live
//! while the storage plane could not answer a single foreign read.
//!
//! R311y496 makes the split explicit instead: a hosted storage's DATA lives in
//! the shared `StorageState` over its volume-created backend, and its subscriber
//! and queryable are a PER-SESSION BINDING that `RuntimeStorageManager::rebind_all`
//! re-establishes on every accepted client. Leg 1 is the guard for exactly that,
//! and it FAILED before the change (no reply at all for the key pico had written).
//!
//! ## Why the durability pair is a pair
//!
//! Leg 2 kills the host and brings it back on the same `--storage-host-dir`, and
//! pico still reads its value: that is `storage-backend-filesystem`'s claim, and
//! it is the atom the preset held back. Leg 3 runs the SAME script with the flag
//! absent and requires the value GONE. Without leg 3, leg 2 passes just as well
//! if the value never left memory in the first place, or if the second host were
//! answering from something other than the restored volume — the calibration is
//! what makes leg 2 evidence about durability rather than about survival.
//!
//! ## Ordering is OWNED, and the barrier is COUNTED
//!
//! Every barrier here is a host log line, and the load-bearing one is
//! `client session ended`: pico's `z_put` sends its Put and then closes on the
//! SAME link, the driver consumes that link in order, so a session that reached
//! terminal necessarily dispatched the Put first. A `sleep` would make the same
//! claim without establishing it.
//!
//! That line is emitted once per client, and `read_captured` re-reads the whole
//! capture from offset 0 on every poll — it has to, or the parent's seek would
//! rewind the child's shared write offset. So "wait for `client session ended`"
//! answers "has one EVER ended", and matches a line the previous client wrote.
//! Waits on it are therefore COUNTED
//! ([`StorageHost::wait_session_ended`]). This is not a hypothetical: with the
//! plain wait, leg 2 failed 3 runs in 8 — the host was killed on the
//! storage-add client's terminator while the sample it was to persist was still
//! in flight, and it surfaced two steps later as "the filesystem volume did not
//! restore its mirror".
//!
//! Requires the zenoh-pico CLI (`z_put` + `z_get`) and a `wz-ap-demo` built
//! `--no-default-features --features preset-ap-full`. `#[ignore]`d binary-dep
//! e2e; run-ci Layer E13 drives it.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

/// The host's per-client terminator. Not unique — every client produces one —
/// which is why waits on it are COUNTED (see [`StorageHost::wait_session_ended`]).
const SESSION_ENDED: &str = "client session ended";

/// The storage this file configures over the wire, and the data it holds.
const STORAGE_NAME: &str = "apfull";
const MOUNT: &str = "demo/store/**";
const DATA_KEY: &str = "demo/store/k1";
const DATA_VALUE: &str = "value-written-by-pico";

/// Fail NOW, naming the feature list, if the binary at the shared demo path is
/// not the AP-full one this file needs.
///
/// The demo path is ONE path that many feature sets are written over, which has
/// already cost this tree three misdiagnoses (R311y482), so every leg reads the
/// demo's own generated report before it waits on any wire marker. The storage
/// keys are asserted BESIDE `preset-ap-full` so that a preset which dropped the
/// plane again fails here in milliseconds rather than as a mute 15s timeout that
/// reads like a wz defect.
fn assert_apfull_storage_was_built(captured: &str, role: &str) {
    let line = captured
        .lines()
        .find(|l| l.contains("BUILD FEATURES = ["))
        .unwrap_or_else(|| {
            panic!(
                "the wz-ap-demo ({role}) never printed its BUILD FEATURES line, so \
                 which feature set this binary carries is unknown and no assertion \
                 below means anything\n--- captured ---\n{captured}"
            )
        });
    for needed in [
        "preset-ap-full",
        // The admin surface the config-write arrives on.
        "adminspace-config-hotreload",
        // The manager + the volume seam the storage is created through.
        "storage-backend",
        // The durable volume legs 2 and 3 discriminate on. Held back from this
        // preset until R311y496.
        "storage-backend-filesystem",
    ] {
        assert!(
            line.contains(&format!(" {needed} ")) || line.contains(&format!("[{needed} ")),
            "the wz-ap-demo ({role}) was built WITHOUT `{needed}`, so the storage \
             leg this file asserts on is compiled out. Build it with \
             `--no-default-features --features preset-ap-full` from a tree that \
             carries the R311y496 preset change.\n{line}"
        );
    }
}

/// A spawned AP-full storage host: the child, its stderr reader, and the admin
/// root (`@/<zid>/peer`) scraped from its own log.
struct StorageHost {
    child: ChildGuard,
    log: std::fs::File,
    root: String,
    /// How many client sessions this fixture has already waited out. The counter
    /// is the barrier; see [`wait_session_ended`](StorageHost::wait_session_ended).
    sessions_ended: usize,
}

impl StorageHost {
    /// Wait for `needle` to appear in this host's log. Only sound for a needle
    /// this host emits AT MOST ONCE.
    ///
    /// `read_captured` re-reads the capture from offset 0 on every poll, and it
    /// must: the parent and the child share one open file description, so a
    /// parent that seeks would rewind the CHILD's write position and corrupt the
    /// capture. The consequence for a caller is that `wait_for_substring` is
    /// "has this EVER appeared", never "has it appeared again" — a repeatable
    /// needle must be counted instead.
    fn wait(&mut self, needle: &str, what: &str) -> String {
        match wait_for_substring(&mut self.log, needle, Duration::from_secs(15)) {
            Ok(c) => c,
            Err(c) => panic!(
                "storage host never logged `{needle}` ({what}) within 15s\n--- host ---\n{c}"
            ),
        }
    }

    /// Wait until this host has ended one MORE client session than the last time
    /// this was called — the barrier for "the write that client sent has been
    /// dispatched".
    ///
    /// COUNTED rather than awaited, for the reason [`wait`](StorageHost::wait)
    /// gives: `client session ended` is emitted once per client, so a plain wait
    /// on it returns instantly on a line the PREVIOUS client wrote. That is not a
    /// theoretical hazard — it is how this file's durability leg failed 3 runs in
    /// 8 before this counter existed. The host was killed on the storage-add
    /// client's terminator while the sample it was supposed to persist was still
    /// in flight, and the failure surfaced two steps away as "the filesystem
    /// volume did not restore its mirror".
    ///
    /// The strength of the barrier itself is an ordering property of the link,
    /// not a timing guess: pico's one-shot sends its Put and then closes on the
    /// SAME TCP link, and the driver consumes that link in order, so a session
    /// that reached terminal has already dispatched the Put into the storage's
    /// capture subscriber.
    fn wait_session_ended(&mut self, what: &str) {
        self.sessions_ended += 1;
        let want = self.sessions_ended;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let captured = read_captured(&mut self.log);
            if captured.matches(SESSION_ENDED).count() >= want {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "storage host ended fewer than {want} client sessions within 15s \
                     ({what})\n--- host ---\n{captured}"
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

/// Spawn `wz-ap-demo --storage-host <addr>`, optionally on a durable volume
/// directory, and return it once its admin registrations are logged.
///
/// The build assertion runs BEFORE the readiness wait deliberately: the banner is
/// emitted ahead of every mode branch, so a wrong binary is named in milliseconds
/// instead of spending the full readiness timeout to report the same cause.
fn spawn_storage_host(addr: &str, dir: Option<&Path>, role: &str) -> StorageHost {
    spawn_storage_host_with(addr, dir, role, &[])
}

/// [`spawn_storage_host`] plus `extra` argv — the host-side policy flags a leg
/// needs (R311y503: the garbage-collection period / lifespan). Kept as one
/// spawner rather than a second copy so every leg shares the same BUILD FEATURES
/// assertion and the same readiness barrier.
fn spawn_storage_host_with(
    addr: &str,
    dir: Option<&Path>,
    role: &str,
    extra: &[&str],
) -> StorageHost {
    let stderr = tempfile::tempfile().expect("tempfile for storage-host stderr");
    let writer = stderr.try_clone().expect("dup storage-host stderr handle");
    let mut reader = stderr;

    let mut cmd = Command::new(wz_ap_demo_binary());
    cmd.arg("--storage-host").arg(addr);
    if let Some(d) = dir {
        cmd.arg("--storage-host-dir").arg(d);
    }
    cmd.args(extra);
    cmd.env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(writer));

    let mut child = ChildGuard::wrap(
        format!("wz-ap-demo --storage-host ({role})"),
        cmd.spawn().expect("spawn wz-ap-demo storage host"),
    );

    let banner = match wait_for_substring(&mut reader, "BUILD FEATURES = [", Duration::from_secs(5))
    {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!(
                "the wz-ap-demo ({role}) never printed its BUILD FEATURES line \
                 within 5s, so which feature set this binary carries is \
                 unknown\n--- {role} ---\n{c}"
            );
        }
    };
    assert_apfull_storage_was_built(&banner, role);

    let tail = match wait_for_substring(
        &mut reader,
        "adminspace config GET at ",
        Duration::from_secs(15),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!(
                "the storage host ({role}) never became ready within 15s\n--- {role} \
                 ---\n{banner}{c}"
            );
        }
    };
    let config_key = tail
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("storage host logged the admin config keyexpr");
    let root = config_key
        .strip_suffix("/config")
        .expect("config key ends with /config")
        .to_string();

    StorageHost {
        child,
        log: reader,
        root,
        sessions_ended: 0,
    }
}

/// Drive a one-shot pico `z_put` at `key` carrying `value`. pico ENCODES the
/// keyexpr, payload and push body; wz decodes them.
fn pico_put(z_put: &Path, key: &str, value: &str, addr: &str) {
    let mut child = ChildGuard::wrap(
        "z_put client (zenoh-pico)",
        Command::new(z_put)
            .args([
                "-k",
                key,
                "-v",
                value,
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_put"),
    );
    let _ = child.child_mut().wait();
}

/// Run a fresh one-shot pico `z_get` on `key` and return its stdout up to the
/// terminating Final. A SEPARATE process with its own session every time — which
/// is precisely the boundary this file exists to cross.
fn pico_get(z_get: &Path, key: &str, addr: &str) -> String {
    let stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let writer = stdout.try_clone().expect("dup z_get stdout handle");
    let mut reader = stdout;

    let mut child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_get)
            .args(["-k", key, "-e", &format!("tcp/{addr}"), "-m", "client"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );

    let out = match wait_for_substring(
        &mut reader,
        "Received query final notification",
        Duration::from_secs(15),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}");
        }
    };
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();
    out
}

/// A one-line-per-entry listing of the durable volume directory, for failure
/// messages only.
fn volume_listing(dir: &Path) -> String {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            out.push(format!(
                "{} ({} bytes)",
                p.display(),
                e.metadata().map(|m| m.len()).unwrap_or(0)
            ));
            if p.is_dir() {
                walk(&p, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    if out.is_empty() {
        String::from("(empty)")
    } else {
        out.join("\n")
    }
}

/// Whether pico DECODED a reply carrying `key` with `value`. The pico CLI prints
/// each reply as `('<keyexpr>': '<payload>')`, so both halves are required on ONE
/// line — a key present with someone else's payload is not a hit.
fn pico_decoded(out: &str, key: &str, value: &str) -> bool {
    out.lines()
        .any(|l| l.contains(&format!("('{key}':")) && l.contains(value))
}

/// Configure the storage over the wire (`storage-add <name>:<keyexpr>`) and
/// return once the host reports it live AND that client's session has ended.
///
/// CONSUMING THE SESSION TERMINATOR HERE IS LOAD-BEARING, and leaving it out is
/// a defect this file already had: `client session ended` is the only barrier the
/// host offers for "your write was dispatched", and it is not unique to any one
/// client. A later wait for it would match THIS call's terminator — a line
/// already in the log — and return before the next client had so much as
/// connected. Leg 2 failed exactly that way (the host was killed before the
/// sample it was supposed to persist had been captured) while legs 1, 3 and 4
/// passed on timing. Draining the terminator here makes the next one belong to
/// the next client by construction.
fn pico_adds_storage(z_put: &Path, host: &mut StorageHost, addr: &str) {
    pico_put(
        z_put,
        &format!("{}/config/storage-add", host.root),
        &format!("{STORAGE_NAME}:{MOUNT}"),
        addr,
    );
    host.wait(
        &format!("spawned live storage '{STORAGE_NAME}'"),
        "storage-add applied",
    );
    host.wait_session_ended("storage-add client disconnected");
}

/// pico writes one sample into the mount, and the host is driven to the end of
/// that client's session before the caller reads.
///
/// The barrier is `client session ended`, and its strength is an ORDERING
/// property of the link, not a timing guess: pico's `z_put` emits the Put and
/// then closes on the same TCP link, and the driver consumes that link in order,
/// so a session that reached terminal has already dispatched the Put into the
/// storage's capture subscriber.
fn pico_writes_sample(z_put: &Path, host: &mut StorageHost, addr: &str) {
    pico_put(z_put, DATA_KEY, DATA_VALUE, addr);
    host.wait_session_ended("pico put session driven to terminal");
}

/// R311y496 leg 1 — THE PLANE. A real pico configures a storage on the AP-full
/// binary, a real pico writes a sample into it, and a THIRD pico reads that
/// sample back. Three separate foreign processes, three separate sessions, one
/// wz node.
///
/// This is the guard for the per-session rebinding: before R311y496 the storage's
/// capture subscriber and queryable were bound to whichever transient client
/// session carried the `storage-add`, so the reader's session reached a storage
/// that could neither capture nor answer, and this leg failed with no reply at
/// all for `DATA_KEY`.
// ONE claim, and the two this leg does NOT make are the interesting part.
//
// `storage-mgr-config` and `storage-backend-volume-trait` are both on the path
// this leg drives — pico's payload becomes a StorageConfig, and the backend is
// created through the Volume factory — and claiming them was the first draft.
// Layer A4 refused both: each is declared FOREIGN-NON-OBSERVABLE (a declarative
// data model whose effects belong to the storage-mgr-* atoms; a Rust factory
// trait with no independent wire artifact), and the audit is right. Nothing a
// foreign peer can observe distinguishes a volume-created backend from a
// directly-constructed one, so the witness would have been for the storage
// SERVING, credited to atoms that are not what makes it observable.
//
// The surviving claim is `partial`: this leg hosts ONE storage, so the
// manager's "N named storages" property is only partly exercised, and only the
// name/key_expr fields are wire-driven (complete, strip_prefix and the GC
// config are host-side — the deferred `parse_storage_add_payload` follow-up).
// wz-proves: storage-mgr-multi-storage-host wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_put/z_get); Layer E13 runs via --ignored"]
fn apfull_storage_plane_serves_a_pico_write_to_a_later_pico_read() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_get = zenoh_pico_cli_binary("z_get");
    let dir = tempfile::tempdir().expect("durable volume dir");
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());

    let mut host = spawn_storage_host(&addr, Some(dir.path()), "plane");
    drop(port);

    pico_adds_storage(&z_put, &mut host, &addr);
    pico_writes_sample(&z_put, &mut host, &addr);

    let out = pico_get(&z_get, MOUNT, &addr);
    let _ = host.child.child_mut().kill();

    assert!(
        pico_decoded(&out, DATA_KEY, DATA_VALUE),
        "a real zenoh-pico z_get on `{MOUNT}` did not read back the sample a real \
         zenoh-pico z_put had written to the SAME AP-full storage host. The storage \
         reported live, so this is the storage plane failing to serve across the \
         session boundary, not a configuration miss.\n--- z_get ---\n{out}"
    );
}

/// R311y496 leg 2 — `storage-backend-filesystem`. The host is KILLED and brought
/// back on the same `--storage-host-dir`, the storage is re-configured over the
/// wire, and pico reads the value it wrote to the previous PROCESS.
///
/// The value can only come from the volume: the second host is a new process with
/// an empty manager, and the storage it hosts is created fresh from the same
/// directory. Leg 3 is what forbids the alternative reading.
// wz-proves: storage-backend-filesystem wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_put/z_get); Layer E13 runs via --ignored"]
fn apfull_storage_plane_survives_a_host_restart_on_a_durable_volume() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_get = zenoh_pico_cli_binary("z_get");
    let dir = tempfile::tempdir().expect("durable volume dir");

    // ── first host: pico configures the storage and writes into it ──
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());
    let mut host = spawn_storage_host(&addr, Some(dir.path()), "durable/first");
    drop(port);
    pico_adds_storage(&z_put, &mut host, &addr);
    pico_writes_sample(&z_put, &mut host, &addr);
    let _ = host.child.child_mut().kill();
    let _ = host.child.child_mut().wait();
    let first_log = read_captured(&mut host.log);

    // ── second host: same directory, new process, empty manager ──
    let port2 = PortReservation::pick();
    let addr2 = format!("127.0.0.1:{}", port2.port());
    let mut host2 = spawn_storage_host(&addr2, Some(dir.path()), "durable/second");
    drop(port2);
    pico_adds_storage(&z_put, &mut host2, &addr2);

    let out = pico_get(&z_get, MOUNT, &addr2);
    let _ = host2.child.child_mut().kill();

    // The on-disk state is reported with the failure: it separates "the first
    // host never persisted" from "the second host did not restore", which are
    // different defects and would otherwise present identically here.
    let on_disk = volume_listing(dir.path());
    assert!(
        pico_decoded(&out, DATA_KEY, DATA_VALUE),
        "a real zenoh-pico z_get did not read back a value written to a PREVIOUS \
         process of the same durable storage host (--storage-host-dir {dir:?}), so \
         the filesystem volume did not restore its mirror on open.\n--- volume dir \
         ---\n{on_disk}\n--- first host (tail) ---\n{first_log}\n--- z_get ---\n{out}",
        dir = dir.path()
    );
}

/// R311y496 leg 3 — the CALIBRATION for leg 2, and it is not optional. The same
/// script with `--storage-host-dir` ABSENT must NOT read the value back: the
/// storage then rides the volatile `mem` volume, which a process restart cannot
/// restore.
///
/// Without this leg, leg 2's pass is equally consistent with the value never
/// having been durable at all — with pico's own client cache, with a second host
/// that answers from anywhere. This is what makes leg 2 evidence about the
/// filesystem volume specifically.
// The volatile arm is where the `mem` volume is the one under test: with no
// --storage-host-dir the host maps its storages onto MemoryVolume, and both the
// serve and the non-survival are foreign-observed. `partial` because the volume
// is not selectable from the wire — the host's flag chooses it.
// wz-proves: storage-backend-memory-volume wz->pico partial
// wz-proves: storage-backend-filesystem wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_put/z_get); Layer E13 runs via --ignored"]
fn apfull_storage_plane_is_volatile_across_a_restart_without_the_durable_volume() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_get = zenoh_pico_cli_binary("z_get");

    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());
    let mut host = spawn_storage_host(&addr, None, "volatile/first");
    drop(port);
    pico_adds_storage(&z_put, &mut host, &addr);
    pico_writes_sample(&z_put, &mut host, &addr);

    // The SAME-process read must still work — otherwise this leg would "pass" for
    // leg 1's reason and prove nothing about the volume.
    let live = pico_get(&z_get, MOUNT, &addr);
    assert!(
        pico_decoded(&live, DATA_KEY, DATA_VALUE),
        "the volatile arm could not read its own write back BEFORE the restart, so \
         its post-restart absence would say nothing about \
         durability\n--- z_get ---\n{live}"
    );
    let _ = host.child.child_mut().kill();
    let _ = host.child.child_mut().wait();

    let port2 = PortReservation::pick();
    let addr2 = format!("127.0.0.1:{}", port2.port());
    let mut host2 = spawn_storage_host(&addr2, None, "volatile/second");
    drop(port2);
    pico_adds_storage(&z_put, &mut host2, &addr2);

    let out = pico_get(&z_get, MOUNT, &addr2);
    let _ = host2.child.child_mut().kill();

    assert!(
        !pico_decoded(&out, DATA_KEY, DATA_VALUE),
        "a volatile (`mem`-volume) storage host returned a value written to a \
         PREVIOUS process. Then leg 2's pass is not evidence about \
         `storage-backend-filesystem` — something other than the durable volume is \
         carrying the value across the restart.\n--- z_get ---\n{out}"
    );
}

/// R311y496 leg 4 — `storage-del` tears the plane down as observed by pico: after
/// the despawn a real `z_get` on the mount gets the terminating Final and no
/// value, from the same binary that served it a moment earlier.
///
/// The pair with leg 1 is what makes each meaningful: leg 1 alone is consistent
/// with anything at all answering on the mount, and this leg alone is consistent
/// with a storage that never served.
// wz-proves: adminspace-config-hotreload wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_put/z_get); Layer E13 runs via --ignored"]
fn apfull_storage_del_stops_serving_a_real_pico_get() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_get = zenoh_pico_cli_binary("z_get");
    let dir = tempfile::tempdir().expect("durable volume dir");
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());

    let mut host = spawn_storage_host(&addr, Some(dir.path()), "del");
    drop(port);
    pico_adds_storage(&z_put, &mut host, &addr);
    pico_writes_sample(&z_put, &mut host, &addr);

    let served = pico_get(&z_get, MOUNT, &addr);
    assert!(
        pico_decoded(&served, DATA_KEY, DATA_VALUE),
        "the storage did not serve BEFORE the despawn, so its silence afterwards \
         would say nothing about storage-del\n--- z_get ---\n{served}"
    );

    pico_put(
        &z_put,
        &format!("{}/config/storage-del", host.root),
        STORAGE_NAME,
        &addr,
    );
    host.wait(
        &format!("despawned '{STORAGE_NAME}'"),
        "storage-del applied",
    );

    let out = pico_get(&z_get, MOUNT, &addr);
    let _ = host.child.child_mut().kill();

    assert!(
        !pico_decoded(&out, DATA_KEY, DATA_VALUE),
        "a real zenoh-pico z_get still read the stored value AFTER `storage-del` \
         despawned the storage, so the despawn did not undeclare the answering \
         queryable\n--- z_get ---\n{out}"
    );
}

/// R311y503 leg 5 — the storage's periodic GARBAGE COLLECTOR, sweeping a
/// wildcard-update entry that a REAL zenoh-pico put there.
///
/// ## What was missing, and why nothing caught it
///
/// `storage-mgr-garbage-collection` had a faithful sweep
/// (`StorageState::collect_garbage`) and a faithful tokio driver
/// (`GarbageCollector`), both unit-tested — and NO production caller. `spawn`
/// was invoked only under `#[cfg(test)]`, so every deployed storage grew its
/// wildcard registries forever. The inventory recorded that as a named residual
/// rather than a bug, and no gate could see it: A3 asks whether a cfg site
/// exists (it did), the unit tests drive the collector directly (they passed),
/// and no e2e went near it. R311y503 wired the spawn into
/// `RuntimeStorageManager::add_storage` — the storage's lifetime owner, and the
/// same place zenoh registers its `GarbageCollectionEvent` — and this leg is
/// what holds it there.
///
/// ## The chain, all of it foreign-driven
///
/// 1. a real pico `z_put` on `.../config/storage-add` spawns the live storage —
///    so the collector under test is one created by the production path, not by
///    the test;
/// 2. a real pico `z_put` on the WILDCARD `demo/store/**` registers a
///    wildcard-update entry. pico encodes the wildcard keyexpr and the payload;
///    wz decodes them and files the entry in `wildcard_puts`;
/// 3. the collector sweeps it, and says so.
///
/// The host runs `--storage-gc-lifespan-ms 0`, which is what makes a 24-hour
/// default observable inside a test: every entry is stale at the next sweep.
/// That the lifespan is genuinely THREADED (rather than everything always being
/// swept) is pinned deterministically by the driver's own unit test
/// `a_within_lifespan_entry_is_retained_proving_lifespan_is_threaded`; asserting
/// the retention here would mean waiting for a log NOT to appear, which is a
/// flake wearing a proof's clothes.
///
/// The sweep line is emitted only when entries were actually REMOVED, so it
/// cannot fire on an idle storage — it witnesses the collection, not the timer.
/// And the counts in it (`puts 1->0`) are asserted, not just the verb: a line
/// reporting `puts 0->0` would mean the sweep ran on an empty registry and the
/// foreign wildcard never landed.
// wz-proves: storage-mgr-garbage-collection pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_put); Layer E13 runs via --ignored"]
fn apfull_storage_gc_sweeps_a_wildcard_update_a_real_pico_registered() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());
    // period 200 ms so a sweep lands inside the barrier budget; lifespan 0 so the
    // entry pico registers is stale by the time the first sweep sees it.
    let mut host = spawn_storage_host_with(
        &addr,
        None,
        "gc",
        &[
            "--storage-gc-period-ms",
            "200",
            "--storage-gc-lifespan-ms",
            "0",
        ],
    );
    drop(port);

    // (1) the storage exists because a foreign client asked for it.
    pico_adds_storage(&z_put, &mut host, &addr);

    // (2) a foreign WILDCARD put — the thing the registry holds. `MOUNT` is the
    //     storage's own keyexpr, so the entry lands in this storage's registry
    //     and not somewhere the sweep would never look.
    pico_put(&z_put, MOUNT, "wildcard-written-by-pico", &addr);
    host.wait_session_ended("pico wildcard-put session driven to terminal");

    // (3) the sweep, with its counts.
    let captured = host.wait(
        "garbage collected",
        "the periodic collector swept the wildcard-update registry",
    );
    let line = captured
        .lines()
        .find(|l| l.contains("garbage collected"))
        .expect("the sweep line is present (the wait above returned it)");
    assert!(
        line.contains(&format!("wz storage '{STORAGE_NAME}'")),
        "the sweep names the storage a real pico created, so it cannot be some \
         other storage's collector\n  got: {line}"
    );
    assert!(
        line.contains("puts 1->0"),
        "the sweep removed the wildcard-update entry the real pico registered — a \
         `puts 0->0` would mean the collector ran on an empty registry and the \
         foreign wildcard never landed\n  got: {line}"
    );
}
