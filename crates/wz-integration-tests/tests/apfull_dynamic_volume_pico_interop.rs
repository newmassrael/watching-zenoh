// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y497 — the §5.24 `storage-mgr-dynamic-volume-loading` atom witnessed
//! end-to-end: a real zenoh-pico SELECTS a `dlopen`ed storage volume over the
//! wire, writes into a storage mounted on it, and a later pico reads that value
//! back out of a DIFFERENT HOST PROCESS.
//!
//! ## The atom, and why it was open
//!
//! R311y256 deprecated this atom as OBVIATED, writing the condition into the
//! reason: *"if `plugin-dynamic-loading` is ever built, this returns with it."*
//! R311y492 built `plugin-dynamic-loading`; R311y496 moved this back to `reserved`
//! and made Layer A5 PRINT it as OPEN on every run so the condition could not be
//! forgotten a second time. It was one of exactly two atoms A5 reported as keeping
//! `preset-ap-full` from being literally full.
//!
//! ## Why the restart is the discriminator and a read is not
//!
//! The host keeps an in-memory read mirror over EVERY backend, because the in-tree
//! `StorageBackend::get` hands back a borrowed value. So within one process a read
//! is answered by the mirror, and leg 1 alone cannot separate "the volume served
//! it" from "the host served itself". What the mirror cannot supply is a value the
//! PREVIOUS process wrote: that reaches a fresh host only through the volume's
//! `store_entries` at create time. Leg 2 is therefore the load-bearing one, and
//! leg 3 is what forbids the remaining alternative reading — the same script with
//! `--storage-volume` absent must fail to mount at all.
//!
//! ## What each leg pins
//!
//! - Leg 1 — the wire SELECTION works: pico's `storage-add apfull@wzvol_example:…`
//!   mounts the storage on the loaded volume (the host names the volume it landed
//!   on), and a second `storage-add` naming NO volume still lands on `mem`, so the
//!   payload widening did not break the legacy form ON THE WIRE.
//! - Leg 2 — DURABILITY through the `.so`: kill the host, start a new process on
//!   the same volume `.so` and config, and pico reads its pre-restart value.
//! - Leg 3 — the CALIBRATION: without `--storage-volume`, the identical script
//!   fails to mount (`VolumeNotFound`) and reads nothing.
//! - Leg 4 — a shared object that is not a volume is REFUSED and the node keeps
//!   serving: a `storage-add` naming the volume fails while one naming none still
//!   works. The `.so` used is the real `wz-plugin-example`, which exports
//!   `wz_plugin_entry` and not `wz_volume_entry` — the honest negative, and the
//!   leg that justifies the two ABIs having distinct entry symbols.
//!
//! ## Ordering is OWNED, and the session barrier is COUNTED
//!
//! Every barrier is a host log line. `client session ended` is emitted once per
//! client and `read_captured` re-reads the capture from offset 0 on every poll — it
//! must, or the parent's seek would rewind the child's shared write position — so a
//! plain wait on it answers "has one EVER ended" and matches the PREVIOUS client's
//! line. Waits on it are COUNTED. R311y496 paid 3 failures in 8 runs for that
//! lesson on the sibling file; it is not re-learned here.
//!
//! Requires the zenoh-pico CLI (`z_put` + `z_get`), a `wz-ap-demo` built
//! `--no-default-features --features preset-ap-full`, and the
//! `libwz_volume_example.so` / `libwz_plugin_example.so` cdylibs. `#[ignore]`d
//! binary-dep e2e; run-ci Layer E14 drives it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    project_root, read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
    ChildGuard, PortReservation,
};

/// The host's per-client terminator. Not unique — every client produces one —
/// which is why waits on it are COUNTED.
const SESSION_ENDED: &str = "client session ended";

/// The id the example volume's `.so` DECLARES. The host registers it under this
/// name (never under an operator-chosen one), so it is what a client puts after
/// the `@` in a `storage-add` payload.
const VOLUME_ID: &str = "wzvol_example";

const STORAGE_NAME: &str = "apfull";
const MOUNT: &str = "demo/store/**";
const DATA_KEY: &str = "demo/store/k1";
const DATA_VALUE: &str = "value-on-a-dlopened-volume";

/// A second storage that names NO volume, so leg 1 can check the legacy payload
/// form still resolves to `mem` over the real wire.
const LEGACY_NAME: &str = "legacy";
const LEGACY_MOUNT: &str = "demo/legacy/**";

/// One of the workspace's cdylibs, by cargo's own output naming.
fn cdylib(stem: &str) -> PathBuf {
    let mut p = project_root().join("crates").join("target").join("debug");
    p.push(if cfg!(target_os = "macos") {
        format!("lib{stem}.dylib")
    } else {
        format!("lib{stem}.so")
    });
    p
}

/// The example volume `.so`, or fail NOW naming the build command.
///
/// A hard failure rather than a skip: this file's entire subject is a `dlopen` of
/// this file, so continuing without it would be a green run that proved nothing —
/// and Layer E14 builds it first.
fn volume_so() -> PathBuf {
    let p = cdylib("wz_volume_example");
    assert!(
        p.exists(),
        "{} not built — run `cargo build -p wz-volume-example` (Layer E14 does). \
         Every leg in this file dlopens it, so there is nothing to witness without it.",
        p.display()
    );
    p
}

/// The example PLUGIN `.so` — a real shared object that is emphatically not a
/// volume. Leg 4's honest negative.
fn plugin_so() -> PathBuf {
    let p = cdylib("wz_plugin_example");
    assert!(
        p.exists(),
        "{} not built — run `cargo build -p wz-plugin-example` (Layer E14 does). \
         Leg 4 needs a REAL loadable shared object that is not a volume; a file \
         crafted to fail would not test the entry-symbol distinction.",
        p.display()
    );
    p
}

/// Fail NOW, naming the feature list, if the binary at the shared demo path is not
/// the AP-full one this file needs.
///
/// The demo path is ONE path that many feature sets are written over, which has
/// already cost this tree three misdiagnoses (R311y482), so every leg reads the
/// demo's own generated report before it waits on any wire marker.
fn assert_apfull_dynamic_volume_was_built(captured: &str, role: &str) {
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
        // The manager + volume seam the storage is created through.
        "storage-backend",
        // THE atom. Without it `--storage-volume` is an inert warning and every
        // leg below would fail on a mute timeout that reads like a wz defect.
        "storage-mgr-dynamic-volume-loading",
    ] {
        assert!(
            line.contains(&format!(" {needed} ")) || line.contains(&format!("[{needed} ")),
            "the wz-ap-demo ({role}) was built WITHOUT `{needed}`, so the leg this \
             file asserts on is compiled out. Build it with `--no-default-features \
             --features preset-ap-full` from a tree that carries the R311y497 preset \
             change.\n{line}"
        );
    }
}

/// A spawned AP-full storage host: the child, its stderr reader, and the admin
/// root (`@/<zid>/peer`) scraped from its own log.
struct StorageHost {
    child: ChildGuard,
    log: std::fs::File,
    root: String,
    /// How many client sessions this fixture has already waited out. The counter IS
    /// the barrier; see [`wait_session_ended`](StorageHost::wait_session_ended).
    sessions_ended: usize,
}

impl StorageHost {
    /// Wait for `needle`. Only sound for a needle this host emits AT MOST ONCE.
    fn wait(&mut self, needle: &str, what: &str) -> String {
        match wait_for_substring(&mut self.log, needle, Duration::from_secs(15)) {
            Ok(c) => c,
            Err(c) => panic!(
                "storage host never logged `{needle}` ({what}) within 15s\n--- host ---\n{c}"
            ),
        }
    }

    /// Everything the host has logged so far, for failure messages.
    fn captured(&mut self) -> String {
        read_captured(&mut self.log)
    }

    /// Wait until this host has ended one MORE client session than the last time
    /// this was called — the barrier for "the write that client sent has been
    /// dispatched".
    ///
    /// COUNTED rather than awaited: `client session ended` is emitted once per
    /// client and `read_captured` re-reads from offset 0, so a plain wait returns
    /// instantly on a line the PREVIOUS client wrote. The barrier's strength is an
    /// ordering property of the link rather than a timing guess — pico's one-shot
    /// sends its Put and then closes on the SAME TCP link, and the driver consumes
    /// that link in order, so a session that reached terminal has already
    /// dispatched the Put into the storage's capture subscriber.
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

    fn kill(&mut self) {
        let _ = self.child.child_mut().kill();
        let _ = self.child.child_mut().wait();
    }
}

/// What volume `.so` (if any) a host is launched with.
enum VolumeArg<'a> {
    /// No `--storage-volume` at all — leg 3's arm.
    None,
    /// `--storage-volume <so> --storage-volume-config <dir>`.
    Load { so: &'a Path, config: &'a Path },
}

/// Spawn `wz-ap-demo --storage-host <addr>` and return it once its admin
/// registrations are logged.
///
/// The build assertion runs BEFORE the readiness wait deliberately: the banner
/// precedes every mode branch, so a wrong binary is named in milliseconds instead
/// of spending the full readiness timeout to report the same cause.
fn spawn_storage_host(addr: &str, volume: VolumeArg<'_>, role: &str) -> StorageHost {
    let stderr = tempfile::tempfile().expect("tempfile for storage-host stderr");
    let writer = stderr.try_clone().expect("dup storage-host stderr handle");
    let mut reader = stderr;

    let mut cmd = Command::new(wz_ap_demo_binary());
    cmd.arg("--storage-host").arg(addr);
    if let VolumeArg::Load { so, config } = volume {
        cmd.arg("--storage-volume")
            .arg(so)
            .arg("--storage-volume-config")
            .arg(config);
    }
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
                "the wz-ap-demo ({role}) never printed its BUILD FEATURES line within \
                 5s, so which feature set this binary carries is unknown\n--- {role} \
                 ---\n{c}"
            );
        }
    };
    assert_apfull_dynamic_volume_was_built(&banner, role);

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

/// Drive a one-shot pico `z_put` at `key` carrying `value`.
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

/// Whether pico DECODED a reply carrying `key` with `value`. The pico CLI prints
/// each reply as `('<keyexpr>': '<payload>')`, so both halves are required on ONE
/// line — a key present with someone else's payload is not a hit.
fn pico_decoded(out: &str, key: &str, value: &str) -> bool {
    out.lines()
        .any(|l| l.contains(&format!("('{key}':")) && l.contains(value))
}

/// A one-line-per-entry listing of the volume's directory, for failure messages
/// only. It separates "the first host never persisted" from "the second host did
/// not restore", which are different defects and present identically otherwise.
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

/// Configure a storage over the wire on the volume the client NAMES, and return
/// once the host reports it live on THAT volume and the client's session has ended.
///
/// The `on volume '<id>'` half of the barrier is what makes this a check of the
/// wire's volume selection rather than of storage-add in general: before R311y497
/// the host overrode the volume unconditionally, so this same payload would have
/// mounted on `mem` and every later leg would have passed for the wrong reason.
///
/// CONSUMING THE SESSION TERMINATOR HERE IS LOAD-BEARING. `client session ended`
/// is the only barrier the host offers for "your write was dispatched", and it is
/// not unique to any one client; a later wait would match THIS call's terminator
/// and return before the next client had connected. Draining it here makes the
/// next one belong to the next client by construction.
fn pico_adds_storage_on(
    z_put: &Path,
    host: &mut StorageHost,
    addr: &str,
    name: &str,
    mount: &str,
    volume: Option<&str>,
) {
    let payload = match volume {
        Some(v) => format!("{name}@{v}:{mount}"),
        None => format!("{name}:{mount}"),
    };
    pico_put(
        z_put,
        &format!("{}/config/storage-add", host.root),
        &payload,
        addr,
    );
    // The volume is the TAIL of the host's spawn line, not a mid-line insert: two
    // older integration tests pin that line through its `— storage_manager Started`
    // segment, so appending is what lets this file assert the volume without
    // editing them. Waiting on the whole line, volume included, is therefore both
    // the storage-add barrier and the volume-selection assertion.
    host.wait(
        &format!(
            "spawned live storage '{name}' — storage_manager Started (volume '{}')",
            volume.unwrap_or("mem")
        ),
        "storage-add applied on the named volume",
    );
    host.wait_session_ended("storage-add client disconnected");
}

/// pico writes one sample into the mount, and the host is driven to the end of
/// that client's session before the caller reads.
fn pico_writes_sample(z_put: &Path, host: &mut StorageHost, addr: &str) {
    pico_put(z_put, DATA_KEY, DATA_VALUE, addr);
    host.wait_session_ended("pico put session driven to terminal");
}

/// R311y497 leg 1 — the wire SELECTS the `dlopen`ed volume, and the legacy payload
/// form still resolves to `mem`.
///
/// The storage rides a volume that is not compiled into this binary at all: it
/// arrived as a `.so` the operator named, and the client asked for it BY ITS
/// DECLARED ID. The second storage-add, naming no volume, is the calibration for
/// the payload widening itself — a parser that started reading every payload as
/// volume-qualified would land `legacy` somewhere other than `mem`.
// The atom's foreign-observable difference is that a storage serves from a volume
// this binary never compiled in, selected by the client. `partial` because within
// one process the host's read mirror also holds the value — the unqualified claim
// belongs to leg 2, where only the `.so` can have supplied it.
// wz-proves: storage-mgr-dynamic-volume-loading wz->pico partial
// wz-proves: adminspace-config-hotreload wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + wz-volume-example.so + zenoh-pico z_put/z_get); Layer E14 runs via --ignored"]
fn apfull_dynamic_volume_selected_over_the_wire_serves_a_pico_write() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_get = zenoh_pico_cli_binary("z_get");
    let so = volume_so();
    let vol_dir = tempfile::tempdir().expect("volume config dir");
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());

    let mut host = spawn_storage_host(
        &addr,
        VolumeArg::Load {
            so: &so,
            config: vol_dir.path(),
        },
        "select",
    );
    drop(port);
    // The load itself is a host claim, checked before anything depends on it: a
    // refused load would otherwise surface as a storage-add failure and read like
    // a wire defect.
    host.wait(
        &format!("dlopen'd storage volume '{VOLUME_ID}'"),
        "the volume .so loaded and configured",
    );

    pico_adds_storage_on(
        &z_put,
        &mut host,
        &addr,
        STORAGE_NAME,
        MOUNT,
        Some(VOLUME_ID),
    );
    // The legacy form, over the same wire, in the same host: no `@`, so `mem`.
    pico_adds_storage_on(&z_put, &mut host, &addr, LEGACY_NAME, LEGACY_MOUNT, None);
    pico_writes_sample(&z_put, &mut host, &addr);

    let out = pico_get(&z_get, MOUNT, &addr);
    let on_disk = volume_listing(vol_dir.path());
    let host_log = host.captured();
    host.kill();

    assert!(
        pico_decoded(&out, DATA_KEY, DATA_VALUE),
        "a real zenoh-pico z_get on `{MOUNT}` did not read back the sample a real \
         zenoh-pico z_put had written to a storage mounted on the DLOPEN'd volume \
         `{VOLUME_ID}`.\n--- volume dir ---\n{on_disk}\n--- host ---\n{host_log}\n\
         --- z_get ---\n{out}"
    );
}

/// R311y497 leg 2 — DURABILITY through the `.so`, and the load-bearing leg.
///
/// The host is killed and a NEW PROCESS is started on the same volume `.so` and
/// the same volume config. The value pico reads cannot have come from the host's
/// read mirror (that died with the process) and cannot have come from
/// `storage-backend-filesystem` (no `--storage-host-dir` is passed at all). The
/// only path left is the loaded volume's own `store_entries`, which is exactly the
/// call the mirror is rebuilt from.
// The unqualified claim: a value written by one process is served by another
// through a volume neither compiled in, selected by a foreign client both times.
// wz-proves: storage-mgr-dynamic-volume-loading wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + wz-volume-example.so + zenoh-pico z_put/z_get); Layer E14 runs via --ignored"]
fn apfull_dynamic_volume_survives_a_host_restart_through_the_loaded_so() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_get = zenoh_pico_cli_binary("z_get");
    let so = volume_so();
    let vol_dir = tempfile::tempdir().expect("volume config dir");

    // ── first host: pico mounts on the loaded volume and writes into it ──
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());
    let mut host = spawn_storage_host(
        &addr,
        VolumeArg::Load {
            so: &so,
            config: vol_dir.path(),
        },
        "durable/first",
    );
    drop(port);
    host.wait(
        &format!("dlopen'd storage volume '{VOLUME_ID}'"),
        "the volume .so loaded and configured (first host)",
    );
    pico_adds_storage_on(
        &z_put,
        &mut host,
        &addr,
        STORAGE_NAME,
        MOUNT,
        Some(VOLUME_ID),
    );
    pico_writes_sample(&z_put, &mut host, &addr);
    // Read it back BEFORE the restart, so a post-restart failure cannot be
    // confused with "the value was never stored at all".
    let live = pico_get(&z_get, MOUNT, &addr);
    let first_log = host.captured();
    host.kill();
    assert!(
        pico_decoded(&live, DATA_KEY, DATA_VALUE),
        "the first host could not serve its own write, so its successor's behaviour \
         would say nothing about the volume\n--- host ---\n{first_log}\n--- z_get \
         ---\n{live}"
    );

    // ── second host: new process, same `.so`, same volume config, empty manager ──
    let port2 = PortReservation::pick();
    let addr2 = format!("127.0.0.1:{}", port2.port());
    let mut host2 = spawn_storage_host(
        &addr2,
        VolumeArg::Load {
            so: &so,
            config: vol_dir.path(),
        },
        "durable/second",
    );
    drop(port2);
    host2.wait(
        &format!("dlopen'd storage volume '{VOLUME_ID}'"),
        "the volume .so loaded and configured (second host)",
    );
    pico_adds_storage_on(
        &z_put,
        &mut host2,
        &addr2,
        STORAGE_NAME,
        MOUNT,
        Some(VOLUME_ID),
    );

    let out = pico_get(&z_get, MOUNT, &addr2);
    let on_disk = volume_listing(vol_dir.path());
    let second_log = host2.captured();
    host2.kill();

    assert!(
        pico_decoded(&out, DATA_KEY, DATA_VALUE),
        "a real zenoh-pico z_get did not read back a value written to a PREVIOUS \
         process of a storage host, through a volume that reached both processes \
         only as a dlopen'd `.so`. Nothing else could have carried it: the mirror \
         died with the first process and no --storage-host-dir was ever \
         passed.\n--- volume dir ---\n{on_disk}\n--- first host ---\n{first_log}\n\
         --- second host ---\n{second_log}\n--- z_get ---\n{out}"
    );
}

/// R311y497 leg 3 — the CALIBRATION, and it is not optional.
///
/// The identical script with `--storage-volume` ABSENT must not mount at all: the
/// client names a volume the host has never heard of, so `add_storage` fails with
/// `VolumeNotFound` and the mount answers nothing. Without this leg, legs 1 and 2
/// are equally consistent with the host having quietly substituted one of its own
/// volumes — which is precisely what it DID before R311y497, unconditionally.
// The negative arm: a client-named volume that is not registered must be refused
// rather than substituted. `partial` because the atom's positive claim is leg 2's.
// wz-proves: storage-mgr-dynamic-volume-loading wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_put/z_get); Layer E14 runs via --ignored"]
fn apfull_without_the_loaded_volume_the_same_payload_mounts_nothing() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_get = zenoh_pico_cli_binary("z_get");
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());

    let mut host = spawn_storage_host(&addr, VolumeArg::None, "calibration");
    drop(port);

    // The SAME payload leg 1 sends, at a host that loaded no volume.
    pico_put(
        &z_put,
        &format!("{}/config/storage-add", host.root),
        &format!("{STORAGE_NAME}@{VOLUME_ID}:{MOUNT}"),
        &addr,
    );
    host.wait(
        &format!("add_storage '{STORAGE_NAME}' failed"),
        "the unregistered volume is refused, not substituted",
    );
    host.wait_session_ended("storage-add client disconnected");

    pico_writes_sample(&z_put, &mut host, &addr);
    let out = pico_get(&z_get, MOUNT, &addr);
    let host_log = host.captured();
    host.kill();

    assert!(
        !pico_decoded(&out, DATA_KEY, DATA_VALUE),
        "a host that loaded NO volume still served a storage the client asked to \
         mount on `{VOLUME_ID}`. Then legs 1 and 2 are not evidence about the \
         dlopen'd volume — the host substituted one of its own, which is the \
         pre-R311y497 behaviour this leg exists to forbid.\n--- host ---\n{host_log}\n\
         --- z_get ---\n{out}"
    );
}

/// R311y497 leg 4 — a shared object that is not a volume is REFUSED, and the node
/// keeps serving.
///
/// The `.so` is the real `wz-plugin-example`: a loadable object that exports
/// `wz_plugin_entry` and no `wz_volume_entry`. That makes this the leg which
/// justifies the two ABIs having distinct entry symbols — were they shared, the
/// volume loader would resolve a plugin's vtable, and the ABI gate would pass while
/// doing it, because the plugin's descriptor carries the plugin's own layout
/// numbers.
///
/// A refusal must not take the node down, so the leg also requires the host to
/// still mount an un-named storage and serve a real pico read through it. Without
/// that half, a host that died on the bad `.so` would "pass" the refusal check.
// wz-proves: storage-mgr-dynamic-volume-loading wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + wz-plugin-example.so + zenoh-pico z_put/z_get); Layer E14 runs via --ignored"]
fn apfull_a_non_volume_shared_object_is_refused_and_the_node_survives() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_get = zenoh_pico_cli_binary("z_get");
    let not_a_volume = plugin_so();
    let vol_dir = tempfile::tempdir().expect("volume config dir");
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());

    let mut host = spawn_storage_host(
        &addr,
        VolumeArg::Load {
            so: &not_a_volume,
            config: vol_dir.path(),
        },
        "refusal",
    );
    drop(port);
    let refusal = host.wait(
        "storage volume load failed",
        "a non-volume shared object is refused",
    );
    assert!(
        refusal.contains("wz_volume_entry"),
        "the refusal must name the MISSING VOLUME ENTRY SYMBOL — any other cause \
         means the loader got far enough to read a plugin's vtable as a \
         volume's\n--- host ---\n{refusal}"
    );

    // The node survived: an un-named storage still mounts on `mem` and serves a
    // real foreign read.
    pico_adds_storage_on(&z_put, &mut host, &addr, STORAGE_NAME, MOUNT, None);
    pico_writes_sample(&z_put, &mut host, &addr);
    let out = pico_get(&z_get, MOUNT, &addr);

    // And the volume the bad `.so` would have provided is NOT registered.
    pico_put(
        &z_put,
        &format!("{}/config/storage-add", host.root),
        &format!("other@{VOLUME_ID}:demo/other/**"),
        &addr,
    );
    host.wait(
        "add_storage 'other' failed",
        "the refused volume was never registered",
    );
    let host_log = host.captured();
    host.kill();

    assert!(
        pico_decoded(&out, DATA_KEY, DATA_VALUE),
        "the node stopped serving after refusing a non-volume `.so`. A rejected \
         volume must cost the operator that volume and nothing else — otherwise one \
         bad path takes the storage host down, which is the opposite of what a \
         loader is for.\n--- host ---\n{host_log}\n--- z_get ---\n{out}"
    );
}
