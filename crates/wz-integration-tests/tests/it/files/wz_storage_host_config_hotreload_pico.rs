// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y277 — FOREIGN-INTEROP CONFIG-HOTRELOAD: a stock zenoh-pico client drives
//! watching-zenoh's `adminspace-config-hotreload` storage lifecycle END-TO-END over
//! the wire. A pico `z_put` `@/<zid>/peer/config/storage-add demo:demo/**` live-spawns
//! a `RuntimeStorageManager` storage on the wz `--storage-host`; a subsequent pico
//! `z_get` `@/<zid>/peer/plugins/**` then decodes `storage_manager` state `Started`
//! (`Loaded` before); a `storage-del demo` reverses it back to `Loaded`.
//!
//! R311y828 extends the same run with the STATUS SUB-TREE
//! (`@/<zid>/peer/status/plugins/storage_manager/**`), which the
//! `adminspace-plugins-handlers` atom had recorded as unserved: the pico client
//! reads the host's registered volume back as a capability object and the storage
//! the pico `z_put` just created back as its mounted `key_expr`/`volume`, then
//! sees the storage leg disappear on `storage-del`. Same client, same wire, same
//! host process — so the sub-tree is proven DRIVEN, not merely wired.
//!
//! ## What binds the claim (and why it is NOT a bool flip)
//!
//! `adminspace-config-hotreload`'s `F=` is the config-diff-driven storage lifecycle:
//! the `storage-add`/`storage-del` decode (wz-session-core `parse_admin_config_write`),
//! the APPLY via `RuntimeStorageManager::add_storage` / `remove_storage`, AND the
//! DYNAMIC plugin registry (`compiled_plugins_dyn`) reflecting `storage_manager`
//! `Started` when a storage is LIVE. The host's GET handler reads
//! `compiled_plugins_dyn(&version, storage_started)`, and `storage_started` tracks
//! `!manager.is_empty()` — set only by a REAL `add_storage`/`remove_storage`, never a
//! bare bool. A `Started` reply therefore cannot appear without a live
//! manager-hosted storage; the state flip is the wz-encoded reply pico decodes, so
//! the claim rides the plugins GET arm (`wz->pico`). pico is ALSO the encoder of the
//! `storage-add`/`storage-del` PUT (the `pico->wz` config-write half), but the atom
//! is witnessed by the STATE it produces, not the PUT that triggers it.
//!
//! ## The "zombie storage" bound (NAMED — do not over-read this witness)
//!
//! A stock pico `z_put` and `z_get` are SEPARATE one-shot processes, so the wz host
//! multi-accepts a fresh per-client Session each. A storage is spawned on the
//! TRANSIENT z_put client Session; when that pico process exits and the Session is
//! dropped, the hosted `StorageService` SURVIVES (the manager is hoisted; the service
//! holds `Arc` clones of the dropped Session's observer/actions, and dead-link
//! undeclare emits are swallowed). So the storage is STATE-OBSERVABLE across the
//! session boundary — it keeps the manager non-empty, which is what this
//! plugins-STATE witness reads — but it is a ZOMBIE: it does NOT serve data across
//! the connection boundary. This test asserts ONLY the reported state
//! (`Loaded`->`Started`->`Loaded`); it makes no claim that the zombie storage answers
//! cross-connection data gets.
//!
//! ## Positive edges only
//!
//! Every wait is on a log/notification that MUST appear: the host's readiness line,
//! the host's `spawned live storage`/`despawned` lines (the storage-apply barriers,
//! waited on AFTER the driving z_put exits), and pico's `Received query final
//! notification`. No arm waits for the absence of a line.
//!
//! ## Which binary this rides
//!
//! Layer E6h's — it builds `wz-ap-demo --features adminspace-config-hotreload` (the
//! ONLY lane with the `--storage-host` mode compiled in) and drives this test. The
//! `wz_storage_host_` fn prefix keeps the default Layer E sweep's `--skip wz_peer` /
//! `--skip wz_router` from touching it; the `--ignored` gate keeps it out of the
//! host-only unit runs. Cargo uplifts every feature variant of `wz-ap-demo` to one
//! path (R311y269), so this variant is only safe inside the lane that built it.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::bounded::BoundedChild as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// Run a fresh one-shot pico `z_get` on `<root>/plugins/**` and return its stdout
/// (captured up to the terminating `Received query final notification`). Each call
/// is a SEPARATE pico process opening its own session — the reason the wz host
/// multi-accepts.
fn pico_get_plugins_output(z_get: &Path, root: &str, addr: &str) -> String {
    pico_get_output(z_get, &format!("{root}/plugins/**"), addr)
}

/// R311y828 — the same one-shot pico `z_get`, on an ARBITRARY keyexpr. The
/// `plugins/**` helper above now routes through this so the two GETs this test
/// makes are byte-for-byte the same client behaviour on different keys, and a
/// difference in what comes back cannot be a difference in how it was asked.
fn pico_get_output(z_get: &Path, keyexpr: &str, addr: &str) -> String {
    let g_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let g_writer = g_stdout.try_clone().expect("dup z_get stdout handle");
    let mut g_reader = g_stdout;

    let mut g_child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_get)
            .args(["-k", keyexpr, "-e", &format!("tcp/{addr}"), "-m", "client"])
            .stdout(Stdio::from(g_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );

    let done = wait_for_substring(
        &mut g_reader,
        "Received query final notification",
        Duration::from_secs(15),
    );
    let out = match done {
        Ok(c) => c,
        Err(c) => {
            let _ = g_child.child_mut().kill();
            let _ = g_child.child_mut().wait_bounded();
            panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}");
        }
    };
    let _ = g_child.child_mut().kill();
    let _ = g_child.child_mut().wait_bounded();
    out
}

/// R311y828 — whether the pico-decoded output carries a reply keyed exactly `key`.
/// pico's `z_get` prints one `('<key>': '<payload>')` line per reply, so presence
/// is read off the key literal rather than off a payload substring that could
/// occur under some other key.
fn pico_replied_at(out: &str, key: &str) -> bool {
    out.lines().any(|l| l.contains(&format!("('{key}':")))
}

/// R311y828 — the pico-decoded reply body at `key`, or a panic naming what DID
/// come back. Used for the `status/plugins/storage_manager/**` sub-tree legs.
fn pico_body_at(out: &str, key: &str, when: &str) -> String {
    let marker = format!("('{key}': '");
    out.lines()
        .find_map(|l| {
            let (_, rest) = l.split_once(&marker)?;
            rest.rsplit_once('\'').map(|(body, _)| body.to_string())
        })
        .unwrap_or_else(|| {
            panic!("pico decoded no reply at `{key}` ({when})\n--- z_get ---\n{out}")
        })
}

/// Assert the pico-decoded `<root>/plugins/storage_manager` record carries the
/// expected `storage_manager` state. `when` names the phase for the failure message.
fn assert_plugins_state(out: &str, root: &str, expected_state: &str, when: &str) {
    let key = format!("{root}/plugins/storage_manager");
    let line = out
        .lines()
        .find(|l| l.contains(&format!("('{key}':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no plugins leg at `{key}` ({when})\n--- z_get ---\n{out}")
        });
    assert!(
        line.contains(r#""id":"storage_manager""#)
            && line.contains(&format!(r#""state":"{expected_state}""#)),
        "storage_manager must report state `{expected_state}` ({when})\n  got: {line}"
    );
}

/// Drive a one-shot pico `z_put` at `key` carrying `value`. pico ENCODES the config
/// write (keyexpr + payload + push body); wz's config-write subscriber decodes it.
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
    let _ = child.child_mut().wait_bounded();
}

/// The running `--storage-host`: its process, the reader of its log, its admin root
/// (`@/<zid>/peer`) and the address a pico client dials.
struct StorageHost {
    child: ChildGuard,
    log: std::fs::File,
    root: String,
    addr: String,
}

impl StorageHost {
    /// Wait up to 15 s for the host to log `line`, which is how every apply is observed: a
    /// positive edge, waited on after the driving pico process has exited.
    fn expect_log(&mut self, line: &str, what: &str) {
        if let Err(c) = wait_for_substring(&mut self.log, line, Duration::from_secs(15)) {
            let _ = self.child.child_mut().kill();
            let _ = self.child.child_mut().wait_bounded();
            panic!("storage host never logged {line:?} within 15s ({what})\n--- host ---\n{c}");
        }
    }

    fn stop(mut self) {
        let _ = self.child.child_mut().kill();
        let _ = self.child.child_mut().wait_bounded();
    }
}

/// Start `wz-ap-demo --storage-host` on a fresh port and read its admin root off its
/// readiness line.
fn start_storage_host(demo: &Path) -> StorageHost {
    assert_demo_binary_newer_than_sources(demo);
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());
    let h_stderr = tempfile::tempfile().expect("tempfile for storage-host stderr");
    let h_writer = h_stderr
        .try_clone()
        .expect("dup storage-host stderr handle");
    let mut log = h_stderr;
    let mut child = ChildGuard::wrap(
        "wz-ap-demo --storage-host (adminspace-config-hotreload)",
        Command::new(demo)
            .arg("--storage-host")
            .arg(&addr)
            // Inert on this lane's build (see the state-flip test), passed so a write gate
            // added to the lane later cannot silently deny the PUTs.
            .arg("--config-write-permit")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(h_writer))
            .spawn()
            .expect("spawn wz-ap-demo storage host"),
    );
    let captured = match wait_for_substring(
        &mut log,
        "adminspace config GET at ",
        Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait_bounded();
            panic!("storage host never became ready within 5s\n--- host ---\n{c}");
        }
    };
    let root = captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("storage host logged the admin config keyexpr")
        .strip_suffix("/config")
        .expect("config key ends with /config")
        .to_string();
    drop(port_res);
    StorageHost {
        child,
        log,
        root,
        addr,
    }
}

/// Open-debt item 781 — the VOLUME lifecycle, driven by the same stock pico client over the
/// same wire as the storage one below.
///
/// The decoder (`volume-add` / `volume-del`) and the manager (`register_volume`,
/// `remove_volume`'s cascade) each have unit witnesses; the storage host's dispatch arms that
/// join them are reached only through a process, so this is their witness:
///
/// 1. `volume-add archive@memory` registers a volume the pico GET then reads back under
///    `status/plugins/storage_manager/volumes/archive`; `volume-add bogus@nosuchbackend` is
///    refused by name and never listed.
/// 2. `storage-add vault@archive:vault/**` mounts a storage on that volume, and the status
///    sub-tree reports `"volume":"archive"` for it.
/// 3. `volume-del archive` takes `vault` with it (upstream's `kill_volume` cascade), while a
///    storage on the built-in `mem` volume (`keep`) survives: it keeps the sub-tree served, so
///    the two absences read after the cascade are measurements and not a sub-tree that went
///    away whole.
// wz-proves: adminspace-config-hotreload wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features adminspace-config-hotreload + zenoh-pico z_get/z_put CLIs); Layer E6h runs via --ignored"]
fn wz_storage_host_config_hotreload_volume_lifecycle_via_pico() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let z_put = zenoh_pico_cli_binary("z_put");
    let mut host = start_storage_host(&demo);
    let (root, addr) = (host.root.clone(), host.addr.clone());
    let status_root = format!("{root}/status/plugins/storage_manager");
    let memory_capability = r#"{"capability":{"history":"Latest","persistence":"Volatile"}}"#;

    pico_put(
        &z_put,
        &format!("{root}/config/volume-add"),
        "archive@memory",
        &addr,
    );
    host.expect_log(
        "registered storage volume 'archive' (backend 'memory')",
        "volume-add archive@memory",
    );
    pico_put(
        &z_put,
        &format!("{root}/config/volume-add"),
        "bogus@nosuchbackend",
        &addr,
    );
    host.expect_log(
        "volume-add 'bogus' refused",
        "a volume on a backend this build does not carry",
    );
    pico_put(
        &z_put,
        &format!("{root}/config/storage-add"),
        "keep:keep/**",
        &addr,
    );
    host.expect_log(
        "spawned live storage 'keep' — storage_manager Started",
        "storage-add on the built-in volume",
    );
    pico_put(
        &z_put,
        &format!("{root}/config/storage-add"),
        "vault@archive:vault/**",
        &addr,
    );
    host.expect_log(
        "spawned live storage 'vault' — storage_manager Started (volume 'archive')",
        "storage-add on the added volume",
    );

    let out_added = pico_get_output(&z_get, &format!("{status_root}/**"), &addr);
    assert_eq!(
        pico_body_at(
            &out_added,
            &format!("{status_root}/volumes/archive"),
            "after volume-add"
        ),
        memory_capability,
        "the volume a pico client added is listed with its backend's capability"
    );
    assert_eq!(
        pico_body_at(
            &out_added,
            &format!("{status_root}/storages/vault"),
            "after storage-add on the added volume"
        ),
        r#"{"key_expr":"vault/**","volume":"archive"}"#,
        "the storage is mounted on the volume the client named"
    );
    assert!(
        !pico_replied_at(&out_added, &format!("{status_root}/volumes/bogus")),
        "a refused volume-add must register nothing\n--- z_get ---\n{out_added}"
    );

    pico_put(
        &z_put,
        &format!("{root}/config/volume-del"),
        "archive",
        &addr,
    );
    host.expect_log(
        "unregistered storage volume 'archive', despawning vault — storage_manager Started",
        "volume-del archive with a storage on it",
    );

    let out_removed = pico_get_output(&z_get, &format!("{status_root}/**"), &addr);
    for kept in ["storages/keep", "volumes/mem"] {
        assert!(
            pico_replied_at(&out_removed, &format!("{status_root}/{kept}")),
            "`{kept}` is not on the removed volume and must still be served (control)\n\
             --- z_get ---\n{out_removed}"
        );
    }
    for gone in ["volumes/archive", "storages/vault"] {
        assert!(
            !pico_replied_at(&out_removed, &format!("{status_root}/{gone}")),
            "`{gone}` must go with `volume-del archive`\n--- z_get ---\n{out_removed}"
        );
    }

    host.stop();
}

// wz-proves: adminspace-config-hotreload wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features adminspace-config-hotreload + zenoh-pico z_get/z_put CLIs); Layer E6h runs via --ignored"]
fn wz_storage_host_config_hotreload_state_flip_via_pico() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let z_put = zenoh_pico_cli_binary("z_put");

    // ── the wz storage host: multi-accepts per-client Sessions, hosts the admin GET
    //    + config-write subscriber, applies storage-add/-del via RuntimeStorageManager.
    let mut host = start_storage_host(&demo);
    let (root, addr) = (host.root.clone(), host.addr.clone());

    // ── (1) BEFORE any storage-add: storage_manager is Loaded (compiled, not live) ──
    let out_before = pico_get_plugins_output(&z_get, &root, &addr);
    assert_plugins_state(&out_before, &root, "Loaded", "before storage-add");

    // ── (2) pico z_put storage-add: wz calls RuntimeStorageManager::add_storage ──
    pico_put(
        &z_put,
        &format!("{root}/config/storage-add"),
        "demo:demo/**",
        &addr,
    );
    // BARRIER: the host's REAL add_storage apply (waited after the z_put exits — a
    // positive edge, the apply happens on the host as it drains the config-write).
    host.expect_log(
        "spawned live storage 'demo' — storage_manager Started",
        "the config-hotreload add_storage on a pico-encoded PUT",
    );

    // ── (3) AFTER storage-add: storage_manager flips to Started ──
    let out_added = pico_get_plugins_output(&z_get, &root, &addr);
    assert_plugins_state(&out_added, &root, "Started", "after storage-add");

    // ── (3b) R311y828 — the storage_manager STATUS SUB-TREE, over the wire, read
    //    by a FOREIGN client. This is the leg the `adminspace-plugins-handlers`
    //    atom recorded as unserved: upstream's `adminspace_getter` publishes
    //    `/version`, `/volumes/**` and `/storages/**`, and wz answered only
    //    `__path__` while owning live volumes and storages.
    let status_root = format!("{root}/status/plugins/storage_manager");
    let out_status = pico_get_output(&z_get, &format!("{status_root}/**"), &addr);
    // The `__path__` leg is the CONTROL: it was already served before this round,
    // so its presence says the GET reached the handler and the window is open. A
    // sub-tree assertion that failed with it absent would be reporting a broken
    // observation, not a missing sub-tree.
    assert!(
        pico_replied_at(&out_status, &format!("{status_root}/__path__")),
        "the pre-existing __path__ leg must answer this GET (control)\n--- z_get ---\n{out_status}"
    );
    assert_eq!(
        pico_body_at(
            &out_status,
            &format!("{status_root}/volumes/mem"),
            "after storage-add"
        ),
        r#"{"capability":{"history":"Latest","persistence":"Volatile"}}"#,
        "the in-memory volume's real capability reaches a foreign client"
    );
    assert_eq!(
        pico_body_at(
            &out_status,
            &format!("{status_root}/storages/demo"),
            "after storage-add"
        ),
        r#"{"key_expr":"demo/**","volume":"mem"}"#,
        "the LIVE storage the pico z_put created is introspectable by key expression \
         and volume — the config the host actually mounted, not an echo of the PUT"
    );

    // ── (4) pico z_put storage-del: wz calls RuntimeStorageManager::remove_storage ──
    pico_put(&z_put, &format!("{root}/config/storage-del"), "demo", &addr);
    host.expect_log(
        "despawned 'demo' — storage_manager Loaded",
        "the config-hotreload remove_storage on a pico-encoded PUT",
    );

    // ── (5) AFTER storage-del: storage_manager reverts to Loaded ──
    let out_removed = pico_get_plugins_output(&z_get, &root, &addr);
    assert_plugins_state(&out_removed, &root, "Loaded", "after storage-del");

    // ── (5b) R311y828 — and the sub-tree FOLLOWS the manager rather than being a
    //    snapshot taken at host start: the storage leg is gone. Both halves are
    //    asserted because either alone is weak — a sub-tree that never appeared
    //    would also pass "it is gone now", which is why (3b) had to see it first.
    //    The whole sub-tree goes with it: `status/plugins/**` is Started-gated, and
    //    a `storage-del` returns storage_manager to Loaded.
    let out_status_removed = pico_get_output(&z_get, &format!("{status_root}/**"), &addr);
    assert!(
        !pico_replied_at(&out_status_removed, &format!("{status_root}/storages/demo")),
        "the removed storage must stop being advertised\n--- z_get ---\n{out_status_removed}"
    );

    host.stop();
}
