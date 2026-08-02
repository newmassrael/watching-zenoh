// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.22 `plugin-dynamic-loading` — a real `.so` is `dlopen`ed at runtime and a
//! real zenoh-pico reads it out of the admin space beside the statically
//! composed subsystems.
//!
//! ## Why this atom exists again at all
//!
//! R311y256 deprecated four of the five §5.22 atoms, correctly and
//! conditionally: `plugin-manager`, `-host-trait`, `-lifecycle` and
//! `-abi-compat` each serve dynamic loading, and wz composed every subsystem at
//! build time, so none of them had anything to do. The same round kept
//! `plugin-dynamic-loading` as `reserved` with the condition written out — *"the
//! other four exist only to SERVE dynamic loading, so if this is ever built they
//! return with it"* — and removed its out-of-scope label by user decision,
//! recording it as *"genuinely unbuilt and genuinely buildable ON THE AP
//! PROFILE"*. R311y492 built it.
//!
//! ## The discriminator, which the admin space already had a field for
//!
//! `AdminPlugin::path` carries `WZ_STATIC_PLUGIN_PATH` (`"__static__"`) for a
//! compiled-in subsystem, and its doc says why: *"wz subsystems are STATICALLY
//! linked … so there is no dylib path"*. A dynamically loaded plugin reports the
//! FILE IT WAS LOADED FROM. That is not a marker this test invents — it is the
//! field zenoh uses for exactly this (`PluginStatus::path`), and pico has been
//! decoding it since R311y237.
//!
//! So the witness is: one GET, two records, one carrying `"__static__"` and the
//! other carrying a path this test computed at runtime. A build that faked
//! dynamic loading would have to fabricate a filesystem path it was never given,
//! and a build that ignored `--plugin` entirely reports only the static one —
//! which is precisely what leg 2 asserts against a `.so` that is not a plugin.
//!
//! ## What each leg claims, stated apart because the evidence differs
//!
//! - **leg 1** — `plugin-dynamic-loading` and `plugin-manager`. The `.so` path
//!   and `Started` state can only come from a real `dlopen` plus a registry that
//!   kept the result and fed it to the reply slice.
//! - **leg 2** — no atom of its own. It is the CONTROL that makes leg 1 mean
//!   something: handed a real, loadable shared object that is not a wz plugin,
//!   the host refuses it, stays up, and reports only the static subsystem. Its
//!   own failure mode (a host that reports whatever it was handed) is what leg 1
//!   cannot rule out alone.
//!
//! ## Why both fn names begin `wz_plugin`
//!
//! Layer E runs a CATCH-ALL `--ignored` sweep over this crate against the
//! DEFAULT demo binary, and `--skip` matches the TEST FUNCTION name. A test that
//! needs a non-default binary must therefore be excludable by its own name — the
//! convention `wz_storage_host_*` and `apfull_*` already follow. Named without
//! that prefix, these two were swept into Layer E and failed there against a
//! `preset-ap-client` binary, which is the R311y481 shared-artifact trap wearing
//! a new mask. The build discriminator reported it in 0.10s naming the feature
//! list, which is the only reason it read as a wiring defect rather than a
//! loader one.
//!
//! `plugin-abi-compat`, `-host-trait` and `-lifecycle` are NOT claimed here and
//! that is deliberate. The ABI gate is a pure function over a descriptor and is
//! bound by five unit tests in `wz-plugin-abi`; the vtable and the lifecycle FSM
//! are host-internal and produce no foreign-observable difference a pico can
//! decode. Claiming them off this transcript would be the per-compiled-feature
//! claiming that rots a proof axis.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    project_root, read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
    ChildGuard, PortReservation,
};

/// The example plugin `.so` the demo is asked to load.
fn example_plugin_so() -> PathBuf {
    project_root()
        .join("crates/target/debug")
        .join(if cfg!(target_os = "macos") {
            "libwz_plugin_example.dylib"
        } else {
            "libwz_plugin_example.so"
        })
}

/// Spawn the storage host with `--plugin <path>` for each entry, returning it
/// once its admin surface is up, with the admin root and the capture.
fn spawn_plugin_host(
    plugins: &[PathBuf],
    role: &str,
) -> (ChildGuard, std::fs::File, String, String) {
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let stderr = tempfile::tempfile().expect("tempfile for host stderr");
    let writer = stderr.try_clone().expect("dup host stderr handle");
    let mut reader = stderr;

    let mut cmd = Command::new(wz_ap_demo_binary());
    cmd.arg("--storage-host").arg(&addr);
    for p in plugins {
        cmd.arg("--plugin").arg(p);
    }
    cmd.env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(writer));

    let mut child = ChildGuard::wrap(
        format!("wz-ap-demo --storage-host ({role})"),
        cmd.spawn().expect("spawn wz-ap-demo storage host"),
    );

    // The build check runs BEFORE any wire wait (R311y490): the demo emits its
    // banner ahead of every mode branch, so a binary without the feature fails
    // here in milliseconds naming the feature list, rather than after a timeout
    // that reads like a loader defect.
    let banner = match wait_for_substring(&mut reader, "BUILD FEATURES = [", Duration::from_secs(5))
    {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!(
                "the wz-ap-demo ({role}) never printed its BUILD FEATURES line\n--- host ---\n{c}"
            );
        }
    };
    let line = banner
        .lines()
        .find(|l| l.contains("BUILD FEATURES = ["))
        .expect("the banner line was just matched");
    assert!(
        line.contains(" plugin-dynamic-loading ") || line.contains("[plugin-dynamic-loading "),
        "the wz-ap-demo ({role}) was built WITHOUT `plugin-dynamic-loading`, so \
         `--plugin` is INERT and nothing below means anything. Build it with \
         `--no-default-features --features preset-ap-full`.\n{line}"
    );

    let tail = match wait_for_substring(
        &mut reader,
        "adminspace config GET at ",
        Duration::from_secs(15),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("the storage host ({role}) never registered its admin surface\n--- host ---\n{banner}{c}");
        }
    };
    let captured = format!("{banner}{tail}");
    let root = captured
        .lines()
        .find_map(|l| l.split_once("adminspace config GET at "))
        .map(|(_, rest)| rest.trim().to_string())
        .and_then(|k| k.strip_suffix("/config").map(str::to_owned))
        .unwrap_or_else(|| panic!("no scrapeable admin root\n--- host ---\n{captured}"));

    drop(port_res);
    (child, reader, root, addr)
}

/// pico's `z_get` over the plugins subtree, captured to the terminating Final.
fn pico_get_plugins(root: &str, addr: &str) -> Result<String, String> {
    let z_get = zenoh_pico_cli_binary("z_get");
    let stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let writer = stdout.try_clone().expect("dup z_get stdout handle");
    let mut reader = stdout;

    let mut child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args([
                "-k",
                &format!("{root}/plugins/**"),
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );
    let done = wait_for_substring(
        &mut reader,
        "Received query final notification",
        Duration::from_secs(15),
    );
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();
    done
}

// R311y503 — three more of the §5.22 atoms are claimed here, and this REOPENS a
// caveat R311y492 wrote into their inventory reasons: "none of the four is
// claimed on the pico transcript, which would be per-compiled-feature claiming".
// That caution is right about the failure it names -- four atoms riding ONE cargo
// key must not all be credited because the key was compiled in -- but it does not
// apply to a claim bound by its OWN damage. Each of the three below was damaged
// separately, and each damage changes a DIFFERENT field of the record the real
// pico decodes, so the wire transcript itself distinguishes them:
//
//   `plugin-abi-compat` — `PluginEntry::compatibility`. Forced to return
//   MajorMismatch, the load is refused and this leg reds with no `wz_example`
//   record at all, while the CONTROL leg below (which expects a refusal) stays
//   green. The gate is what admits the plugin the pico then reads.
//
//   `plugin-host-trait` — `PluginVTable`, the repr(C) call table. Reading
//   `version` from the `name` slot instead of the `version` slot leaves the load
//   and the lifecycle intact and reds only the version assertion: the pico
//   decodes `"version":"wz_example"`. The foreign process sees the slot layout
//   the host and the plugin agreed on, which is the atom.
//
//   `plugin-lifecycle` — Declared->Loaded->Started. Suppressing only the final
//   transition (`start` still calls the plugin, still returns Ok) reds the state
//   assertion alone: the pico decodes `"state":"Loaded"`. The FSM, not the load.
//
// All three are wz->pico: wz produces the admin record, a real zenoh-pico z_get
// decodes it.
// wz-proves: plugin-dynamic-loading wz->pico
// wz-proves: plugin-manager wz->pico
// wz-proves: plugin-abi-compat wz->pico
// wz-proves: plugin-host-trait wz->pico
// wz-proves: plugin-lifecycle wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + wz-plugin-example cdylib + zenoh-pico z_get CLI); Layer C1bp runs via --ignored"]
fn wz_plugin_dlopened_is_read_by_a_real_pico_beside_the_static_one() {
    let so = example_plugin_so();
    assert!(
        so.exists(),
        "the example plugin `.so` is not built: {}. Run \
         `cargo build -p wz-plugin-example` (Layer C1bp does). Skipping instead \
         would be a green test that loaded nothing.",
        so.display()
    );

    let (mut host, mut host_log, root, addr) =
        spawn_plugin_host(std::slice::from_ref(&so), "with-plugin");

    // The host's own load edge — a barrier, so the GET below cannot race startup.
    if let Err(c) = wait_for_substring(
        &mut host_log,
        "plugin 'wz_example' Started",
        Duration::from_secs(15),
    ) {
        let _ = host.child_mut().kill();
        let _ = host.child_mut().wait();
        panic!("the host never started the plugin within 15s\n--- host ---\n{c}");
    }

    let out = pico_get_plugins(&root, &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get never saw the terminating Final\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait();

    // ── the DYNAMIC record: a real filesystem path and a Started state ──
    let dynamic = out
        .lines()
        .find(|l| l.contains(&format!("('{root}/plugins/wz_example':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no record for the dlopen'd plugin at `{root}/plugins/wz_example`\n--- z_get ---\n{out}")
        });
    assert!(
        dynamic.contains(&format!(r#""path":"{}""#, so.display())),
        "the record carries the EXACT path this test handed the host — a value it \
         could only have because a dlopen of that file happened\n  got: {dynamic}"
    );
    assert!(
        dynamic.contains(r#""state":"Started""#) && dynamic.contains(r#""version":"0.1.0""#),
        "the plugin's own version string and its Started state come back through \
         the vtable getters\n  got: {dynamic}"
    );

    // ── the STATIC record, in the SAME reply set — the contrast that makes the
    //    path field a discriminator rather than a string ──
    let static_rec = out
        .lines()
        .find(|l| l.contains(&format!("('{root}/plugins/storage_manager':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no record for the statically composed storage_manager\n--- z_get ---\n{out}")
        });
    assert!(
        static_rec.contains(r#""path":"__static__""#),
        "the compiled-in subsystem still reports the static marker — if BOTH \
         carried a path, the field would distinguish nothing\n  got: {static_rec}"
    );
}

// wz-proves: none -- the CONTROL arm. It claims no atom because its subject is
// what the host does NOT do: handed a real, loadable shared object that is not a
// wz plugin, it refuses, stays up, and reports only the static subsystem. Without
// it, leg 1 is equally consistent with a host that reports whatever path it was
// handed, which is the one failure mode leg 1 cannot rule out from its own
// transcript.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_get CLI); Layer C1bp runs via --ignored"]
fn wz_plugin_non_plugin_shared_object_is_refused_and_the_node_survives() {
    // A real, loadable `.so` that is emphatically not a wz plugin. Using the
    // system C library rather than a file crafted to fail keeps the negative
    // honest — a truncated or corrupt file would exercise `dlopen`'s error path,
    // not the entry-symbol check this arm is about.
    let not_a_plugin = PathBuf::from("libc.so.6");

    let (mut host, mut host_log, root, addr) =
        spawn_plugin_host(&[not_a_plugin], "with-non-plugin");

    if let Err(c) = wait_for_substring(&mut host_log, "plugin load failed", Duration::from_secs(15))
    {
        let _ = host.child_mut().kill();
        let _ = host.child_mut().wait();
        panic!("the host never reported the refusal within 15s — it either loaded a non-plugin or said nothing\n--- host ---\n{c}");
    }

    // POSITIVE edge: the node is still serving. A host that aborted on a bad
    // plugin would fail here rather than at the absence assertion below, and the
    // two are different defects.
    let out = pico_get_plugins(&root, &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("the node stopped serving after refusing a plugin\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait();

    assert!(
        out.contains(&format!("('{root}/plugins/storage_manager':")),
        "the statically composed subsystem is still reported\n--- z_get ---\n{out}"
    );
    assert!(
        !out.contains("libc.so"),
        "a refused shared object must not appear in the plugin registry\n--- z_get ---\n{out}"
    );
}
