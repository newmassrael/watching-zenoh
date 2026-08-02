// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y272 — FOREIGN-INTEROP ADMINSPACE WRITE: a real zenoh-pico `z_put` CLI
//! RECONFIGURES a watching-zenoh routing peer through its admin config-write path,
//! and is REJECTED by the same peer when the write permission is not granted.
//!
//! This is the first §5.23 witness in which **pico is the ENCODER**: y270 and y271
//! had pico decoding wz's admin replies, so wz owned every byte on the wire that
//! mattered. Here pico's C stack builds the Put — keyexpr, payload, push body — and
//! wz's admin write path has to accept it, which is the half a read-only witness
//! structurally cannot reach.
//!
//! ## The atom, and why BOTH arms are needed to witness it
//!
//! `adminspace-write`'s `F=` is not "a config PUT is applied" — it is the
//! **`permissions.write` GATE on that path** (zenoh `adminspace.rs:396`,
//! `if !permissions().write`), default-DENY (zenoh's `PermissionsConf` write:false).
//! A test that only showed a write landing would witness the config-write PLUMBING
//! while saying nothing about the gate the atom IS. So both arms are driven, from
//! pico, against the same binary:
//!
//! - GRANTED (`--config-write-permit`): pico's Put is APPLIED — peer A reconfigures
//!   its LIVE forwarder and logs `config reconfigured — now denying mesh/data`.
//! - DENIED (permit omitted): the same Put from the same pico CLI is REJECTED —
//!   `config-write DENIED (adminspace.permissions.write=false ...); ignored <key>`.
//!
//! Both are DETERMINISTIC POSITIVE EDGES. Neither arm waits for the absence of a
//! log, which would be a flake dressed up as a proof — the deny arm asserts the
//! gate's own rejection line, not the silence around it.
//!
//! ## Why the claim rides the DENY arm alone — an executed counterfactual said so
//!
//! Rebuilding the demo `--features routing-peer` (the write plumbing still present,
//! only `adminspace-write` removed) and re-running gives the answer that decides
//! the grading:
//!
//! - the DENY arm FAILS — nothing rejects, because there is no gate. It binds.
//! - the APPLY arm still PASSES — an unguarded write path applies the Put anyway.
//!
//! So the apply arm proves the config-write plumbing, NOT the atom, and it declares
//! `none`. Only the deny arm carries `adminspace-write`.
//!
//! And it must not be re-used to claim `config-mutate-runtime` either, which is the
//! trap next door: `WzConfig::reconfigure_interceptors` STORES the new config
//! unconditionally and gates only the `sink.set_interceptors` re-drive behind
//! `#[cfg(feature = "config-mutate-runtime")]` (wz-runtime-tokio/src/config.rs:442),
//! while the demo logs `config reconfigured` right after the call — so that log
//! fires with the atom compiled OUT. Its real observable is the DATA-PLANE flip
//! (`interceptor dropped`), which the wz<->wz twin asserts and this test does not.
//!
//! ## Which binary this rides
//!
//! Layer E6's — it already builds `--features routing-peer,adminspace-write` for
//! its wz<->wz twin `wz_peer_adminspace_config_write`, so the cross-impl half rides
//! the same lane and the same binary (the R311y270/y271 shape). Cargo uplifts every
//! feature variant of the same `--bin` to one path (R311y269), so a variant is only
//! safe inside the lane that built it.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

/// Spawn peer A (the config-write HOST), scrape its admin root, and return the
/// child + its stderr reader + the `@/<zid>/peer` root. `permit` grants
/// `adminspace.permissions.write`; omitting it is the default-deny arm.
fn spawn_write_host(permit: bool) -> (ChildGuard, std::fs::File, String, String) {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let stderr = tempfile::tempfile().expect("tempfile for peer A stderr");
    let writer = stderr.try_clone().expect("dup peer A stderr handle");
    let mut reader = stderr;

    let mut cmd = Command::new(&demo);
    cmd.arg("--peer")
        .arg(&addr)
        .arg("--subscribe")
        .arg("mesh/data")
        .arg("--config-writable");
    if permit {
        cmd.arg("--config-write-permit");
    }
    let mut child = ChildGuard::wrap(
        "wz-ap-demo peer A (--config-writable config-write host)",
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo peer A"),
    );

    // The config-WRITE host announces its keyexpr; that log is the barrier proving
    // the write subscriber is registered before pico's Put can race it.
    let ready = wait_for_substring(
        &mut reader,
        "adminspace config WRITE at ",
        Duration::from_secs(5),
    );
    let captured = match ready {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("peer A never registered its config-write host within 5s\n--- A ---\n{c}");
        }
    };
    let write_key = captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config WRITE at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("peer A logged the admin config-write keyexpr");
    let root = write_key
        .strip_suffix("/config/**")
        .expect("write key ends with /config/**")
        .to_string();
    drop(port_res);
    (child, reader, root, addr)
}

/// Drive pico's `z_put` CLI at A's `.../config/acl-deny`, carrying the keyexpr to
/// deny. pico ENCODES the Put; wz decodes it.
fn pico_put_acl_deny(root: &str, addr: &str) {
    let z_put = zenoh_pico_cli_binary("z_put");
    let mut child = ChildGuard::wrap(
        "z_put client (zenoh-pico)",
        Command::new(&z_put)
            .args([
                "-k",
                &format!("{root}/config/acl-deny"),
                "-v",
                "mesh/data",
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

// wz-proves: none -- the GRANT arm that makes the deny arm's rejection meaningful; it claims no atom of its own because it passes with adminspace-write compiled OUT (an unguarded write path applies anyway) and its "config reconfigured" log fires even with config-mutate-runtime OFF (reconfigure_interceptors STORES unconditionally; only the sink re-drive is cfg-gated), so it witnesses the config-write PLUMBING, not either gate
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-write + zenoh-pico z_put CLI); Layer E6 runs via --ignored"]
fn wz_peer_admin_config_write_applied_from_pico_z_put() {
    let (mut a_child, mut a_reader, root, addr) = spawn_write_host(true);
    pico_put_acl_deny(&root, &addr);

    // POSITIVE edge: A applied pico's Put to its LIVE forwarder.
    let applied = wait_for_substring(
        &mut a_reader,
        "config reconfigured — now denying mesh/data",
        Duration::from_secs(15),
    );
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait();
    if let Err(c) = applied {
        panic!(
            "peer A never applied the config write pico PUT within 15s — wz's admin \
             write path did not accept a Put encoded by zenoh-pico\n--- A ---\n{c}"
        );
    }
}

// wz-proves: adminspace-write pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-write + zenoh-pico z_put CLI); Layer E6 runs via --ignored"]
fn wz_peer_admin_config_write_denied_from_pico_z_put_without_permit() {
    let (mut a_child, mut a_reader, root, addr) = spawn_write_host(false);
    pico_put_acl_deny(&root, &addr);

    // POSITIVE edge again: the gate's OWN rejection line, not the absence of an
    // apply. `permissions.write` defaults to false (zenoh PermissionsConf), and this
    // is the atom — the same pico Put that lands under `--config-write-permit` is
    // refused without it.
    let denied = wait_for_substring(
        &mut a_reader,
        "config-write DENIED (adminspace.permissions.write=false",
        Duration::from_secs(15),
    );
    let out = match denied {
        Ok(c) => c,
        Err(c) => {
            let _ = a_child.child_mut().kill();
            let _ = a_child.child_mut().wait();
            panic!(
                "peer A never rejected the un-permitted config write within 15s — the \
                 permissions.write gate did not fire on a Put encoded by zenoh-pico\n--- A ---\n{c}"
            );
        }
    };
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait();

    // The rejection names the key pico wrote, so it cannot be some other write.
    assert!(
        out.contains(&format!("ignored {root}/config/acl-deny")),
        "the rejection names the exact key pico's z_put addressed\n--- A ---\n{out}"
    );
    // And the write was refused, not silently applied.
    let tail = read_captured(&mut a_reader);
    let all = format!("{out}{tail}");
    assert!(
        !all.contains("config reconfigured"),
        "a DENIED config write must not also reconfigure the forwarder\n--- A ---\n{all}"
    );
}

/// Drive pico's `z_pub` CLI at the keyexpr peer A subscribes to. Returned ALIVE:
/// the point of the leg below is to watch the verdict change UNDER a foreign
/// publisher that never stops, so the caller owns the guard. pico publishes once
/// a second for `n` seconds.
fn spawn_pico_pub(addr: &str, n: u32) -> ChildGuard {
    let z_pub = zenoh_pico_cli_binary("z_pub");
    ChildGuard::wrap(
        "z_pub client (zenoh-pico)",
        Command::new(&z_pub)
            .args([
                "-k",
                "mesh/data",
                "-v",
                "flip-probe",
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
                "-n",
                &n.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_pub"),
    )
}

// R311y503 — `config-mutate-runtime`'s cross-impl witness, and it exists because
// this file's own header ruled the APPLY arm above OUT of claiming it: "its real
// observable is the DATA-PLANE flip (`interceptor dropped`), which the wz<->wz
// twin asserts and this test does not". That was correct, and this leg is that
// sentence answered rather than argued.
//
// `WzConfig::reconfigure_interceptors` STORES the new config unconditionally and
// gates only the `sink.set_interceptors` RE-DRIVE behind
// `#[cfg(feature = "config-mutate-runtime")]` (wz-runtime-tokio/src/config.rs).
// So the atom is not "a config write is accepted" -- that is `adminspace-write`,
// proven one leg up -- it is "the live forwarder actually picks the new config
// up". The only way to see that from outside the process is to watch a verdict
// CHANGE on data that is already flowing.
//
// Both ends of that are foreign here: a real zenoh-pico `z_pub` is the publisher
// whose Puts get admitted and then dropped, and a real zenoh-pico `z_put` is what
// carries the new ACL in. wz is the only thing in the middle.
//
// The ordering is OWNED, never slept (three positive-edge barriers, each waiting
// for an event that can only happen after the previous one):
//   1. `received mesh data` -- A admitted foreign Puts. Without this barrier the
//      config write could land before pico's first Put and the run would prove a
//      denied-from-the-start node, not a FLIP.
//   2. `config reconfigured — now denying mesh/data` -- the write was applied.
//   3. `interceptor dropped` -- a Put from the STILL-RUNNING pico publisher hit
//      the new ACL. This is the atom: the re-drive reached the live forwarder.
// The final assertion is the causal order of (2) before (3) in the post-shutdown
// capture, so a drop that somehow preceded the reconfigure cannot pass.
// wz-proves: config-mutate-runtime pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-write + zenoh-pico z_pub/z_put CLIs); Layer E6 runs via --ignored"]
fn wz_peer_config_write_from_pico_flips_the_live_verdict_for_a_real_pico_publisher() {
    let (mut a_child, mut a_reader, root, addr) = spawn_write_host(true);

    // 60 s of foreign traffic: long enough to outlive the write + the flip, and
    // the guard kills it either way.
    let mut pico_pub = spawn_pico_pub(&addr, 60);

    let kill_all = |a: &mut ChildGuard, p: &mut ChildGuard| {
        let _ = p.child_mut().kill();
        let _ = p.child_mut().wait();
        let _ = a.child_mut().kill();
        let _ = a.child_mut().wait();
    };

    // Barrier 1 — the ADMIT edge.
    if let Err(c) = wait_for_substring(&mut a_reader, "received mesh data", Duration::from_secs(30))
    {
        kill_all(&mut a_child, &mut pico_pub);
        panic!(
            "peer A never admitted a Put from the real pico publisher within 30s — \
             there is no admit edge to flip away from\n--- A ---\n{c}"
        );
    }

    // The foreign config write.
    pico_put_acl_deny(&root, &addr);

    // Barrier 2 — the write was APPLIED.
    if let Err(c) = wait_for_substring(
        &mut a_reader,
        "config reconfigured — now denying mesh/data",
        Duration::from_secs(15),
    ) {
        kill_all(&mut a_child, &mut pico_pub);
        panic!("peer A never applied pico's config write within 15s\n--- A ---\n{c}");
    }

    // Barrier 3 — the LIVE verdict flipped for the foreign publisher.
    let flipped = wait_for_substring(
        &mut a_reader,
        "interceptor dropped",
        Duration::from_secs(30),
    );
    kill_all(&mut a_child, &mut pico_pub);
    let captured = match flipped {
        Ok(c) => c,
        Err(c) => panic!(
            "peer A dropped nothing from the real pico publisher within 30s of \
             applying the config write — the new ACL was STORED but never re-driven \
             into the live forwarder, which is exactly the half `adminspace-write` \
             does not cover\n--- A ---\n{c}"
        ),
    };

    // Causal order: the drop must FOLLOW the reconfigure. A drop that preceded it
    // would mean the node was denying already, and the leg would be proving
    // nothing about the runtime mutation.
    let reconfig_at = captured
        .find("config reconfigured")
        .expect("reconfigure line present (barrier 2 passed)");
    let dropped_at = captured
        .find("interceptor dropped")
        .expect("drop line present (barrier 3 passed)");
    assert!(
        reconfig_at < dropped_at,
        "peer A dropped a foreign Put BEFORE it applied the config write — the \
         verdict did not flip, it was already deny\n--- A ---\n{captured}"
    );
}
