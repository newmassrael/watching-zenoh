// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y799 — the ACCEPT half of the `AllComplete` verdict, witnessed by a real
//! zenoh encoder that sets the bit.
//!
//! ## The gap this closes, and why its sibling could not
//!
//! `wz_querier_all_complete_vs_pico_queryable` (R311y798) put a real foreign
//! process on the REFUSING side: stock zenoh-pico declares `complete = false`
//! and omits the QueryableInfo ext entirely, so wz's reading of that absence is
//! bound against a real encoder. Its acceptance leg is driven by wz's own
//! session-local queryable, which means the `true` side of the bit was still
//! only ever witnessed against wz's own encoder. That was recorded as the
//! round's named residual.
//!
//! zenoh-pico cannot close it: its stock `z_queryable` example takes no
//! completeness option (`examples/unix/c11/z_queryable.c`'s `getopt` string is
//! `"k:v:e:m:l:n:"`), so a pico-based `complete = true` would need a patched
//! oracle — which is exactly the kind of wz-modified witness this corpus keeps
//! out. zenoh-full can: the storage-manager plugin declares its storage's
//! queryable with `.complete(self.configuration.complete)`
//! (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs:154`),
//! and that field is a plain config key
//! (`plugins/zenoh-backend-traits/src/config.rs:63`, parsed at `:446-460`).
//! So the bit is settable from the command line of a stock zenohd.
//!
//! ## Two runs, one config key apart
//!
//! Both spawn the same zenohd with the same storage on the same keyexpr and the
//! same wz client; the ONLY difference is `complete:true` vs `complete:false` in
//! the storage config string. The `false` run is not decoration — it is what
//! makes the `true` run mean something, because a wz that ignored the bit
//! entirely would pass the `true` run on its own.
//!
//! ## This also MEASURES the router question R311y798 left open
//!
//! zenoh does not forward a declarer's `QueryableInfo` verbatim: its routing
//! tables MERGE the info across faces before propagating. R311y798 recorded
//! that as an unexamined difference — wz has no merge at all, which is right
//! for a direct peer and unexamined for a routed one. With ONE storage behind
//! the router the merge has a single input, so what wz reads is that storage's
//! own bit; these two runs establish that the routed path preserves it in both
//! directions. What they do NOT establish is what wz should do when several
//! queryables with DIFFERENT completeness sit behind one router, which stays
//! open and is now open with a measurement behind it rather than a guess.
//!
//! ## Why the ordinary querier rides along
//!
//! Both runs also carry the plain `--querier-matching-log` querier, and in the
//! `false` run its `matching=true` is the control: it proves zenohd forwarded
//! the declaration at all, so the AllComplete listener's silence is about the
//! bit and not about the router withholding the queryable (the failure mode
//! `wz_querier_matching_through_zenohd_router` exists to catch).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, storage_manager_plugin,
    wait_for_substring, wait_for_tcp_accept_alive, wz_ap_demo_binary, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};

/// The storage's keyexpr, and therefore the queryable zenohd declares for it. A
/// wildcard that INCLUDES the querier's literal, so the keyexpr half of the
/// AllComplete predicate is satisfied and only `complete` can decide.
const STORAGE_KEYEXPR: &str = "acdemo/**";
/// wz's querier keyexpr — a literal on both queriers.
const QUERIER_KEY: &str = "acdemo/matching/allcomplete";

/// Ceiling for the rise. Same budget and reasoning as
/// `wz_querier_matching_through_zenohd_router`: wz dials zenohd and Establishes,
/// declares the listeners (which emit the Interest), zenohd answers from its
/// CURRENT dump, and the demo's deferred-fire drain runs on the sweep task's
/// 100ms cadence.
const MATCHING_TIMEOUT: Duration = Duration::from_secs(25);

/// How long to let the AllComplete listener stay silent after the ordinary one
/// has spoken. Both are fed by the same dispatch of the same declaration, so
/// this is slack for one deferred-fire drain rather than for the router.
const SETTLE_AFTER_CONTROL: Duration = Duration::from_secs(3);

/// Spawn a zenohd whose storage-manager holds ONE memory storage on
/// [`STORAGE_KEYEXPR`], declared with the given completeness. zenohd EXITS if
/// the plugin fails to load, so a returned guard means the plugin loaded and
/// the storage was accepted.
fn spawn_zenohd_with_storage(port: u16, complete: bool) -> ChildGuard {
    let storage_cfg = format!(
        "plugins/storage_manager/storages/acdemo:{{key_expr:\"{STORAGE_KEYEXPR}\",\
         volume:\"memory\",complete:{complete}}}"
    );
    let plugin = storage_manager_plugin();
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        .arg("--plugin")
        .arg(format!("storage_manager:{}", plugin.display()))
        .arg("--cfg")
        .arg("timestamping/enabled:true")
        .arg("--cfg")
        .arg(&storage_cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guard = ChildGuard::wrap(
        "zenohd (storage-manager, completeness under test)",
        command.spawn().expect("spawn zenohd with storage-manager"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (storage-manager, complete={complete}): {e}");
    }
    guard
}

/// Drive one run and return the demo's captured stderr plus whether the
/// AllComplete listener ever spoke. Shared by both tests so the two runs cannot
/// drift apart in anything but the `complete` argument — the property the pair
/// rests on.
fn run_against_storage(complete: bool) -> (String, bool) {
    let demo = wz_ap_demo_binary();
    // Both knobs this file drives landed with R311y798; a stale binary would
    // ignore them silently and the `false` run would pass for the wrong reason.
    assert_demo_binary_newer_than_sources(&demo);

    let port_res = PortReservation::pick();
    let port = port_res.port();
    let mut zenohd = spawn_zenohd_with_storage(port, complete);
    drop(port_res);

    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd, both matching queriers)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--querier-matching-log")
            .arg(QUERIER_KEY)
            .arg("--querier-matching-all-complete")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    // ANTI-VACUITY: both listeners exist. With `session-matching` off the demo
    // WARNs instead, and every wait below would time out blaming the router.
    for line in [
        "DECLARED QUERIER MATCHING LISTENER",
        "DECLARED QUERIER ALLCOMPLETE MATCHING LISTENER",
    ] {
        if let Err(captured) = wait_for_substring(&mut demo_stderr_reader, line, MATCHING_TIMEOUT) {
            let _ = demo_child.child_mut().kill();
            let _ = zenohd.child_mut().kill();
            panic!(
                "wz-ap-demo never logged '{line}', so this run proves NOTHING \
                 about the AllComplete semantic\n\
                 --- captured demo stderr ---\n{captured}"
            );
        }
    }

    // THE CONTROL, and the synchronisation point: zenohd forwarded the storage's
    // queryable at all. Both runs assert it, because in both runs the ordinary
    // querier must match regardless of completeness.
    let control = format!("QUERIER MATCHING STATUS keyexpr='{QUERIER_KEY}' matching=true");
    if let Err(captured) = wait_for_substring(&mut demo_stderr_reader, &control, MATCHING_TIMEOUT) {
        let _ = demo_child.child_mut().kill();
        let _ = zenohd.child_mut().kill();
        panic!(
            "wz's ORDINARY querier never rose behind zenohd, so the storage's \
             queryable never reached wz and nothing downstream can mean \
             anything. Either wz emitted no QUERYABLES interest or zenohd did \
             not answer it.\n--- captured demo stderr ---\n{captured}"
        );
    }

    let all_complete_line = format!("QUERIER ALLCOMPLETE MATCHING STATUS keyexpr='{QUERIER_KEY}'");
    // In the accepting run, WAIT for the line; in the refusing run, let the
    // settle elapse. Waiting in both would make the refusing run pay the full
    // timeout for a result it already has.
    let spoke = if complete {
        wait_for_substring(
            &mut demo_stderr_reader,
            &all_complete_line,
            MATCHING_TIMEOUT,
        )
        .is_ok()
    } else {
        std::thread::sleep(SETTLE_AFTER_CONTROL);
        read_captured(&mut demo_stderr_reader).contains(&all_complete_line)
    };

    let captured = read_captured(&mut demo_stderr_reader);
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    (captured, spoke)
}

// wz-proves: session-matching zenohd->wz
#[test]
#[ignore = "binary-dep e2e (zenohd + storage-manager + wz-ap-demo); Layer Z runs it"]
fn a_zenohd_storage_declared_complete_satisfies_an_all_complete_wz_querier() {
    let (captured, spoke) = run_against_storage(true);
    assert!(
        spoke,
        "a zenoh storage declared `complete:true` puts the QueryableInfo C bit \
         on its DeclareQueryable, and its keyexpr `{STORAGE_KEYEXPR}` includes \
         `{QUERIER_KEY}` — so wz's AllComplete querier must match it. This is \
         the only leg in the corpus where a FOREIGN encoder sets the bit; its \
         sibling against zenoh-pico can only ever clear it.\n\
         --- captured demo stderr ---\n{captured}"
    );
}

// wz-proves: session-matching zenohd->wz
#[test]
#[ignore = "binary-dep e2e (zenohd + storage-manager + wz-ap-demo); Layer Z runs it"]
fn a_zenohd_storage_declared_incomplete_does_not_satisfy_it() {
    let (captured, spoke) = run_against_storage(false);
    assert!(
        !spoke,
        "the same zenohd, the same storage keyexpr and the same wz client, one \
         config key apart (`complete:false`), must NOT satisfy the AllComplete \
         querier — and the ordinary querier's `matching=true` above proves the \
         declaration did arrive. Without this run its twin would be satisfied by \
         a wz that ignored the bit entirely.\n\
         --- captured demo stderr ---\n{captured}"
    );
}
