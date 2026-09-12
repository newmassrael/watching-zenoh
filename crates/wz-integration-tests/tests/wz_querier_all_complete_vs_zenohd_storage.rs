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

/// R2581 — a WILDCARD querier keyexpr, for the two legs that put the
/// `includes` half of the AllComplete predicate under test.
///
/// Against [`QUERIER_KEY`], a literal, inclusion and intersection cannot
/// differ: every queryable that intersects a literal also includes it. So the
/// original pair measures the `complete` bit and says nothing about the keyexpr
/// half. Against this one they come apart — which is what makes the two
/// storages below mean different things.
const WILDCARD_QUERIER_KEY: &str = "acdemo/*/allcomplete";

/// INCLUDES [`WILDCARD_QUERIER_KEY`]: `acdemo/**` covers every key the querier
/// can ask for, so a COMPLETE storage here can answer it alone.
const WIDE_KEYEXPR: &str = "acdemo/**";

/// INTERSECTS [`WILDCARD_QUERIER_KEY`] and does NOT include it: the two meet at
/// `acdemo/matching/allcomplete`, but `acdemo/other/allcomplete` matches the
/// querier and not this. A complete storage here therefore cannot satisfy an
/// AllComplete querier, and an incomplete one cannot satisfy it either way.
const NARROW_KEYEXPR: &str = "acdemo/matching/**";

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
/// One storage as the plugin takes it: its config NAME, its keyexpr, and the
/// `complete` bit that ends up on the `DeclareQueryable` zenohd forwards.
type Storage<'a> = (&'a str, &'a str, bool);

/// Spawn a zenohd whose storage-manager holds the given memory storages. zenohd
/// EXITS if the plugin fails to load, so a returned guard means the plugin
/// loaded and every storage was accepted.
///
/// R2581 — a SLICE rather than one `complete` flag, because the question
/// `session-matching`'s third residual asks is what happens with several
/// queryables of DIFFERENT completeness behind ONE router, and that cannot be
/// posed at all with a single storage. MEASURED before this was written: zenohd
/// takes two `--cfg` storages with distinct names and echoes both back in its
/// own startup config dump, `complete` bits intact.
fn spawn_zenohd_with_storages(port: u16, storages: &[Storage<'_>]) -> ChildGuard {
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
        .arg("timestamping/enabled:true");
    for (name, keyexpr, complete) in storages {
        command.arg("--cfg").arg(format!(
            "plugins/storage_manager/storages/{name}:{{key_expr:\"{keyexpr}\",\
             volume:\"memory\",complete:{complete}}}"
        ));
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut guard = ChildGuard::wrap(
        "zenohd (storage-manager, completeness under test)",
        command.spawn().expect("spawn zenohd with storage-manager"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (storage-manager, storages={storages:?}): {e}");
    }
    guard
}

/// Drive one run and return the demo's captured stderr plus whether the
/// AllComplete listener ever spoke. Shared by every leg so no two runs can
/// drift apart in anything but the arguments named here — the property each
/// pair rests on.
///
/// R2581 — `querier_key` became a parameter alongside the storages. The two
/// original legs pass a LITERAL, against which inclusion and intersection
/// cannot differ (every intersecting queryable also includes a literal), so
/// they measure the `complete` bit alone. The legs added here pass a WILDCARD,
/// which is the only way to put the `includes` half of the AllComplete
/// predicate under test at all.
fn run_against_storages(
    storages: &[Storage<'_>],
    querier_key: &str,
    wait_for_line: bool,
) -> (String, bool) {
    let demo = wz_ap_demo_binary();
    // Both knobs this file drives landed with R311y798; a stale binary would
    // ignore them silently and the `false` run would pass for the wrong reason.
    assert_demo_binary_newer_than_sources(&demo);

    let port_res = PortReservation::pick();
    let port = port_res.port();
    let mut zenohd = spawn_zenohd_with_storages(port, storages);
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
            .arg(querier_key)
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
    let control = format!("QUERIER MATCHING STATUS keyexpr='{querier_key}' matching=true");
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

    let all_complete_line = format!("QUERIER ALLCOMPLETE MATCHING STATUS keyexpr='{querier_key}'");
    // In a run that should SEE the line, wait for it; in one that should not,
    // let the settle elapse. Waiting in both would make the refusing run pay
    // the full timeout for a result it already has.
    //
    // R2581 — `wait_for_line` is a TIMING choice and nothing else. The verdict
    // is `spoke`, which the LEG asserts on; getting this argument wrong costs
    // 25s of wall clock and cannot change what the run reports. It is passed in
    // rather than derived from `storages` because "a complete storage is
    // present" stopped predicting the answer the moment inclusion entered the
    // picture: Leg B below has one and must NOT see the line.
    let spoke = if wait_for_line {
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
    let (captured, spoke) =
        run_against_storages(&[("acdemo", STORAGE_KEYEXPR, true)], QUERIER_KEY, true);
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
    let (captured, spoke) =
        run_against_storages(&[("acdemo", STORAGE_KEYEXPR, false)], QUERIER_KEY, false);
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

/// R2581 — §5.4 `session-matching` residual (3): SEVERAL queryables of
/// DIFFERENT completeness behind ONE router.
///
/// The AGGREGATE is the claim. wz asks `any(candidate.complete &&
/// includes(candidate, target))`, mirroring zenoh's own
/// `.any(|q| q.complete && q.key_expr.includes(key_expr))`, so ONE complete
/// includer satisfies the querier however many incomplete queryables sit beside
/// it. Neither existing leg can see that: with a single storage `any` and `all`
/// agree, which is exactly why the residual names several.
///
/// ⚠ The CONTROL for this leg is NOT `any` -> `all`. `declared` holds every
/// remote queryable the session knows, so a bare `all` goes false the moment
/// zenohd propagates any unrelated one and would red the two legs above as
/// well — destroying the half of the discriminator that matters. The control
/// that isolates the aggregate is the plausible wrong implementation, "every
/// INTERSECTING queryable must be complete and include": it leaves both
/// single-storage legs green and reds this one alone.
// wz-proves: session-matching zenohd->wz
#[test]
#[ignore = "binary-dep e2e (zenohd + storage-manager + wz-ap-demo); Layer Z runs it"]
fn one_complete_includer_satisfies_the_querier_despite_an_incomplete_neighbour() {
    let (captured, spoke) = run_against_storages(
        &[
            ("wide", WIDE_KEYEXPR, true),
            ("narrow", NARROW_KEYEXPR, false),
        ],
        WILDCARD_QUERIER_KEY,
        true,
    );
    assert!(
        spoke,
        "one zenohd carries a COMPLETE storage on `{WIDE_KEYEXPR}`, which \
         includes `{WILDCARD_QUERIER_KEY}`, and an INCOMPLETE one on \
         `{NARROW_KEYEXPR}` that only intersects it. wz's AllComplete querier \
         must match, because the predicate is an ANY over the declared set and \
         one complete includer is enough. A wz that folded the set with ALL — \
         or that let an incomplete neighbour veto — reports false here while \
         both single-storage legs stay green.\n\
         --- captured demo stderr ---\n{captured}"
    );
}

/// R2581 — the same residual's other half: AllComplete demands INCLUSION, not
/// intersection.
///
/// The storage here is COMPLETE, so the bit the original pair measures is set;
/// what it is not is a cover for the querier. `acdemo/other/allcomplete`
/// matches `{WILDCARD_QUERIER_KEY}` and not `{NARROW_KEYEXPR}`, so this
/// responder cannot answer the querier's whole keyexpr by itself and must not
/// satisfy it.
///
/// ⚠ The COMPLETE storage has to be the merely-intersecting one, and that is
/// not interchangeable: under `complete_required` an incomplete candidate is
/// rejected by the `complete` conjunct BEFORE the keyexpr test runs, so an
/// arrangement that made the incomplete storage the narrow one would green
/// under both `includes` and `intersects` and measure nothing.
// wz-proves: session-matching zenohd->wz
#[test]
#[ignore = "binary-dep e2e (zenohd + storage-manager + wz-ap-demo); Layer Z runs it"]
fn a_complete_storage_that_only_intersects_does_not_satisfy_an_all_complete_querier() {
    let (captured, spoke) = run_against_storages(
        &[("narrow", NARROW_KEYEXPR, true)],
        WILDCARD_QUERIER_KEY,
        false,
    );
    assert!(
        !spoke,
        "a storage declared `complete:true` on `{NARROW_KEYEXPR}` INTERSECTS \
         `{WILDCARD_QUERIER_KEY}` without including it, so it cannot answer the \
         querier's whole keyexpr alone and must not satisfy AllComplete — while \
         the ordinary querier's `matching=true` proves the declaration arrived. \
         A wz that tested intersection here would report true, and no leg in \
         this file that uses a literal querier key could ever tell.\n\
         --- captured demo stderr ---\n{captured}"
    );
}
