// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y498 — §5.27 `api-compat-c`: upstream's own zenoh-c example, compiled
//! against upstream's own header, linked against WZ's cdylib, put onto a real wz
//! subscriber — and the SAME source linked against the REAL `libzenohc.so` as a
//! reference arm.
//!
//! ## Two arms, because they answer different questions
//!
//! The sibling atom (`api-compat-pico`) is proven by compiling upstream's
//! examples against wz's cdylib, and its file states the reason plainly: *"a
//! wz-authored C program would be written against the exports wz happens to have,
//! which is precisely the bias that let the atom sit at BUILT while its headline
//! claim was unwitnessed."* That objection is correct and it applies here, so the
//! corpus is upstream's.
//!
//! But upstream's examples alone establish only that the program LINKS and that
//! one leg works. They cannot show that wz's answers are the same answers. This
//! atom has something its sibling does not — the real implementation is installed
//! on the machine — so the same binary is built twice and both are run:
//!
//! - ARM REF: upstream `z_put.c` + upstream header + **`libzenohc.so`**;
//! - ARM WZ:  upstream `z_put.c` + upstream header + **`libwz_capi_c.so`**.
//!
//! Representativeness comes from the program being upstream's; equivalence comes
//! from the reference arm. Neither alone is the claim.
//!
//! ## A FRESH observer per arm, and that is not hygiene
//!
//! The first hand-run of this differential reported the drop-in arm failing to
//! open, and the cause was the harness: `wz-ap-demo --listen` serves ONE session,
//! and the reference arm had already consumed it. A probe showed `z_open` = 0
//! against a live listener, which cleared wz before the harness was touched. Each
//! arm therefore gets its own observer on its own port here — a shared one makes
//! the second arm's result depend on the first.
//!
//! ## The oracle is machine-local
//!
//! zenoh-c's headers, its library and its example clone are not in this repo.
//! Absence is reported LOUDLY and the leg returns, because a silent skip is a
//! green test that proved nothing; the LANE decides whether that is acceptable
//! (`WZ_C1CC_REQUIRE` turns it into a hard failure on the job that provisions the
//! oracle). Override the locations with `WZ_ZENOH_C_PREFIX` /
//! `WZ_ZENOH_C_EXAMPLES`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    compile_zenoh_c_example, wait_for_substring, wz_ap_demo_binary, wz_capi_c_cdylib,
    zenoh_c_oracle, ChildGuard, PortReservation,
};

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<(PathBuf, PathBuf, PathBuf)> {
    match zenoh_c_oracle() {
        Some(o) => Some(o),
        None => {
            eprintln!(
                "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers \
                 and libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX) \
                 AND a clone of its examples (default ~/zenoh-c-ref/examples, override \
                 WZ_ZENOH_C_EXAMPLES: `git clone --depth 1 --branch 1.5.0 \
                 https://github.com/eclipse-zenoh/zenoh-c ~/zenoh-c-ref`). Layer C1cc \
                 with WZ_C1CC_REQUIRE=1 fails instead of skipping."
            );
            None
        }
    }
}

/// One arm: spawn a fresh wz subscriber, run `program` at it, and return what the
/// subscriber logged.
///
/// The observer is `wz-ap-demo --listen <addr> --key <filter>`, a real wz node —
/// so the adjudicating party is neither the C program nor this test.
fn run_arm(program: &Path, libdir: &Path, keyexpr: &str, payload: &str, arm: &str) -> String {
    let stderr = tempfile::tempfile().expect("tempfile for observer stderr");
    let writer = stderr.try_clone().expect("dup observer stderr handle");
    let mut reader = stderr;

    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());
    let mut observer = ChildGuard::wrap(
        format!("wz-ap-demo --listen ({arm})"),
        Command::new(wz_ap_demo_binary())
            .args(["--listen", &addr, "--key", "demo/example/**"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn the wz observer"),
    );
    drop(port);

    if let Err(c) = wait_for_substring(&mut reader, "listening on", Duration::from_secs(15)) {
        let _ = observer.child_mut().kill();
        panic!("the wz observer ({arm}) never bound within 15s\n--- observer ---\n{c}");
    }

    let out = Command::new(program)
        .args(["-e", &format!("tcp/{addr}"), "-k", keyexpr, "-p", payload])
        .env("LD_LIBRARY_PATH", libdir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run the {arm} program: {e}"));
    assert!(
        out.status.success(),
        "the {arm} program exited {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let observed = wait_for_substring(&mut reader, "SUBSCRIBER FIRED", Duration::from_secs(15));
    let _ = observer.child_mut().kill();
    match observed {
        Ok(c) => c,
        Err(c) => panic!(
            "the wz subscriber never received the sample the {arm} program put\n\
             --- program stdout ---\n{}\n--- observer ---\n{c}",
            String::from_utf8_lossy(&out.stdout)
        ),
    }
}

/// The `SUBSCRIBER FIRED` line's keyexpr and payload length, which is what the two
/// arms are compared on.
fn fired(log: &str) -> Option<(String, usize)> {
    let line = log.lines().find(|l| l.contains("SUBSCRIBER FIRED"))?;
    let ke = line
        .split("keyexpr='")
        .nth(1)?
        .split('\'')
        .next()?
        .to_owned();
    let len = line
        .split("payload_len=")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((ke, len))
}

/// ## Why this file carries NO cross-impl proof annotation at all
///
/// The first draft claimed `api-compat-c wz->wz partial`, and Layer A4 refused it
/// twice, each time for a better reason than the last. First the GRAMMAR: there
/// is no `wz->wz` kind, because A4 scores a foreign IMPLEMENTATION on the wire
/// opposite wz and neither leg puts one there — the C program links WZ's library
/// and the observer is a wz node. Then, rewritten to `none -- <reason>`, A4-3
/// refused that too: a file whose classifier finds no foreign implementation may
/// not annotate at all, not even to decline.
///
/// Both refusals are correct, and the second states something worth keeping: A4's
/// class vocabulary is pico / zenohd / zenoh-ext, and zenoh-c is not in it. That
/// is a real gap — the reference arm DOES link a foreign implementation — but
/// widening the audit's vocabulary changes what every number in it means, so it
/// belongs to a round that decides it rather than to one that needs it.
///
/// The leg that would earn the axis is named rather than implied: upstream's
/// `z_sub.c` running on the REAL `libzenohc.so`, subscribing to a wz publisher.
/// That needs the closure and channel families, so it is a later slice; claiming
/// the axis before then is exactly the over-claim A4 exists to refuse.
///
/// R311y498 — THE drop-in leg. Upstream's `z_put.c` links against wz's cdylib and
/// a real wz subscriber receives what it published.
///
/// The claim is `partial` and the reason is exact: one upstream example of the 22
/// that compile against this oracle build. The lane prints that ratio every run.
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and needs the machine-local \
            zenoh-c oracle; run-ci Layer C1cc drives it"]
fn upstream_z_put_links_against_wz_capi_c_and_a_real_wz_subscriber_receives_it() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled arms");
    let wz_lib = wz_capi_c_cdylib();
    let libdir_wz = wz_lib.parent().expect("cdylib has a parent").to_path_buf();

    // ARM WZ — upstream source, upstream header, WZ's implementation.
    let on_wz = compile_zenoh_c_example(
        "z_put",
        dir.path(),
        &include,
        &examples,
        &libdir_wz,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: upstream z_put.c does NOT link against wz's C-ABI \
             cdylib, so wz is not a binary drop-in for it.\n{diag}"
        )
    });

    // ARM REF — the same source against the real implementation. If THIS fails,
    // the finding is about the oracle or the harness, never about wz.
    let on_ref = compile_zenoh_c_example(
        "z_put",
        dir.path(),
        &include,
        &examples,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "the REFERENCE arm did not build: upstream z_put.c against upstream's own \
             libzenohc. That is an oracle problem, not a wz one.\n{diag}"
        )
    });

    let ref_log = run_arm(&on_ref, &libdir_ref, "demo/example/x", "REFERENCE", "ref");
    let wz_log = run_arm(&on_wz, &libdir_wz, "demo/example/x", "DROPIN-XX", "wz");

    let (ref_ke, ref_len) = fired(&ref_log).expect("the reference arm's FIRED line parses");
    let (wz_ke, wz_len) = fired(&wz_log).expect("the drop-in arm's FIRED line parses");

    assert_eq!(
        wz_ke, ref_ke,
        "the two arms delivered DIFFERENT keyexprs from the same source: wz {wz_ke:?} \
         vs upstream {ref_ke:?}. The program is identical, so this is wz's keyexpr \
         handling diverging from zenoh-c's."
    );
    // The payloads are chosen the same LENGTH on purpose, so this compares what
    // arrived rather than what was typed — a wz put that dropped or padded bytes
    // would show up here and nowhere else in this file.
    assert_eq!(
        wz_len, ref_len,
        "the two arms delivered payloads of different length ({wz_len} vs {ref_len}) \
         for equal-length inputs, so wz's payload framing diverges from zenoh-c's"
    );
}

/// R311y498 — the LAYOUT gate, derived rather than transcribed.
///
/// `wz-capi-c/src/abi.rs` asserts its own footprints at compile time, which
/// catches a mistake in that file and CANNOT catch the header moving underneath
/// it: `zenoh_opaque.h` is generated per zenoh-c version and per `Z_FEATURE_*`
/// set. So this leg asks a C compiler what upstream's types measure — on this
/// installation, with this feature set — and compares that to what the cdylib
/// reports through `wz_capi_c_layout()`.
///
/// Neither side is a list someone remembered to update: one is the installed
/// header, the other is `size_of` inside the shipped library.
///
/// ## R311y539 — the export is an ARRAY now, and the count is asserted
///
/// This test used to declare a `#[repr(C)]` struct in parallel with the
/// cdylib's, and its own comment named the hazard: the cdylib writes through
/// the pointer, so a test copy NARROWER than the exported struct is a silent
/// stack overwrite in the test process. Widening the table from twenty entries
/// to fifty made that a question of when.
///
/// The array form removes it structurally. This side says how many slots it
/// has, the cdylib writes at most that many and returns the TRUE count, and the
/// count is asserted first — so a width disagreement is a failed assertion on an
/// integer, not memory corruption. The NAMES still have to be kept in step with
/// the C probe below, which is what the per-entry message is for.
#[test]
#[ignore = "compiles a C probe against the machine-local zenoh-c headers; run-ci \
            Layer C1cc drives it"]
fn the_wz_capi_c_type_footprints_equal_upstreams_on_this_installation() {
    let Some((include, _libdir_ref, _examples)) = oracle_or_note() else {
        return;
    };
    // WHICH zenoh-c build this is, read BEFORE the probe list is built rather
    // than after it. R311y543: the `ze_advanced_*` plane is
    // `#if defined(Z_FEATURE_UNSTABLE_API)` in upstream's header, so on a
    // no-unstable oracle a probe naming those types does not COMPILE — the
    // feature set has to be known before the probe source is written, not only
    // in time to advise about a mismatch.
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h"))
        .expect("the oracle ships zenoh_configure.h");
    let unstable = configure.contains("#define Z_FEATURE_UNSTABLE_API");
    let shm = unstable && configure.contains("#define Z_FEATURE_SHARED_MEMORY");

    // (name, C expression). ONE list, so the name and the thing measured cannot
    // drift apart — the previous shape kept them in two.
    let base: &[(&str, &str)] = &[
        ("z_owned_session_t", "sizeof(z_owned_session_t)"),
        ("z_owned_bytes_t", "sizeof(z_owned_bytes_t)"),
        ("z_view_keyexpr_t", "sizeof(z_view_keyexpr_t)"),
        ("z_owned_config_t", "sizeof(z_owned_config_t)"),
        ("align", "_Alignof(z_owned_session_t)"),
        ("z_owned_subscriber_t", "sizeof(z_owned_subscriber_t)"),
        ("z_owned_string_t", "sizeof(z_owned_string_t)"),
        (
            "z_owned_closure_sample_t",
            "sizeof(z_owned_closure_sample_t)",
        ),
        (
            "z_owned_liveliness_token_t",
            "sizeof(z_owned_liveliness_token_t)",
        ),
        ("z_owned_publisher_t", "sizeof(z_owned_publisher_t)"),
        ("z_publisher_options_t", "sizeof(z_publisher_options_t)"),
        (
            "z_publisher_put_options_t",
            "sizeof(z_publisher_put_options_t)",
        ),
        ("z_owned_encoding_t", "sizeof(z_owned_encoding_t)"),
        ("z_owned_closure_zid_t", "sizeof(z_owned_closure_zid_t)"),
        (
            "z_owned_closure_matching_status_t",
            "sizeof(z_owned_closure_matching_status_t)",
        ),
        ("z_id_t", "sizeof(z_id_t)"),
        ("z_id_t/align", "_Alignof(z_id_t)"),
        ("z_clock_t", "sizeof(z_clock_t)"),
        (
            "z_liveliness_subscriber_options_t",
            "sizeof(z_liveliness_subscriber_options_t)",
        ),
        ("z_matching_status_t", "sizeof(z_matching_status_t)"),
        // R311y539 — the query / reply / channel / sync / serialization planes.
        // Every one of these is STACK-ALLOCATED by an upstream example, which is
        // why a wrong size corrupts the caller's frame rather than failing to
        // link.
        ("z_owned_sample_t", "sizeof(z_owned_sample_t)"),
        ("z_owned_queryable_t", "sizeof(z_owned_queryable_t)"),
        ("z_owned_querier_t", "sizeof(z_owned_querier_t)"),
        ("z_owned_query_t", "sizeof(z_owned_query_t)"),
        ("z_owned_reply_t", "sizeof(z_owned_reply_t)"),
        ("z_owned_hello_t", "sizeof(z_owned_hello_t)"),
        ("z_owned_string_array_t", "sizeof(z_owned_string_array_t)"),
        ("z_owned_bytes_writer_t", "sizeof(z_owned_bytes_writer_t)"),
        ("ze_owned_serializer_t", "sizeof(ze_owned_serializer_t)"),
        (
            "z_owned_fifo_handler_reply_t",
            "sizeof(z_owned_fifo_handler_reply_t)",
        ),
        (
            "z_owned_fifo_handler_query_t",
            "sizeof(z_owned_fifo_handler_query_t)",
        ),
        (
            "z_owned_ring_handler_sample_t",
            "sizeof(z_owned_ring_handler_sample_t)",
        ),
        ("z_owned_mutex_t", "sizeof(z_owned_mutex_t)"),
        ("z_owned_condvar_t", "sizeof(z_owned_condvar_t)"),
        ("z_owned_condvar_t/align", "_Alignof(z_owned_condvar_t)"),
        ("z_loaned_condvar_t", "sizeof(z_loaned_condvar_t)"),
        ("z_loaned_condvar_t/align", "_Alignof(z_loaned_condvar_t)"),
        ("z_owned_slice_t", "sizeof(z_owned_slice_t)"),
        ("z_owned_closure_query_t", "sizeof(z_owned_closure_query_t)"),
        ("z_owned_closure_reply_t", "sizeof(z_owned_closure_reply_t)"),
        ("z_owned_closure_hello_t", "sizeof(z_owned_closure_hello_t)"),
        ("z_bytes_reader_t", "sizeof(z_bytes_reader_t)"),
        (
            "z_bytes_slice_iterator_t",
            "sizeof(z_bytes_slice_iterator_t)",
        ),
        ("ze_deserializer_t", "sizeof(ze_deserializer_t)"),
        ("z_get_options_t", "sizeof(z_get_options_t)"),
        ("z_queryable_options_t", "sizeof(z_queryable_options_t)"),
        ("z_query_reply_options_t", "sizeof(z_query_reply_options_t)"),
        (
            "z_liveliness_get_options_t",
            "sizeof(z_liveliness_get_options_t)",
        ),
        ("z_querier_options_t", "sizeof(z_querier_options_t)"),
        ("z_querier_get_options_t", "sizeof(z_querier_get_options_t)"),
        ("z_scout_options_t", "sizeof(z_scout_options_t)"),
        // R311y543 — the base subscriber options. Not unstable-gated, and the
        // struct `ze_advanced_subscriber_options_t` embeds at offset 0.
        ("z_subscriber_options_t", "sizeof(z_subscriber_options_t)"),
        ("z_put_options_t", "sizeof(z_put_options_t)"),
        ("z_delete_options_t", "sizeof(z_delete_options_t)"),
        // R311y557 — `z_timestamp_t`, the type the option structs' `timestamp`
        // field points at. Its ALIGNMENT is measured beside its size for the
        // reason `abi.rs` states: upstream declares it `ALIGN(8)` over a
        // 24-byte array, and 24 bytes at align 4 would compare equal on size.
        ("z_timestamp_t", "sizeof(z_timestamp_t)"),
        ("z_timestamp_t/align", "_Alignof(z_timestamp_t)"),
        // R311y564 — the OWNED keyexpr, newly declared so the
        // `z_keyexpr_from_str` / `z_declare_keyexpr` family has a result type.
        // `z_get.c` and `z_pub.c` both stack-allocate one.
        ("z_owned_keyexpr_t", "sizeof(z_owned_keyexpr_t)"),
        // R311y565 — the DEL reply options, newly declared this round.
        (
            "z_query_reply_del_options_t",
            "sizeof(z_query_reply_del_options_t)",
        ),
        // R311y565 — the other three channel handlers.
        (
            "z_owned_fifo_handler_sample_t",
            "sizeof(z_owned_fifo_handler_sample_t)",
        ),
        (
            "z_owned_ring_handler_query_t",
            "sizeof(z_owned_ring_handler_query_t)",
        ),
        (
            "z_owned_ring_handler_reply_t",
            "sizeof(z_owned_ring_handler_reply_t)",
        ),
        // R311y568 — the seven types the DROP-IN CENSUS forced into existence.
        // Order matches `WZ_CAPI_C_LAYOUT_NAMES`'s tail exactly; the two tables
        // are compared index for index.
        ("z_owned_reply_err_t", "sizeof(z_owned_reply_err_t)"),
        ("z_owned_task_t", "sizeof(z_owned_task_t)"),
        ("z_task_attr_t", "sizeof(z_task_attr_t)"),
        (
            "z_query_reply_err_options_t",
            "sizeof(z_query_reply_err_options_t)",
        ),
        (
            "z_publisher_delete_options_t",
            "sizeof(z_publisher_delete_options_t)",
        ),
        ("z_query_consolidation_t", "sizeof(z_query_consolidation_t)"),
        ("zc_owned_closure_log_t", "sizeof(zc_owned_closure_log_t)"),
        (
            "z_loaned_closure_matching_status_t",
            "sizeof(z_loaned_closure_matching_status_t)",
        ),
    ];
    // R311y543 — the `ze_advanced_*` plane, measured ONLY where upstream
    // declares it. The order must match `abi.rs`'s
    // `WZ_CAPI_C_LAYOUT_NAMES_UNSTABLE` exactly: the two tables are compared
    // index for index, so a reordering here compares an advanced publisher
    // against a miss closure and passes or fails for the wrong reason.
    let unstable_probes: &[(&str, &str)] = &[
        ("z_entity_global_id_t", "sizeof(z_entity_global_id_t)"),
        (
            "z_entity_global_id_t/align",
            "_Alignof(z_entity_global_id_t)",
        ),
        ("ze_miss_t", "sizeof(ze_miss_t)"),
        ("ze_owned_closure_miss_t", "sizeof(ze_owned_closure_miss_t)"),
        (
            "ze_owned_advanced_publisher_t",
            "sizeof(ze_owned_advanced_publisher_t)",
        ),
        (
            "ze_owned_advanced_subscriber_t",
            "sizeof(ze_owned_advanced_subscriber_t)",
        ),
        (
            "ze_owned_sample_miss_listener_t",
            "sizeof(ze_owned_sample_miss_listener_t)",
        ),
        (
            "ze_advanced_publisher_cache_options_t",
            "sizeof(ze_advanced_publisher_cache_options_t)",
        ),
        (
            "ze_advanced_publisher_sample_miss_detection_options_t",
            "sizeof(ze_advanced_publisher_sample_miss_detection_options_t)",
        ),
        (
            "ze_advanced_publisher_options_t",
            "sizeof(ze_advanced_publisher_options_t)",
        ),
        (
            "ze_advanced_publisher_put_options_t",
            "sizeof(ze_advanced_publisher_put_options_t)",
        ),
        (
            "ze_advanced_subscriber_history_options_t",
            "sizeof(ze_advanced_subscriber_history_options_t)",
        ),
        (
            "ze_advanced_subscriber_last_sample_miss_detection_options_t",
            "sizeof(ze_advanced_subscriber_last_sample_miss_detection_options_t)",
        ),
        (
            "ze_advanced_subscriber_recovery_options_t",
            "sizeof(ze_advanced_subscriber_recovery_options_t)",
        ),
        (
            "ze_advanced_subscriber_options_t",
            "sizeof(ze_advanced_subscriber_options_t)",
        ),
    ];
    // R311y543 — the SHM provider / buffer plane. Upstream gates every one of
    // these on `Z_FEATURE_SHARED_MEMORY` AND `Z_FEATURE_UNSTABLE_API` together,
    // so this is a third half rather than the unstable half widened. Same
    // ordering obligation as above, against `WZ_CAPI_C_LAYOUT_NAMES_SHM`.
    let shm_probes: &[(&str, &str)] = &[
        ("z_owned_shm_t", "sizeof(z_owned_shm_t)"),
        ("z_owned_shm_mut_t", "sizeof(z_owned_shm_mut_t)"),
        ("z_owned_shm_provider_t", "sizeof(z_owned_shm_provider_t)"),
        ("z_alloc_alignment_t", "sizeof(z_alloc_alignment_t)"),
        (
            "z_buf_layout_alloc_result_t",
            "sizeof(z_buf_layout_alloc_result_t)",
        ),
        ("z_buf_alloc_result_t", "sizeof(z_buf_alloc_result_t)"),
    ];
    let probes: Vec<(&str, &str)> = base
        .iter()
        .chain(if unstable { unstable_probes } else { &[] }.iter())
        .chain(if shm { shm_probes } else { &[] }.iter())
        .copied()
        .collect();

    let dir = tempfile::tempdir().expect("tempdir for the layout probe");
    let src = dir.path().join("layout.c");
    let body: String = probes
        .iter()
        .map(|(_, expr)| format!("    printf(\"%zu\\n\", {expr});\n"))
        .collect();
    std::fs::write(
        &src,
        format!("#include <stdio.h>\n#include \"zenoh.h\"\nint main(void) {{\n{body}    return 0;\n}}\n"),
    )
    .expect("write the layout probe");

    let exe = dir.path().join("layout");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let build = Command::new(&cc)
        .arg(&src)
        .arg("-std=c11")
        .arg(format!("-I{}", include.display()))
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("spawn the C compiler");
    assert!(
        build.status.success(),
        "the layout probe did not compile against upstream's headers\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let out = Command::new(&exe).output().expect("run the layout probe");
    let text = String::from_utf8_lossy(&out.stdout);
    let upstream: Vec<usize> = text
        .split_whitespace()
        .map(|t| t.parse().expect("the probe prints one integer per field"))
        .collect();
    assert_eq!(upstream.len(), probes.len(), "probe output: {text:?}");

    // What the SHIPPED cdylib says about itself, read through its own export.
    let lib = wz_capi_c_cdylib();
    // SAFETY: loading wz's own freshly built cdylib and calling its documented
    // layout-report export, which writes at most `cap` `usize`s through the
    // out-param and returns the true count.
    let (mine, total) = unsafe {
        let handle = libloading::Library::new(&lib).expect("dlopen wz's cdylib");
        let f = handle
            .get::<unsafe extern "C" fn(*mut usize, usize) -> usize>(b"wz_capi_c_layout\0")
            .expect("the cdylib exports wz_capi_c_layout");
        let mut out = vec![0usize; probes.len()];
        let total = f(out.as_mut_ptr(), out.len());
        (out, total)
    };
    // Asserted BEFORE the values are read: a cdylib that reports more entries
    // than this probe measures means someone widened `abi.rs` without widening
    // the C side, and comparing the truncated prefix would pass while leaving
    // the new types unchecked.
    assert_eq!(
        total,
        probes.len(),
        "the cdylib reports {total} footprint entries and this probe measures {}. \
         Widen the `probes` table above in the same commit as `abi.rs`.",
        probes.len()
    );

    // WHICH zenoh-c build this is. `Z_FEATURE_UNSTABLE_API` changes type SIZES,
    // not just option fields — `z_owned_bytes_t` is 40 with it and 32 without —
    // so the message can name the cargo feature to flip instead of leaving a
    // reader with two numbers and no next step.
    // TWO axes, not one. R311y540 measured that `Z_FEATURE_SHARED_MEMORY` moves
    // 8 of the types below and `Z_FEATURE_UNSTABLE_API` moves 2, so advice that
    // named only the unstable axis sent a reader to the wrong build the moment
    // this ran against the SHM oracle — which is exactly what R311y541's probe
    // caught it doing.
    let mut wanted: Vec<&str> = Vec::new();
    if !unstable {
        wanted.push("zenoh-c-no-unstable-api");
    }
    if configure.contains("#define Z_FEATURE_SHARED_MEMORY") {
        wanted.push("zenoh-c-shared-memory");
    }
    let advice = if wanted.is_empty() {
        "this oracle defines NEITHER Z_FEATURE_UNSTABLE_API's absence nor \
         Z_FEATURE_SHARED_MEMORY, so build wz-capi-c with its DEFAULT features"
            .to_string()
    } else {
        format!(
            "this oracle's zenoh_configure.h selects wz-capi-c --features {}",
            wanted.join(",")
        )
    };

    let mut disagreements: Vec<String> = Vec::new();
    for (i, (name, _)) in probes.iter().enumerate() {
        if mine[i] != upstream[i] {
            disagreements.push(format!(
                "  {name}: wz says {}, this installation's zenoh-c header says {}",
                mine[i], upstream[i]
            ));
        }
    }
    // R2239 — REPORT ALL OF THEM, not the first.
    //
    // This was an `assert_eq!` inside the loop, so an upstream version bump
    // that moved N footprints surfaced as ONE name per run. Moving the zenoh-c
    // pin to 1.10.0 moved eleven opaque types and a transparent one, and
    // finding them one build at a time is how a single version bump becomes
    // several rounds. The sibling `capi_c_opaque_arms.py` already collects
    // before it fails; this now matches it.
    assert!(
        disagreements.is_empty(),
        "{} of {} type footprint(s) disagree with this installation's zenoh-c \
         header. A drop-in whose types are a different SIZE is not a drop-in — \
         the C side stack-allocates these. {advice}.\n{}",
        disagreements.len(),
        probes.len(),
        disagreements.join("\n")
    );
}

/// R311y545 — the OPTION DEFAULTS gate: one C probe, compiled once, LINKED
/// TWICE, stdout diffed.
///
/// ## Why the layout gate above cannot see this
///
/// `z_publisher_options_t` is transparent, so the sibling leg measures its
/// SIZE against the installed header and a wrong size fails loudly. Nothing
/// measured the VALUES `*_options_default` writes into it, and those values are
/// C enum discriminants — a wrong one is a correctly-sized struct carrying a
/// different meaning.
///
/// That is not hypothetical: this crate had `Z_CONGESTION_CONTROL_DROP = 0`
/// and `Z_RELIABILITY_RELIABLE = 0`, both transcribed from the zenoh-PICO
/// sibling, whose enums are INVERTED against zenoh-c's
/// (`Z_CONGESTION_CONTROL_BLOCK = 0` / `DROP = 1`;
/// `Z_RELIABILITY_BEST_EFFORT = 0` / `RELIABLE = 1`). So
/// `z_publisher_options_default` wrote BLOCK where upstream writes DROP, and a
/// C program comparing the field against the header's own constant got the
/// wrong answer. It was invisible for as long as the fields were accepted and
/// ignored — nothing read the value — and it becomes a WIRE divergence the
/// moment they are honoured, which is what R311y545 does.
///
/// ## Why a wz-authored probe here, when the corpus rule says upstream's
///
/// The rule exists because a wz-authored program is written against the
/// exports wz happens to have. That bias cannot operate on a differential: the
/// SAME source is compiled once and linked against both libraries, so anything
/// wz-flavoured about the probe shows up identically on both arms and cancels.
/// What survives the subtraction is exactly a disagreement between the two
/// implementations. No upstream example prints these defaults, so the
/// alternative is not a better witness — it is no witness.
///
/// Every field of both structs is printed, including the pointer fields as
/// null-or-not, so a future edit that "defaults" one of them to a dangling
/// value reds here rather than in a caller's frame.
///
/// ## No cross-impl proof annotation, and the ABSENCE is the correct form
///
/// Layer A4-3 refuses one here — "a file whose classifier finds no foreign
/// implementation may not annotate at all, not even to decline", the rule this
/// file's own header records. A first draft declined explicitly, mirroring the
/// z_bytes differential in the sibling pico file, and the lane red. The sibling
/// may decline because the classifier finds real pico there; this file has only
/// wz's cdylib and the reference `libzenohc.so`, and zenoh-c is not in A4's
/// class vocabulary. The reasoning lives in prose instead, which is the same
/// place the rest of this file keeps it.
#[test]
#[ignore = "compiles a C probe against the machine-local zenoh-c headers and links \
            it against BOTH wz's cdylib and the real libzenohc.so; run-ci Layer \
            C1cc drives it"]
fn upstream_option_defaults_on_wz_capi_c_match_real_libzenohc() {
    let Some((include, libdir_ref, _examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    // The `#if defined(Z_FEATURE_UNSTABLE_API)` arms are the header's own, so
    // one source serves both oracle flavours and the probe cannot name a field
    // this installation does not have.
    std::fs::write(
        src_dir.join("wz_option_defaults.c"),
        r#"#include <stdio.h>
#include "zenoh.h"

int main(void) {
    z_publisher_options_t po;
    z_publisher_options_default(&po);
    printf("publisher.encoding_is_null=%d\n", po.encoding == NULL);
    printf("publisher.congestion_control=%d\n", (int)po.congestion_control);
    printf("publisher.priority=%d\n", (int)po.priority);
    printf("publisher.is_express=%d\n", (int)po.is_express);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("publisher.reliability=%d\n", (int)po.reliability);
#endif
    printf("publisher.allowed_destination=%d\n", (int)po.allowed_destination);

    z_publisher_put_options_t ppo;
    z_publisher_put_options_default(&ppo);
    printf("publisher_put.encoding_is_null=%d\n", ppo.encoding == NULL);
    printf("publisher_put.timestamp_is_null=%d\n", ppo.timestamp == NULL);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("publisher_put.source_info_is_null=%d\n", ppo.source_info == NULL);
#endif
    printf("publisher_put.attachment_is_null=%d\n", ppo.attachment == NULL);

    z_put_options_t puo;
    z_put_options_default(&puo);
    printf("put.encoding_is_null=%d\n", puo.encoding == NULL);
    printf("put.congestion_control=%d\n", (int)puo.congestion_control);
    printf("put.priority=%d\n", (int)puo.priority);
    printf("put.is_express=%d\n", (int)puo.is_express);
    printf("put.timestamp_is_null=%d\n", puo.timestamp == NULL);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("put.reliability=%d\n", (int)puo.reliability);
#endif
    printf("put.allowed_destination=%d\n", (int)puo.allowed_destination);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("put.source_info_is_null=%d\n", puo.source_info == NULL);
#endif
    printf("put.attachment_is_null=%d\n", puo.attachment == NULL);

    z_delete_options_t duo;
    z_delete_options_default(&duo);
    printf("delete.congestion_control=%d\n", (int)duo.congestion_control);
    printf("delete.priority=%d\n", (int)duo.priority);
    printf("delete.is_express=%d\n", (int)duo.is_express);
    printf("delete.timestamp_is_null=%d\n", duo.timestamp == NULL);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("delete.reliability=%d\n", (int)duo.reliability);
#endif
    printf("delete.allowed_destination=%d\n", (int)duo.allowed_destination);

    z_get_options_t go;
    z_get_options_default(&go);
    printf("get.target=%d\n", (int)go.target);
    printf("get.consolidation.mode=%d\n", (int)go.consolidation.mode);
    printf("get.payload_is_null=%d\n", go.payload == NULL);
    printf("get.encoding_is_null=%d\n", go.encoding == NULL);
    printf("get.congestion_control=%d\n", (int)go.congestion_control);
    printf("get.is_express=%d\n", (int)go.is_express);
    printf("get.allowed_destination=%d\n", (int)go.allowed_destination);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("get.accept_replies=%d\n", (int)go.accept_replies);
#endif
    printf("get.priority=%d\n", (int)go.priority);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("get.source_info_is_null=%d\n", go.source_info == NULL);
#endif
    printf("get.attachment_is_null=%d\n", go.attachment == NULL);
    printf("get.timeout_ms=%llu\n", (unsigned long long)go.timeout_ms);

    z_queryable_options_t qo;
    z_queryable_options_default(&qo);
    printf("queryable.complete=%d\n", (int)qo.complete);
    printf("queryable.allowed_origin=%d\n", (int)qo.allowed_origin);

    z_query_reply_options_t qro;
    z_query_reply_options_default(&qro);
    printf("query_reply.encoding_is_null=%d\n", qro.encoding == NULL);
    printf("query_reply.congestion_control=%d\n", (int)qro.congestion_control);
    printf("query_reply.priority=%d\n", (int)qro.priority);
    printf("query_reply.is_express=%d\n", (int)qro.is_express);
    printf("query_reply.timestamp_is_null=%d\n", qro.timestamp == NULL);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("query_reply.source_info_is_null=%d\n", qro.source_info == NULL);
#endif
    printf("query_reply.attachment_is_null=%d\n", qro.attachment == NULL);

    z_querier_options_t qrqo;
    z_querier_options_default(&qrqo);
    printf("querier.target=%d\n", (int)qrqo.target);
    printf("querier.consolidation.mode=%d\n", (int)qrqo.consolidation.mode);
    printf("querier.congestion_control=%d\n", (int)qrqo.congestion_control);
    printf("querier.is_express=%d\n", (int)qrqo.is_express);
    printf("querier.allowed_destination=%d\n", (int)qrqo.allowed_destination);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("querier.accept_replies=%d\n", (int)qrqo.accept_replies);
#endif
    printf("querier.priority=%d\n", (int)qrqo.priority);
    printf("querier.timeout_ms=%llu\n", (unsigned long long)qrqo.timeout_ms);

    z_querier_get_options_t qgo;
    z_querier_get_options_default(&qgo);
    printf("querier_get.payload_is_null=%d\n", qgo.payload == NULL);
    printf("querier_get.encoding_is_null=%d\n", qgo.encoding == NULL);
#if defined(Z_FEATURE_UNSTABLE_API)
    printf("querier_get.source_info_is_null=%d\n", qgo.source_info == NULL);
#endif
    printf("querier_get.attachment_is_null=%d\n", qgo.attachment == NULL);

    z_liveliness_get_options_t lgo;
    z_liveliness_get_options_default(&lgo);
    printf("liveliness_get.timeout_ms=%llu\n", (unsigned long long)lgo.timeout_ms);

    z_liveliness_subscriber_options_t lso;
    z_liveliness_subscriber_options_default(&lso);
    printf("liveliness_subscriber.history=%d\n", (int)lso.history);

    z_subscriber_options_t so;
    z_subscriber_options_default(&so);
    printf("subscriber.allowed_origin=%d\n", (int)so.allowed_origin);

    z_scout_options_t sco;
    z_scout_options_default(&sco);
    printf("scout.timeout_ms=%llu\n", (unsigned long long)sco.timeout_ms);
    printf("scout.what=%d\n", (int)sco.what);

#if defined(Z_FEATURE_UNSTABLE_API)
    ze_advanced_publisher_cache_options_t apc;
    ze_advanced_publisher_cache_options_default(&apc);
    printf("adv_pub_cache.is_enabled=%d\n", (int)apc.is_enabled);
    printf("adv_pub_cache.max_samples=%zu\n", apc.max_samples);
    printf("adv_pub_cache.congestion_control=%d\n", (int)apc.congestion_control);
    printf("adv_pub_cache.priority=%d\n", (int)apc.priority);
    printf("adv_pub_cache.is_express=%d\n", (int)apc.is_express);

    ze_advanced_publisher_sample_miss_detection_options_t apm;
    ze_advanced_publisher_sample_miss_detection_options_default(&apm);
    printf("adv_pub_miss.is_enabled=%d\n", (int)apm.is_enabled);
    printf("adv_pub_miss.heartbeat_mode=%d\n", (int)apm.heartbeat_mode);
    printf("adv_pub_miss.heartbeat_period_ms=%llu\n",
           (unsigned long long)apm.heartbeat_period_ms);

    ze_advanced_publisher_options_t apo;
    ze_advanced_publisher_options_default(&apo);
    printf("adv_pub.publisher_options.congestion_control=%d\n",
           (int)apo.publisher_options.congestion_control);
    printf("adv_pub.publisher_options.priority=%d\n", (int)apo.publisher_options.priority);
    printf("adv_pub.publisher_options.is_express=%d\n", (int)apo.publisher_options.is_express);
    printf("adv_pub.publisher_options.reliability=%d\n", (int)apo.publisher_options.reliability);
    printf("adv_pub.publisher_options.allowed_destination=%d\n",
           (int)apo.publisher_options.allowed_destination);
    printf("adv_pub.cache.is_enabled=%d\n", (int)apo.cache.is_enabled);
    printf("adv_pub.sample_miss_detection.is_enabled=%d\n",
           (int)apo.sample_miss_detection.is_enabled);
    printf("adv_pub.publisher_detection=%d\n", (int)apo.publisher_detection);
    printf("adv_pub.publisher_detection_metadata_is_null=%d\n",
           apo.publisher_detection_metadata == NULL);

    ze_advanced_publisher_put_options_t appo;
    ze_advanced_publisher_put_options_default(&appo);
    printf("adv_pub_put.put_options.encoding_is_null=%d\n",
           appo.put_options.encoding == NULL);
    printf("adv_pub_put.put_options.attachment_is_null=%d\n",
           appo.put_options.attachment == NULL);

    ze_advanced_subscriber_history_options_t ash;
    ze_advanced_subscriber_history_options_default(&ash);
    printf("adv_sub_history.is_enabled=%d\n", (int)ash.is_enabled);
    printf("adv_sub_history.detect_late_publishers=%d\n", (int)ash.detect_late_publishers);
    printf("adv_sub_history.max_samples=%zu\n", ash.max_samples);
    printf("adv_sub_history.max_age_ms=%llu\n", (unsigned long long)ash.max_age_ms);

    ze_advanced_subscriber_last_sample_miss_detection_options_t asl;
    ze_advanced_subscriber_last_sample_miss_detection_options_default(&asl);
    printf("adv_sub_last_miss.is_enabled=%d\n", (int)asl.is_enabled);
    printf("adv_sub_last_miss.periodic_queries_period_ms=%llu\n",
           (unsigned long long)asl.periodic_queries_period_ms);

    ze_advanced_subscriber_recovery_options_t asr;
    ze_advanced_subscriber_recovery_options_default(&asr);
    printf("adv_sub_recovery.is_enabled=%d\n", (int)asr.is_enabled);
    printf("adv_sub_recovery.last_sample_miss_detection.is_enabled=%d\n",
           (int)asr.last_sample_miss_detection.is_enabled);

    ze_advanced_subscriber_options_t aso;
    ze_advanced_subscriber_options_default(&aso);
    printf("adv_sub.subscriber_options.allowed_origin=%d\n",
           (int)aso.subscriber_options.allowed_origin);
    printf("adv_sub.history.is_enabled=%d\n", (int)aso.history.is_enabled);
    printf("adv_sub.recovery.is_enabled=%d\n", (int)aso.recovery.is_enabled);
    printf("adv_sub.query_timeout_ms=%llu\n", (unsigned long long)aso.query_timeout_ms);
    printf("adv_sub.subscriber_detection=%d\n", (int)aso.subscriber_detection);
    printf("adv_sub.subscriber_detection_metadata_is_null=%d\n",
           aso.subscriber_detection_metadata == NULL);
#endif
    return 0;
}
"#,
    )
    .expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_option_defaults",
        dir.path(),
        &include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: the option-defaults probe does NOT link against wz's \
             C-ABI cdylib.\n{diag}"
        )
    });
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_option_defaults",
        &ref_dir,
        &include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the option-defaults probe does not link against the REAL libzenohc.so\n{diag}")
    });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        let out = Command::new(exe)
            .env("LD_LIBRARY_PATH", libdir)
            .output()
            .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (wz_ok, wz_stdout) = run(&on_wz, &wz_libdir);
    let (ref_ok, ref_stdout) = run(&on_ref, &libdir_ref);

    assert!(
        ref_ok,
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one \
         here — the comparison below would be meaningless.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "the option-defaults probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}"
    );
    // Asserted BEFORE the diff: two empty captures are equal, and an equality
    // between them would report the strongest result this file can produce
    // while measuring nothing.
    // The UNSTABLE half of the probe sits behind the header's own
    // `#if defined(Z_FEATURE_UNSTABLE_API)`, so on a no-unstable oracle it
    // compiles to nothing and the diff below never sees it. That is correct,
    // and it is also exactly how a whole half of this leg could go silently
    // unmeasured — so which half to expect is read from the oracle's
    // `zenoh_configure.h` rather than inferred from what happened to print.
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h"))
        .expect("the oracle ships zenoh_configure.h");
    let unstable = configure.contains("#define Z_FEATURE_UNSTABLE_API");
    let mut expected: Vec<&str> = vec![
        "publisher.congestion_control=",
        "put.congestion_control=",
        "delete.congestion_control=",
        "get.congestion_control=",
        "querier.congestion_control=",
        "query_reply.congestion_control=",
        "querier_get.encoding_is_null=",
        "queryable.allowed_origin=",
        "subscriber.allowed_origin=",
        "liveliness_get.timeout_ms=",
        "liveliness_subscriber.history=",
        "scout.timeout_ms=",
    ];
    if unstable {
        expected.extend([
            // The two fields that exist ONLY here, and both of which were wrong
            // before R311y545 measured them.
            "publisher.reliability=",
            "get.accept_replies=",
            // One line per ze_advanced_* family, so a family dropped from the
            // probe is a failed assertion rather than a shorter diff.
            "adv_pub_cache.is_enabled=",
            "adv_pub_miss.is_enabled=",
            "adv_pub.publisher_detection=",
            "adv_pub_put.put_options.encoding_is_null=",
            "adv_sub_history.is_enabled=",
            "adv_sub_last_miss.is_enabled=",
            "adv_sub_recovery.is_enabled=",
            "adv_sub.query_timeout_ms=",
        ]);
    }
    for required in expected {
        assert!(
            ref_stdout.contains(required),
            "the reference arm printed no `{required}` line, so the diff below \
             would compare two outputs neither of which contains a field this leg \
             exists for. One assertion per STRUCT, because the \
             `*_options_default` families are independent exports and a probe that \
             silently stopped printing one would still diff EQUAL. This oracle \
             {} Z_FEATURE_UNSTABLE_API.\n\
             --- stdout on real libzenohc ---\n{ref_stdout}",
            if unstable {
                "DEFINES"
            } else {
                "does not define"
            }
        );
    }
    assert_eq!(
        wz_stdout, ref_stdout,
        "wz's `*_options_default` writes DIFFERENT values than the real \
         libzenohc.so on the SAME header. These are C enum discriminants: a \
         correctly-sized struct carrying a different meaning, which the layout \
         gate cannot see. Check the constants in wz-capi-c/src/publisher.rs \
         against zenoh_commons.h — zenoh-c and zenoh-pico INVERT both the \
         congestion-control and the reliability enum.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- stdout on real libzenohc ---\n{ref_stdout}"
    );
}
