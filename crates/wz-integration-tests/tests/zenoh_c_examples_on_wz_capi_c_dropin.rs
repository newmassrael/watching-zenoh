// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
    // (name, C expression). ONE list, so the name and the thing measured cannot
    // drift apart — the previous shape kept them in two.
    let probes: &[(&str, &str)] = &[
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
    ];

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
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h"))
        .expect("the oracle ships zenoh_configure.h");
    let advice = if configure.contains("#define Z_FEATURE_UNSTABLE_API") {
        "this oracle DEFINES Z_FEATURE_UNSTABLE_API, so build wz-capi-c with its \
         DEFAULT features"
    } else {
        "this oracle does NOT define Z_FEATURE_UNSTABLE_API, so build wz-capi-c \
         with --features zenoh-c-no-unstable-api"
    };

    for (i, (name, _)) in probes.iter().enumerate() {
        assert_eq!(
            mine[i], upstream[i],
            "{name}: wz says {} and this installation's zenoh-c header says {}. A \
             drop-in whose types are a different SIZE is not a drop-in — the C side \
             stack-allocates these. {advice}.",
            mine[i], upstream[i]
        );
    }
}
