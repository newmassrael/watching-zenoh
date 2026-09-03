// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — the option-struct LAYOUT gate: every
//! feature-conditional option struct wz declares must have the size and field
//! offsets the REFERENCE pico build's own headers give it.
//!
//! ## Why this gate exists, in one defect
//!
//! R311y562 found `z_get_options_t` modelling the `Z_FEATURE_UNSTABLE_API`-OFF
//! layout while `scripts/build-zenoh-pico-cli.sh` configures the reference pico
//! with `-DZ_FEATURE_UNSTABLE_API=ON`. The two omitted fields sit BEFORE
//! `accept_replies`, so the omission did not hide a tail — it MOVED a field
//! from offset 72 to 56, which in a caller's memory is the `source_info`
//! POINTER. Every drop-in program that called `z_get_options_default` read its
//! reply-keyexpr policy out of the low half of a null pointer.
//!
//! R311y562 fixed it and pinned the result with `const _` assertions carrying
//! hand-measured numbers. That is strictly better than the size-only pins it
//! replaced and still the wrong KIND of gate: the numbers were transcribed by a
//! human reading compiler output, which is exactly how 40 / 32 / 64 got in
//! there. A transcription cannot detect that upstream moved a field; it can
//! only agree with whoever typed it last.
//!
//! ## What makes this one mechanical
//!
//! The reference numbers are produced by COMPILING a probe against the headers
//! the drop-in's own programs compile against — `target/zenoh-pico-build`'s
//! generated `config.h` FIRST on the include path, so `zenoh-pico/config.h`
//! resolves to the reference build's rather than to any other tree's. Nothing
//! here restates a flag: if that build's configuration changes, the probe's
//! output changes with it, and the assertion below fails.
//!
//! This is the same discipline `pico_abi_symbol_census.rs` applies to the
//! symbol table — compare against the artifact, never against a remembered
//! number — extended to struct layout.
//!
//! ## Missing prerequisites are a FAILURE, not a skip
//!
//! A gate that cannot read its input must not report green. Absent reference
//! build, absent mbedtls headers, or absent C compiler all panic with the
//! provisioning hint, matching `zenoh_pico_shared_library`'s contract.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{mbedtls_prefix, project_root, zenoh_pico_build_root};

/// One struct's measured layout: `(size, [(field, offset)])`.
struct Layout {
    size: usize,
    offsets: Vec<(String, usize)>,
}

/// The structs and fields this gate pins.
///
/// Deliberately the FEATURE-CONDITIONAL ones plus the field that follows the
/// conditional region, because that pairing is what the y562 defect was made
/// of: a struct can be the wrong size for a harmless reason (a missing tail
/// nobody reads) or a harmful one (a field displaced under a caller's writes),
/// and only an offset tells those apart.
const PINNED: &[(&str, &[&str])] = &[
    (
        "z_get_options_t",
        &[
            "attachment",
            "source_info",
            "cancellation_token",
            "accept_replies",
        ],
    ),
    (
        "z_querier_get_options_t",
        &["attachment", "cancellation_token", "source_info"],
    ),
    // R311y575 — added because its ABSENCE from this table is what let the
    // defect through. wz declared this struct at 8 B (`timeout_ms` alone) on the
    // reasoning that `Z_FEATURE_UNSTABLE_API` "defaults OFF", the same R311y466
    // trap `z_get_options_t` above was fixed for at y562. Measured against the
    // reference build's headers it is 16 B with `cancellation_token` at 8, so
    // `z_liveliness_get_options_default` wrote 8 of the 16 bytes a drop-in
    // program allocates. A mechanical gate that only covers the structs already
    // known to be wrong is a regression test, not a gate.
    ("z_liveliness_get_options_t", &["cancellation_token"]),
    (
        "z_query_reply_options_t",
        &["timestamp", "attachment", "source_info"],
    ),
    (
        "z_query_reply_del_options_t",
        &["timestamp", "attachment", "source_info"],
    ),
    (
        "z_put_options_t",
        &["timestamp", "attachment", "source_info"],
    ),
    ("z_publisher_put_options_t", &["timestamp", "source_info"]),
    // R311y565 — the SIZE-ONLY half. Everything above is field-mirrored, so its
    // offsets are the interesting part; the families below are opaque blobs the
    // C side stack-allocates and never reads inside, where the SIZE is the whole
    // contract. They were pinned in `wz-capi-pico/src/lib.rs` as wz constants
    // checked against wz constants — self-consistent by construction and unable
    // to notice the reference header moving, which is the exact gap that let
    // `z_get_options_t` sit at the wrong layout for rounds.
    ("z_owned_session_t", &[]),
    ("z_loaned_session_t", &[]),
    ("z_owned_config_t", &[]),
    ("z_owned_bytes_t", &[]),
    ("z_owned_slice_t", &[]),
    ("z_owned_string_t", &[]),
    ("z_view_keyexpr_t", &[]),
    ("z_view_string_t", &[]),
    ("z_owned_closure_sample_t", &[]),
    ("z_owned_closure_query_t", &[]),
    ("z_owned_closure_reply_t", &[]),
    ("z_queryable_options_t", &[]),
    ("z_query_reply_err_options_t", &[]),
    ("z_query_consolidation_t", &[]),
];

/// The reference build's generated config directory — the one whose `config.h`
/// records what `scripts/build-zenoh-pico-cli.sh` actually configured.
fn reference_config_include() -> PathBuf {
    // R2326 — through the resolver, not `project_root().join(..)`: the resolver
    // is where the root's provenance is graded, and a direct join is a route
    // that silently skips that grading.
    let dir = zenoh_pico_build_root().join("zenohpico/include");
    assert!(
        dir.join("zenoh-pico/config.h").is_file(),
        "reference pico config.h missing under {}; run \
         scripts/build-zenoh-pico-cli.sh first",
        dir.display()
    );
    dir
}

/// mbedtls headers, which the vendored pico headers include unconditionally on
/// the TLS link path.
fn mbedtls_include() -> PathBuf {
    // R2326 — through the resolver, for the same reason
    // `reference_config_include` above is.
    let dir = mbedtls_prefix().join("include");
    assert!(
        dir.join("mbedtls/entropy.h").is_file(),
        "mbedtls headers missing under {}; run \
         scripts/build-zenoh-pico-cli.sh first",
        dir.display()
    );
    dir
}

/// Compile and run a probe that prints `<struct> <size> <field>=<offset> ...`
/// for every pinned struct, against the reference headers.
fn measure_reference(work: &Path) -> Vec<(String, Layout)> {
    let mut src = String::from(
        "#include <stdio.h>\n#include <stddef.h>\n#include \"zenoh-pico.h\"\nint main(void){\n",
    );
    for (ty, fields) in PINNED {
        src.push_str(&format!("  printf(\"{ty} %zu\", sizeof({ty}));\n"));
        for f in *fields {
            src.push_str(&format!("  printf(\" {f}=%zu\", offsetof({ty}, {f}));\n"));
        }
        src.push_str("  printf(\"\\n\");\n");
    }
    src.push_str("  return 0;\n}\n");

    let c_path = work.join("pico_option_layout_probe.c");
    let bin_path = work.join("pico_option_layout_probe");
    std::fs::write(&c_path, src).expect("write the layout probe");

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let out = Command::new(&cc)
        .arg("-DZENOH_LINUX")
        .arg("-I")
        .arg(reference_config_include())
        .arg("-I")
        .arg(project_root().join("vendor/zenoh-pico/include"))
        .arg("-I")
        .arg(mbedtls_include())
        .arg("-o")
        .arg(&bin_path)
        .arg(&c_path)
        .output()
        .unwrap_or_else(|e| panic!("running {cc}: {e}"));
    assert!(
        out.status.success(),
        "the layout probe failed to compile against the reference headers:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let run = Command::new(&bin_path)
        .output()
        .expect("running the layout probe");
    assert!(run.status.success(), "the layout probe exited non-zero");
    let text = String::from_utf8(run.stdout).expect("probe output is UTF-8");

    let mut measured = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.split_whitespace();
        let ty = parts.next().expect("struct name").to_string();
        let size: usize = parts
            .next()
            .expect("size")
            .parse()
            .expect("size is a number");
        let offsets = parts
            .map(|kv| {
                let (k, v) = kv.split_once('=').expect("field=offset");
                (k.to_string(), v.parse::<usize>().expect("offset"))
            })
            .collect();
        measured.push((ty, Layout { size, offsets }));
    }
    assert_eq!(
        measured.len(),
        PINNED.len(),
        "the probe printed one line per pinned struct"
    );
    measured
}

/// wz's own layout for the same structs, read out of the Rust types.
///
/// `offset_of!` rather than a hand-written table: the point of this gate is
/// that NO number in it is typed by a human on either side.
fn wz_layout(ty: &str) -> Layout {
    use std::mem::{offset_of, size_of};
    use wz_capi_pico::get::z_get_options_t;
    use wz_capi_pico::liveliness::z_liveliness_get_options_t;
    use wz_capi_pico::pubsub::{z_publisher_put_options_t, z_put_options_t};
    use wz_capi_pico::querier::z_querier_get_options_t;
    use wz_capi_pico::query::{z_query_reply_del_options_t, z_query_reply_options_t};

    match ty {
        "z_get_options_t" => Layout {
            size: size_of::<z_get_options_t>(),
            offsets: vec![
                ("attachment".into(), offset_of!(z_get_options_t, attachment)),
                (
                    "source_info".into(),
                    offset_of!(z_get_options_t, source_info),
                ),
                (
                    "cancellation_token".into(),
                    offset_of!(z_get_options_t, cancellation_token),
                ),
                (
                    "accept_replies".into(),
                    offset_of!(z_get_options_t, accept_replies),
                ),
            ],
        },
        "z_querier_get_options_t" => Layout {
            size: size_of::<z_querier_get_options_t>(),
            offsets: vec![
                (
                    "attachment".into(),
                    offset_of!(z_querier_get_options_t, attachment),
                ),
                (
                    "cancellation_token".into(),
                    offset_of!(z_querier_get_options_t, cancellation_token),
                ),
                (
                    "source_info".into(),
                    offset_of!(z_querier_get_options_t, source_info),
                ),
            ],
        },
        "z_liveliness_get_options_t" => Layout {
            size: size_of::<z_liveliness_get_options_t>(),
            offsets: vec![(
                "cancellation_token".into(),
                offset_of!(z_liveliness_get_options_t, cancellation_token),
            )],
        },
        "z_query_reply_options_t" => Layout {
            size: size_of::<z_query_reply_options_t>(),
            offsets: vec![
                (
                    "timestamp".into(),
                    offset_of!(z_query_reply_options_t, timestamp),
                ),
                (
                    "attachment".into(),
                    offset_of!(z_query_reply_options_t, attachment),
                ),
                (
                    "source_info".into(),
                    offset_of!(z_query_reply_options_t, source_info),
                ),
            ],
        },
        "z_query_reply_del_options_t" => Layout {
            size: size_of::<z_query_reply_del_options_t>(),
            offsets: vec![
                (
                    "timestamp".into(),
                    offset_of!(z_query_reply_del_options_t, timestamp),
                ),
                (
                    "attachment".into(),
                    offset_of!(z_query_reply_del_options_t, attachment),
                ),
                (
                    "source_info".into(),
                    offset_of!(z_query_reply_del_options_t, source_info),
                ),
            ],
        },
        "z_put_options_t" => Layout {
            size: size_of::<z_put_options_t>(),
            offsets: vec![
                ("timestamp".into(), offset_of!(z_put_options_t, timestamp)),
                ("attachment".into(), offset_of!(z_put_options_t, attachment)),
                (
                    "source_info".into(),
                    offset_of!(z_put_options_t, source_info),
                ),
            ],
        },
        "z_publisher_put_options_t" => Layout {
            size: size_of::<z_publisher_put_options_t>(),
            offsets: vec![
                (
                    "timestamp".into(),
                    offset_of!(z_publisher_put_options_t, timestamp),
                ),
                (
                    "source_info".into(),
                    offset_of!(z_publisher_put_options_t, source_info),
                ),
            ],
        },
        // The size-only half. A macro rather than fourteen hand-written
        // `Layout { size: size_of::<..>(), offsets: vec![] }` literals, so a new
        // entry is one line and cannot get its own `offsets` wrong.
        _ => {
            macro_rules! size_only {
                ($t:ty) => {
                    Layout {
                        size: size_of::<$t>(),
                        offsets: Vec::new(),
                    }
                };
            }
            match ty {
                "z_owned_session_t" => size_only!(wz_capi_pico::session::z_owned_session_t),
                "z_loaned_session_t" => size_only!(wz_capi_pico::session::z_loaned_session_t),
                "z_owned_config_t" => size_only!(wz_capi_pico::abi::z_owned_config_t),
                "z_owned_bytes_t" => size_only!(wz_capi_pico::abi::z_owned_bytes_t),
                "z_owned_slice_t" => size_only!(wz_capi_pico::abi::z_owned_slice_t),
                "z_owned_string_t" => size_only!(wz_capi_pico::abi::z_owned_string_t),
                "z_view_keyexpr_t" => size_only!(wz_capi_pico::abi::z_view_keyexpr_t),
                "z_view_string_t" => size_only!(wz_capi_pico::abi::z_view_string_t),
                "z_owned_closure_sample_t" => {
                    size_only!(wz_capi_pico::pubsub::z_owned_closure_sample_t)
                }
                "z_owned_closure_query_t" => {
                    size_only!(wz_capi_pico::query::z_owned_closure_query_t)
                }
                "z_owned_closure_reply_t" => size_only!(wz_capi_pico::get::z_owned_closure_reply_t),
                "z_queryable_options_t" => size_only!(wz_capi_pico::query::z_queryable_options_t),
                "z_query_reply_err_options_t" => {
                    size_only!(wz_capi_pico::query::z_query_reply_err_options_t)
                }
                "z_query_consolidation_t" => size_only!(wz_capi_pico::get::z_query_consolidation_t),
                other => panic!("no wz layout wired for {other}"),
            }
        }
    }
}

#[test]
#[ignore = "compiles a probe against the CMake-built reference headers; run by run-ci Layer E"]
fn pico_option_structs_match_the_reference_header_layout() {
    let work = std::env::temp_dir().join("wz-pico-option-layout");
    std::fs::create_dir_all(&work).expect("scratch dir");

    let measured = measure_reference(&work);

    // CALIBRATION FIRST: the probe must have observed the UNSTABLE-ON layout,
    // i.e. it really did read the reference build's config rather than some
    // other tree's. Without this arm a probe that silently compiled against an
    // unstable-OFF header would agree with an unstable-OFF wz and the gate
    // would certify the very drift it exists to catch.
    let get = measured
        .iter()
        .find(|(ty, _)| ty == "z_get_options_t")
        .expect("the probe measured z_get_options_t");
    assert!(
        get.1.offsets.iter().any(|(f, _)| f == "source_info"),
        "CALIBRATION FAILED: the reference header has no z_get_options_t::\
         source_info, so it is not the Z_FEATURE_UNSTABLE_API build the \
         drop-in links against"
    );

    let mut mismatches = Vec::new();
    for (ty, reference) in &measured {
        let ours = wz_layout(ty);
        if ours.size != reference.size {
            mismatches.push(format!(
                "{ty}: size wz={} reference={}",
                ours.size, reference.size
            ));
        }
        for (field, want) in &reference.offsets {
            match ours.offsets.iter().find(|(f, _)| f == field) {
                Some((_, got)) if got == want => {}
                Some((_, got)) => {
                    mismatches.push(format!("{ty}::{field}: offset wz={got} reference={want}"))
                }
                None => mismatches.push(format!("{ty}::{field}: absent from the wz struct")),
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "wz's pico option structs disagree with the reference build's headers \
         — a C program compiled against those headers would read the wrong \
         bytes:\n  {}",
        mismatches.join("\n  ")
    );
}
