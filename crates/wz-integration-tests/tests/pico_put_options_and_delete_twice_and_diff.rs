// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — R311y559: the PUT OPTIONS and the DELETE, driven
//! by one C program compiled TWICE and adjudicated by a real zenoh-pico
//! subscriber.
//!
//! ## What this exists to catch, and why nothing else could
//!
//! Until R311y559 the pico ABI's `z_put` took `*const c_void` and IGNORED it:
//! a program that set an encoding, a priority, an attachment or a timestamp on
//! its session put had every one of them silently dropped, while the sibling
//! `z_publisher_put` had honoured the same fields for rounds. And `z_delete`
//! did not exist at all — a Del is not a Put with an empty payload (different
//! inner body, and a subscriber reads `z_sample_kind` to tell them apart), so
//! there was no way to retract a key through this ABI.
//!
//! Neither gap was reachable by the existing legs, for a reason worth stating:
//! **no upstream pico example passes put options.** `z_put.c` writes
//! `z_put(.., NULL)`. So the drop-in corpus — which is upstream's programs, on
//! purpose — could compile, link and run the whole suite green while the
//! options plane did nothing. That is the same shape R311y545 found on the
//! zenoh-c side, and the same remedy applies: a census measures the programs
//! that EXIST, so a field no existing program sets needs a program written for
//! it.
//!
//! ## The authorship bias, and what neutralises it
//!
//! This file's driver is wz-authored, which is exactly the bias
//! `api-compat-pico`'s corpus rule exists to avoid — a program written against
//! the exports wz happens to have. Two things neutralise it here and neither is
//! optional:
//!
//! - The SAME SOURCE is compiled twice and linked against wz's cdylib and
//!   against the real `libzenohpico.so`. If wz reads a field differently, or
//!   not at all, the two arms diverge.
//! - The ADJUDICATOR is upstream's own `z_sub_attachment` binary, built from
//!   upstream's source against the real library. It prints the encoding, the
//!   timestamp and the attachment it decodes off the wire — so what is compared
//!   is what a foreign peer SEES, not what either arm claims to have sent.
//!
//! The linker check the census already owns is deliberately not repeated here.
//!
//! ## The oracle is a build product
//!
//! Both the observer CLI and `libzenohpico.so` come from
//! `scripts/build-zenoh-pico-cli.sh`. Absence is a hard FAIL rather than a
//! skip: a differential with nothing to differ against must not report green.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_capi_pico_cdylib, zenoh_pico_cli_binary,
    zenoh_pico_include_dirs, zenoh_pico_library_dir, ChildGuard, PortReservation,
};

/// The driver: upstream's `z_put.c` shape, with the options struct actually
/// FILLED and a `z_delete` after the put.
///
/// Deliberately close to upstream's program rather than minimal — it declares
/// the keyexpr, puts through it, and cleans up the same way — so that what
/// differs between this and `z_put.c` is only the thing under test.
///
/// The attachment is a serialized key/value SEQUENCE, which is what upstream's
/// own `z_pub_attachment.c` writes and what its `z_sub_attachment.c`
/// deserializer reads; a raw blob would fail to decode in BOTH arms and the
/// comparison would be vacuous.
const DRIVER_SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>

int main(int argc, char **argv) {
    (void)argc;
    const char *keyexpr = argv[1];
    const char *endpoint = argv[2];

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, endpoint);

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("driver: unable to open session\n");
        return -1;
    }

    z_view_keyexpr_t vke;
    if (z_view_keyexpr_from_str(&vke, keyexpr) < 0) {
        printf("driver: bad keyexpr\n");
        return -1;
    }

    z_sleep_ms(500);

    /* THE PUT, with every option field this ABI carries actually set. */
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "the-value");

    /* The attachment is a SEQUENCE of key/value strings, which is the shape
       upstream's own z_pub_attachment.c writes and the shape its
       z_sub_attachment.c deserializer reads. A bare string would fail to
       decode in BOTH arms and the comparison would be vacuous. */
    z_owned_bytes_t attachment;
    ze_owned_serializer_t serializer;
    ze_serializer_empty(&serializer);
    ze_serializer_serialize_sequence_length(z_loan_mut(serializer), 1);
    ze_serializer_serialize_str(z_loan_mut(serializer), "attach-key");
    ze_serializer_serialize_str(z_loan_mut(serializer), "attach-value");
    ze_serializer_finish(z_move(serializer), &attachment);

    z_owned_encoding_t encoding;
    z_encoding_clone(&encoding, z_encoding_text_plain());

    z_put_options_t opts;
    z_put_options_default(&opts);
    opts.encoding = z_move(encoding);
    opts.attachment = z_move(attachment);
    opts.priority = Z_PRIORITY_INTERACTIVE_HIGH;
    opts.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    opts.is_express = true;

    if (z_put(z_loan(s), z_loan(vke), z_move(payload), &opts) < 0) {
        printf("driver: put failed\n");
    }

    z_sleep_ms(500);

    /* THE DELETE. */
    z_delete_options_t dopts;
    z_delete_options_default(&dopts);
    if (z_delete(z_loan(s), z_loan(vke), &dopts) < 0) {
        printf("driver: delete failed\n");
    }

    z_sleep_ms(500);
    z_drop(z_move(s));
    return 0;
}
"#;

/// Compile `DRIVER_SRC` against upstream's headers, linked to `lib`.
///
/// The header set is upstream's in BOTH arms — only the library differs, which
/// is the whole point of a compile-twice differential.
fn compile_driver(out_dir: &Path, libdir: &Path, libname: &str, arm: &str) -> PathBuf {
    let src = out_dir.join(format!("driver_{arm}.c"));
    std::fs::write(&src, DRIVER_SRC).expect("write driver source");
    let exe = out_dir.join(format!("driver_{arm}"));

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let mut cmd = Command::new(&cc);
    cmd.arg(&src).arg("-DZENOH_LINUX");
    for inc in zenoh_pico_include_dirs() {
        cmd.arg(format!("-I{}", inc.display()));
    }
    cmd.arg("-o")
        .arg(&exe)
        .arg(format!("-L{}", libdir.display()))
        .arg(format!("-l{libname}"))
        .arg(format!("-Wl,-rpath,{}", libdir.display()));

    let out = cmd.output().expect("spawn C compiler");
    assert!(
        out.status.success(),
        "{arm} arm failed to build against {libname}:\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    exe
}

/// Run one arm: a fresh REAL pico `z_sub_attachment` listening, the driver
/// dialing it, and the OBSERVER's stdout returned.
///
/// A fresh observer per arm is not hygiene: the observer is a one-session
/// program, so a shared one would make the second arm's result depend on the
/// first — the failure R311y498 diagnosed on the zenoh-c side.
fn run_arm(driver: &Path, keyexpr: &str, arm: &str) -> String {
    let port = PortReservation::pick();
    let listen = format!("tcp/127.0.0.1:{}", port.port());

    let mut stdout = tempfile::tempfile().expect("tempfile for observer stdout");
    let observer_out = stdout.try_clone().expect("clone observer stdout handle");
    // `stdbuf -oL`, and it is load-bearing: the observer's stdout is a FILE
    // here, so libc picks FULL buffering and nothing reaches the log until the
    // process exits — which it does not, because it is a subscriber. The
    // REFERENCE arm reads as broken in exactly the same way without it, which
    // is what makes this a harness trap rather than a wz finding.
    let observer = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(zenoh_pico_cli_binary("z_sub_attachment"))
        .args(["-k", keyexpr, "-l", &listen, "-m", "peer"])
        .stdout(Stdio::from(observer_out))
        .stderr(Stdio::from(stdout.try_clone().expect("dup stderr handle")))
        .spawn()
        .expect("spawn the real zenoh-pico z_sub_attachment observer");
    let _observer = ChildGuard::wrap(format!("z_sub_attachment[{arm}]"), observer);

    wait_for_substring(&mut stdout, "Press CTRL-C to quit", Duration::from_secs(10))
        .unwrap_or_else(|e| panic!("{arm}: observer never became ready: {e}"));
    // The observer has bound; the reservation may go.
    drop(port);
    // R311y606 — captured, not discarded: this exit status is ASSERTED,
    // and an asserted failure with no output is unanswerable.
    let mut capture = tempfile::tempfile().expect("the driver capture");
    let status = Command::new(driver)
        .args([keyexpr, &listen])
        .stdout(Stdio::from(capture.try_clone().expect("dup stdout handle")))
        .stderr(Stdio::from(capture.try_clone().expect("dup stderr handle")))
        .status()
        .unwrap_or_else(|e| panic!("{arm}: failed to run the driver: {e}"));
    assert!(
        status.success(),
        "{arm}: the driver exited {status:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut capture)
    );

    // Both the PUT and the DELETE must have landed before the observer's log is
    // read; the driver's own sleeps cover the send side, this covers the
    // receive side.
    let _ = wait_for_substring(&mut stdout, "with encoding", Duration::from_secs(10));
    std::thread::sleep(Duration::from_millis(800));
    read_all(&stdout)
}

/// Read a tempfile from the start.
fn read_all(file: &std::fs::File) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = file.try_clone().expect("clone file handle");
    f.seek(SeekFrom::Start(0)).expect("rewind");
    let mut raw = Vec::new();
    f.read_to_end(&mut raw).expect("read observer log");
    // LOSSY, deliberately: an attachment that fails to decode leaves raw bytes
    // in the observer's output, and the harness must survive that to REPORT it
    // rather than dying on it. Both arms are read the same way, so a decode
    // failure still shows up as a difference when only one arm has it.
    String::from_utf8_lossy(&raw).into_owned()
}

/// Drop the lines whose content cannot agree between two runs.
///
/// Only the TIMESTAMP value is normalised, and only its value: the LINE stays,
/// so "one arm stamped and the other did not" is still a difference. Nothing
/// else is touched — normalising more would be normalising away the finding.
fn normalise(log: &str) -> Vec<String> {
    log.lines()
        .filter(|l| l.starts_with(">> ") || l.starts_with("    "))
        .map(|l| {
            if let Some(idx) = l.find("with timestamp: ") {
                format!("{}with timestamp: <ntp64>", &l[..idx])
            } else {
                l.to_string()
            }
        })
        .collect()
}

/// R311y559 — wz's `z_put` options and its `z_delete` produce the SAME thing on
/// the wire as the real zenoh-pico's, judged by a real zenoh-pico subscriber.
///
/// The observer prints more than the encoding, and that widens what this leg
/// adjudicates for free: the installed `z_sub_attachment` also emits
/// `with kind:` (0 = Put, 1 = Delete) and the QoS trio `with priority:` /
/// `with congestion:` / `with express:`. So the DELETE is judged by its wire
/// KIND rather than by an empty payload, and the three QoS fields
/// `z_put_options_t` carries are compared against the real library's rendering
/// of the same bits.
///
/// Damage probes, both RUN rather than argued:
/// - Making `session_put_options` drop the `encoding` reds exactly the
///   `with encoding:` line — `text/plain` becomes `zenoh/bytes` on the wz arm
///   while every other line still matches.
/// - Making `z_delete` return early without publishing reds the wz arm at the
///   missing second sample: the reference arm shows
///   `Received ('demo/y559/opts': '')` + `with kind: 1` and wz shows neither.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_sub_attachment CLI and cc-compiles a \
            driver against both libraries; run by run-ci Layer E"]
fn put_options_and_delete_match_the_real_pico_on_the_wire() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib
        .parent()
        .expect("cdylib has a parent directory")
        .to_path_buf();

    let wz_driver = compile_driver(dir.path(), &wz_libdir, "wz_capi_pico", "wz");
    let ref_driver = compile_driver(
        dir.path(),
        &zenoh_pico_library_dir(),
        "zenohpico",
        "reference",
    );

    let reference = run_arm(&ref_driver, "demo/y559/opts", "reference");
    let wz = run_arm(&wz_driver, "demo/y559/opts", "wz");

    let reference_lines = normalise(&reference);
    let wz_lines = normalise(&wz);

    // ASSERT THE REFERENCE ARM'S CONTENT FIRST. Two empty logs are equal, and
    // an equality between them proves nothing — the R311y546 rule.
    assert!(
        reference_lines
            .iter()
            .any(|l| l.contains("with encoding: text/plain")),
        "the REFERENCE arm did not carry the encoding, so this leg is \
         measuring the harness rather than wz:\n{reference}"
    );
    assert!(
        reference_lines
            .iter()
            .any(|l| l.contains("attach-key, attach-value")),
        "the REFERENCE arm did not carry the attachment:\n{reference}"
    );
    assert_eq!(
        reference_lines
            .iter()
            .filter(|l| l.starts_with(">> [Subscriber] Received"))
            .count(),
        2,
        "the REFERENCE arm should show the PUT and the DELETE as two samples; \
         without both, the delete half of this leg is vacuous:\n{reference}"
    );

    assert_eq!(
        wz_lines, reference_lines,
        "wz's put options / delete differ from the real zenoh-pico's as seen by \
         a real zenoh-pico subscriber.\n--- wz ---\n{wz}\n--- reference ---\n{reference}"
    );
}
