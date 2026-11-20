// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The two forms of the pico library put the same bytes on the wire.
//!
//! The doors of the additional features build into the core library (the default form) or into a
//! library of their own beside the core, from the same sources and one feature list
//! (`docs/capi-pico-additional-library.md`). What the second form adds is a boundary: every call a
//! door makes into the core crosses it through C, every type it allocates is the core's size by
//! declaration, and every handle, string and callback mark goes through the extension interface.
//! A mistake there (a declaration that drifted, a value read past its end, a callback that waits on
//! itself) changes what the sessions do, and what they do is what goes on the wire.
//!
//! So one scenario (`crates/wz-capi-pico/tests/c/additional_split_scenario.c`: the interface
//! version, an end-to-end sender and receiver, a replay cache served to a subscriber that comes
//! later) is compiled against each form and run through a recording relay between its two
//! sessions, and the network messages each side sent are compared. The zenoh ids are fixed in the
//! scenario, so the ids and the sequence numbers derived from them are the same in every run.
//!
//! The messages of each side are compared as a multiset, each with its channel (reliability and
//! priority), and not in their order: a session sends from the program's calls and from its own
//! answers to its peer, on two threads, and which of two of those goes first is the scheduler's,
//! in either form. Transport messages (the handshake, keep-alives) are not compared: a keep-alive
//! goes out on a timer, and the handshake's cookie is the listener's own.
//!
//! The forms are a build product: `scripts/pico-additional-forms.sh` builds both under the artifact
//! root (`crates/target/pico-forms`). Absent, the test says so and passes, unless
//! `WZ_PICO_FORMS_REQUIRE=1` makes it fail, which a lane that builds the forms sets.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use wz_capture::Dissection;
use wz_integration_tests::bounded::{BoundedOutput as _, BoundedStatus as _};
use wz_integration_tests::common::{
    artifact, baked_library_dir, project_root, read_captured, PortReservation,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Side};
use wz_session_core::inbound::InboundFrame;
use wz_session_core::passive::{Carried, Direction, PassiveFrame};

/// The synthesised endpoint ports; only their order matters to the dissector.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// Where `scripts/pico-additional-forms.sh` puts the two forms and their headers.
fn forms_dir() -> PathBuf {
    artifact("crates").join("target/pico-forms")
}

/// The forms, or `None` with a note naming what to run; a hard failure under
/// `WZ_PICO_FORMS_REQUIRE=1`.
fn forms_or_note() -> Option<PathBuf> {
    let dir = forms_dir();
    let present = [
        "single/libwz_capi_pico.so",
        "split/libwz_capi_pico.so",
        "split/libwz_capi_pico_ext.so",
    ]
    .iter()
    .all(|rel| dir.join(rel).is_file());
    if present {
        return Some(dir);
    }
    let note = format!(
        "the two forms of the pico library are not built in {}: run \
         scripts/pico-additional-forms.sh first",
        dir.display()
    );
    if std::env::var("WZ_PICO_FORMS_REQUIRE").as_deref() == Ok("1") {
        panic!("{note} (WZ_PICO_FORMS_REQUIRE=1)");
    }
    eprintln!("skip: {note}");
    None
}

/// The scenario compiled against one form: `libs` are the libraries of the form, linked in that
/// order from `libdir`, whose directory is baked into the program so it runs with them whatever
/// its environment names.
fn compile(forms: &Path, libdir: &Path, libs: &[&str], out_dir: &Path, form: &str) -> PathBuf {
    let src = project_root().join("crates/wz-capi-pico/tests/c/additional_split_scenario.c");
    let exe = out_dir.join(format!("additional_split_scenario_{form}"));
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let mut cmd = Command::new(&cc);
    cmd.arg("-std=gnu11")
        .arg("-DZENOH_LINUX")
        .arg(format!("-I{}", forms.join("include").display()))
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .arg(format!("-L{}", libdir.display()));
    for lib in libs {
        cmd.arg(format!("-l{lib}"));
    }
    cmd.arg(baked_library_dir(libdir));
    let out = cmd
        .output_bounded()
        .unwrap_or_else(|e| panic!("failed to spawn the C compiler {cc:?}: {e}"));
    assert!(
        out.status.success(),
        "{form}: the scenario did not compile against the form\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    exe
}

/// Run the scenario through a relay in front of its listening session, and return what the relay
/// recorded.
fn record(program: &Path, form: &str) -> Vec<(Side, Vec<u8>)> {
    // Held until the scenario has run: its listening session binds the port at its start.
    let reservation = PortReservation::pick();
    let listen = reservation.port();
    let (proxy, recording) = tap_proxy(listen);
    let mut capture = tempfile::tempfile().expect("the scenario's output");
    let status = Command::new(program)
        .arg(format!("tcp/127.0.0.1:{listen}"))
        .arg(format!("tcp/127.0.0.1:{proxy}"))
        .stdout(capture.try_clone().expect("dup stdout handle"))
        .stderr(capture.try_clone().expect("dup stderr handle"))
        .status_bounded()
        .unwrap_or_else(|e| panic!("{form}: the scenario did not run: {e}"));
    drop(reservation);
    assert!(
        status.success(),
        "{form}: the scenario exited {status:?}\n--- its output ---\n{}",
        read_captured(&mut capture)
    );
    // Let the relay's threads see the end of both streams before the recording is read.
    std::thread::sleep(Duration::from_millis(200));
    let segments = recording.lock().expect("recording lock").clone();
    assert!(
        !segments.is_empty(),
        "{form}: the relay recorded nothing, and two empty recordings are equal"
    );
    segments
}

/// The direction the dialler wrote: the one that opened with an `InitSyn`.
fn dialer_direction(frames: &[&PassiveFrame]) -> Direction {
    let first_init = frames.iter().find_map(|f| match &f.frame {
        Ok(InboundFrame::Init { is_ack, .. }) => Some((f.direction, *is_ack)),
        _ => None,
    });
    match first_init {
        Some((direction, false)) => direction,
        Some((_, true)) => panic!("the first Init in the capture is an InitAck"),
        None => panic!("the capture carries no Init, so there is no handshake to orient by"),
    }
}

/// Each network message either side sent, with its side and channel, and how many times.
fn messages(segments: &[(Side, Vec<u8>)]) -> BTreeMap<String, usize> {
    let pcap = synthesise_pcap(segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let rows: Vec<_> = flows[0].frames().iter().collect();
    let frames: Vec<&PassiveFrame> = rows.iter().map(|row| &**row).collect();
    let dialer = dialer_direction(&frames);
    let mut seen = BTreeMap::new();
    for frame in &frames {
        let Carried::Batch(batch) = &frame.carried else {
            continue;
        };
        let side = if frame.direction == dialer {
            "subscriber"
        } else {
            "publisher"
        };
        let channel = match &frame.frame {
            Ok(InboundFrame::Frame {
                reliable, priority, ..
            }) => format!(
                "{} p{}",
                if *reliable { "reliable" } else { "best-effort" },
                priority.wire_byte()
            ),
            _ => String::from("not a frame"),
        };
        for message in &batch.messages {
            *seen
                .entry(format!("{side} [{channel}] {message:?}"))
                .or_insert(0) += 1;
        }
    }
    seen
}

/// The lines one rendering has more of than the other, for the failure message.
fn surplus(of: &BTreeMap<String, usize>, over: &BTreeMap<String, usize>) -> Vec<String> {
    of.iter()
        .filter(|(line, n)| over.get(*line).copied().unwrap_or(0) < **n)
        .map(|(line, n)| format!("{n} x {line}"))
        .collect()
}

#[test]
fn the_one_library_and_the_two_put_the_same_messages_on_the_wire() {
    let Some(forms) = forms_or_note() else {
        return;
    };
    let out_dir = tempfile::tempdir().expect("a directory for the programs");
    let single = compile(
        &forms,
        &forms.join("single"),
        &["wz_capi_pico"],
        out_dir.path(),
        "single",
    );
    let split = compile(
        &forms,
        &forms.join("split"),
        &["wz_capi_pico", "wz_capi_pico_ext"],
        out_dir.path(),
        "split",
    );

    let one = messages(&record(&single, "single"));
    let two = messages(&record(&split, "split"));

    // What the scenario does is on the wire at all, so an equality below is of something: the
    // live frames are pushes, the history a get's request and its responses.
    for kind in ["Push", "Request", "Response"] {
        assert!(
            one.keys().any(|line| line.contains(kind)),
            "the one library's run carries no {kind}:\n{one:#?}"
        );
    }
    assert!(
        one == two,
        "the two forms put different messages on the wire\n--- only the one library's ---\n{}\n\
         --- only the two libraries' ---\n{}",
        surplus(&one, &two).join("\n"),
        surplus(&two, &one).join("\n")
    );
}
