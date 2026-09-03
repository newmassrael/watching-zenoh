// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2300 (open-debt item 631) — the config the C DOOR emits, judged by a REAL
//! zenohd.
//!
//! # Why this file exists beside the unit tests
//!
//! `wz_capi_c_config_to_json5` renders a document for a stock zenoh node, and
//! that is a claim ABOUT ZENOH which nothing inside wz can settle. The unit
//! test beside the door round-trips the output through wz's own reader, which
//! proves the emitter agrees with the reader and NOTHING MORE — both are wz.
//!
//! The consumer that asked for this door named the failure by hand before it
//! was built: *"if you compare strings without seeing whether real zenoh reads
//! the document, a key emitted at the wrong path passes even when the name is
//! entirely wrong."* That is exactly right, and it is not hypothetical — a key
//! at the wrong path is NOT a parse error in zenoh, it is silently ignored, and
//! zenoh's resolved-config line then shows its own DEFAULT where wz's value
//! should be. So the assertion here is on the VALUES zenoh resolved, never on
//! zenohd merely having started.
//!
//! # Why it is not folded into the existing interop lane
//!
//! `zenoh_config_emit_zenohd_interop` (R311y579, in `wz-integration-tests`)
//! already does this for the RUST emitter, and the natural instinct is to add a
//! case there. It cannot: `wz-capi-c` is deliberately not a normal dependency
//! of that crate — its `#[no_mangle]` symbols would collide — and the door
//! under test here is reachable only by linking it. The two files are the same
//! question asked of two emitters, and the second emitter is the C ABI's.
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` (set
//! `WZ_ZENOHD_BIN` or run `scripts/build-zenohd.sh`). Run via Layer Z /
//! `--ignored`.

use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{z_moved_string_t, z_owned_config_t, z_owned_string_t};
use wz_capi_c::config::{
    z_config_default, z_config_loan, z_config_loan_mut, zc_config_insert_json5,
};
use wz_capi_c::config_verdict::{wz_capi_c_config_to_json5, wz_capi_c_config_validate};
use wz_capi_c::result::Z_OK;
use wz_capi_c::string::{z_string_data, z_string_drop, z_string_len, z_string_loan};

/// zenohd prints its resolved config on this line before doing anything else.
const RESOLVED_CONF_MARKER: &str = "Initial conf:";

/// How long to wait for zenohd to either print its resolved config or exit.
const STARTUP_BUDGET: Duration = Duration::from_secs(30);

/// Locate the reference `zenohd`: the `WZ_ZENOHD_BIN` override, else
/// `scripts/build-zenohd.sh`'s install.
///
/// A private copy of `wz_integration_tests::common::zenohd_binary` for the
/// reason the module header gives — that crate cannot depend on this one — and
/// kept to the two lines that resolve a path so there is nothing here to drift.
fn zenohd_binary() -> PathBuf {
    if let Ok(p) = std::env::var("WZ_ZENOHD_BIN") {
        return PathBuf::from(p);
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/zenohd/zenohd")
        .canonicalize()
        .expect("target/zenohd/zenohd is missing; run scripts/build-zenohd.sh");
    assert!(path.is_file(), "{} is not a file", path.display());
    path
}

/// Kills the child on drop, so a test that panics does not leave a zenohd
/// holding a port.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Build an owned config the way a C caller does.
unsafe fn config_of(entries: &[(&str, &str)]) -> z_owned_config_t {
    // SAFETY: a zeroed owned config is this ABI's gravestone.
    let mut cfg: z_owned_config_t = unsafe { std::mem::zeroed() };
    // SAFETY: a writable owned slot.
    assert_eq!(unsafe { z_config_default(&mut cfg) }, Z_OK);
    for (key, value) in entries {
        let k = CString::new(*key).expect("key has no NUL");
        let v = CString::new(*value).expect("value has no NUL");
        // SAFETY: a live config and two NUL-terminated strings.
        let rc =
            unsafe { zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr()) };
        assert_eq!(rc, Z_OK, "the C insert path refused {key} = {value}");
    }
    cfg
}

/// Read an owned string out and free it, THROUGH THE PUBLISHED DOORS.
///
/// `z_string_loan` / `_data` / `_len` rather than the struct's fields, which
/// are private outside the crate — and rightly so. An integration test is a C
/// caller, and a C caller has exactly these three; reaching past them would
/// test a surface no consumer can use.
unsafe fn take_text(out: &mut z_owned_string_t) -> String {
    // SAFETY: a live or gravestone owned string, which is what loan takes.
    let loaned = unsafe { z_string_loan(out) };
    let text = if loaned.is_null() {
        String::new()
    } else {
        // SAFETY: a loaned string from this library.
        let (ptr, len) = unsafe { (z_string_data(loaned), z_string_len(loaned)) };
        if ptr.is_null() {
            String::new()
        } else {
            // SAFETY: the library's own buffer, `len` bytes long.
            let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
            String::from_utf8(bytes.to_vec()).expect("wz emits UTF-8")
        }
    };
    // SAFETY: a live owned string; freeing it is the caller's contract.
    unsafe { z_string_drop((out as *mut z_owned_string_t).cast::<z_moved_string_t>()) };
    text
}

/// Emit a config document THROUGH THE C DOOR.
fn emitted_document(entries: &[(&str, &str)]) -> String {
    // SAFETY: a fixture config, alive across the call below.
    let cfg = unsafe { config_of(entries) };
    // SAFETY: a zeroed owned string is this ABI's gravestone.
    let mut out: z_owned_string_t = unsafe { std::mem::zeroed() };
    // SAFETY: a live owned config and a writable out slot.
    let rc = unsafe { wz_capi_c_config_to_json5(z_config_loan(&cfg), &mut out) };
    // SAFETY: the door wrote a gravestone or a live string.
    let text = unsafe { take_text(&mut out) };
    assert_eq!(rc, Z_OK, "the emit door refused the config: {text}");
    text
}

/// Write `json5` where zenohd can read it.
///
/// The `.json5` SUFFIX is load-bearing: zenoh dispatches its config parser on
/// the file EXTENSION and panics on a file without one, before reading a single
/// byte. An extensionless tempfile is refused before the config is seen at all.
fn staged_config(json5: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    file.write_all(json5.as_bytes()).expect("write config");
    file.flush().expect("flush config");
    file
}

/// Spawn zenohd on `config_path` and NOTHING else.
///
/// No `-l`, no `--cfg`, no `--no-multicast-scouting`: the config file is the
/// sole input, which is the whole claim under test. A CLI flag alongside it
/// would leave open which of the two zenohd actually obeyed. Only
/// `--rest-http-port none`, because the REST plugin binds a fixed default port
/// and two concurrent zenohds would collide on it for unrelated reasons.
fn spawn_on_config(config_path: &std::path::Path) -> (ChildGuard, std::fs::File) {
    // BOTH streams into ONE capture: zenohd prints the resolved config on
    // stdout and a refusal on stderr, and a test that had to know which stream
    // a line came from would be asserting on zenohd's logging layout.
    let capture = tempfile::tempfile().expect("tempfile for zenohd output");
    let out = capture.try_clone().expect("dup zenohd stdout handle");
    let err = capture.try_clone().expect("dup zenohd stderr handle");
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-c")
        .arg(config_path)
        .arg("--rest-http-port")
        .arg("none")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    (ChildGuard(command.spawn().expect("spawn zenohd")), capture)
}

/// Everything zenohd has written so far.
fn read_captured(capture: &mut std::fs::File) -> String {
    let mut text = String::new();
    capture.seek(SeekFrom::Start(0)).expect("rewind capture");
    capture.read_to_string(&mut text).expect("read capture");
    text
}

/// Wait until `needle` appears in the capture, or the child exits, or the
/// budget runs out.
fn wait_for_substring(
    child: &mut Child,
    capture: &mut std::fs::File,
    needle: &str,
) -> Result<String, String> {
    let deadline = Instant::now() + STARTUP_BUDGET;
    loop {
        let text = read_captured(capture);
        if text.contains(needle) {
            return Ok(text);
        }
        if let Ok(Some(status)) = child.try_wait() {
            // One more read: the line may have landed between the two calls.
            let text = read_captured(capture);
            if text.contains(needle) {
                return Ok(text);
            }
            return Err(format!(
                "zenohd exited ({status:?}) without {needle:?}\n{text}"
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "zenohd never printed {needle:?} within {STARTUP_BUDGET:?}\n{}",
                read_captured(capture)
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Wait for the child to exit and hand back its status.
fn wait_for_exit(child: &mut Child) -> Result<std::process::ExitStatus, String> {
    let deadline = Instant::now() + STARTUP_BUDGET;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(e) => return Err(format!("wait failed: {e}")),
        }
        if Instant::now() >= deadline {
            return Err(format!("still running after {STARTUP_BUDGET:?}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// wz-proves: none -- the same REGISTRATION gap `zenoh_config_emit_zenohd_interop`
// records for itself: zenohd genuinely adjudicates wz here (it parses a document
// the C door emitted and echoes back the values it resolved), but `zenoh-config`
// is not in the atom inventory, so no atom name may be claimed. Registering one
// moves the A3/A4 denominators other gates pin and belongs to its own round.
//
/// R2300 (open-debt item 631) — A REAL ZENOHD STARTS ON THE DOCUMENT THE C DOOR
/// EMITTED, AND REPORTS BACK THE VALUES IT CARRIED.
///
/// The discriminating form, and the reason it is not "zenohd started": a key
/// emitted at the wrong PATH is silently ignored by zenoh, so a node started on
/// a document with every key misplaced comes up perfectly and runs on defaults.
/// Asserting the resolved values is what separates "the door emitted valid
/// JSON" from "the door emitted the config it meant".
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn wz_capi_c_config_to_json5_starts_a_real_zenohd() {
    let port = wz_runtime_tokio_test_support::free_port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let listen = format!("[\"{endpoint}\"]");
    let document = emitted_document(&[
        ("mode", "\"router\""),
        ("listen/endpoints", listen.as_str()),
        ("scouting/multicast/enabled", "false"),
        ("transport/link/tx/batch_size", "60000"),
    ]);

    let file = staged_config(&document);
    let (mut guard, mut capture) = spawn_on_config(file.path());
    let text = wait_for_substring(&mut guard.0, &mut capture, RESOLVED_CONF_MARKER)
        .unwrap_or_else(|e| panic!("{e}\n--- the document the C door emitted ---\n{document}"));

    // The resolved line, which is the config AFTER zenoh's own parser has had
    // it. Every value below must be zenoh's reading of what wz wrote, not
    // zenoh's default — a misplaced key shows up here as the default.
    let resolved = text
        .lines()
        .find(|l| l.contains(RESOLVED_CONF_MARKER))
        .expect("the marker was found, so its line exists");
    for (what, needle) in [
        ("the listen endpoint", endpoint.as_str()),
        ("the router mode", "\"router\""),
        ("the batch size", "60000"),
    ] {
        assert!(
            resolved.contains(needle),
            "zenohd resolved a config without {what} ({needle}), so the door \
             emitted it at a path zenoh does not read\n--- resolved ---\n{resolved}\n\
             --- the document the C door emitted ---\n{document}"
        );
    }
    // Multicast scouting OFF is spelled as a nested false; assert the block
    // rather than a bare `false`, which occurs many times in a resolved config.
    assert!(
        resolved.contains("\"multicast\""),
        "the resolved config carries no scouting/multicast block\n{resolved}"
    );
}

// wz-proves: none -- as above.
//
/// R2300 (open-debt item 631) — A REAL ZENOHD REFUSES WHAT THE C VALIDATOR
/// REJECTS.
///
/// Without this the validator's rules are wz's OPINION about zenoh; with it
/// they are zenoh's measured behaviour. The positive control comes first: the
/// same shape with the defect removed must START, or "zenohd exited" would be
/// evidence about the harness — a bad path, a missing binary — rather than
/// about the defect.
///
/// Two cases rather than the validator's full population, and the split is
/// deliberate: this file's subject is whether zenoh AGREES, and the two below
/// are the ones whose refusal zenohd states in its own words. The population
/// question — every `ConfigDefect` variant reachable through the door — is the
/// unit test's, which runs without a binary dependency and so runs everywhere.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn a_real_zenohd_refuses_what_the_c_validator_rejects() {
    // THE POSITIVE CONTROL.
    let control_port = wz_runtime_tokio_test_support::free_port();
    let control = [
        ("mode", "\"router\""),
        ("scouting/multicast/enabled", "false"),
    ];
    let control_listen = format!("[\"tcp/127.0.0.1:{control_port}\"]");
    let mut control_entries = control.to_vec();
    control_entries.push(("listen/endpoints", control_listen.as_str()));
    let control_document = emitted_document(&control_entries);
    {
        let file = staged_config(&control_document);
        let (mut guard, mut capture) = spawn_on_config(file.path());
        if let Err(e) = wait_for_substring(&mut guard.0, &mut capture, RESOLVED_CONF_MARKER) {
            panic!("the positive control never came up, so this test can prove nothing: {e}");
        }
    }

    for (label, entries) in [
        (
            "unknown protocol",
            vec![
                ("mode", "\"router\""),
                ("listen/endpoints", "[\"carrier-pigeon/127.0.0.1:1\"]"),
                ("scouting/multicast/enabled", "false"),
            ],
        ),
        (
            "qos + lowlatency",
            vec![
                ("mode", "\"router\""),
                ("scouting/multicast/enabled", "false"),
                ("transport/unicast/qos/enabled", "true"),
                ("transport/unicast/lowlatency", "true"),
            ],
        ),
    ] {
        // FIRST the C validator must reject it, or the case is not about
        // agreement at all.
        // SAFETY: a fixture config, alive across the call below.
        let cfg = unsafe { config_of(&entries) };
        // SAFETY: a zeroed owned string is this ABI's gravestone.
        let mut out: z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: a live owned config and a writable out slot.
        let rc = unsafe { wz_capi_c_config_validate(z_config_loan(&cfg), &mut out) };
        // SAFETY: the door wrote a gravestone or a live string.
        let defects = unsafe { take_text(&mut out) };
        assert_eq!(rc, Z_OK, "{label}: the validator door refused the config");
        assert!(
            !defects.is_empty(),
            "{label}: the C validator reports nothing, so there is no claim for \
             zenohd to agree with"
        );

        // THEN zenohd must refuse the emitted document.
        let document = emitted_document(&entries);
        let file = staged_config(&document);
        let (mut guard, mut capture) = spawn_on_config(file.path());
        let status = wait_for_exit(&mut guard.0).unwrap_or_else(|e| {
            panic!("{label}: zenohd kept running on a config wz calls invalid: {e}\n{document}")
        });
        // The exit is the observable; the message is read back so the test
        // cannot pass on an unrelated crash.
        let captured = read_captured(&mut capture);
        assert!(
            captured.contains("Exiting")
                || captured.contains("incompatible")
                || captured.contains("not supported"),
            "{label}: zenohd exited ({status:?}) but not for the reason wz \
             predicted\n--- wz said ---\n{defects}\n--- zenohd said ---\n{captured}"
        );
    }
}
