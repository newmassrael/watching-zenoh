// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport/link/unixpipe/file_access_mask` -- the mode a `unixpipe/` listener creates its
//! request FIFO with, one config document handed to a unixpipe zenohd with `-c` and to the wz
//! demo with `--config`.
//!
//! ## Upstream's rule
//!
//! The key is rendered into every unixpipe endpoint's configuration as `file_mask`
//! (`io/zenoh-links/zenoh-link-unixpipe/src/unix/mod.rs` @
//! `properties.push((config::FILE_ACCESS_MASK, &file_access_mask_));`), and the listener creates
//! its request channel `<path>_uplink` with `mkfifo` at that mode
//! (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @
//! `let r_was_created = create(path_r, Some(access_mode));`), so the process umask applies to it
//! as it applies to any `mkfifo`. Both implementations here inherit this test's umask.
//!
//! ## The observer
//!
//! The FIFO itself: its permission bits, read with `stat` once it exists. Nothing dials it.
//!
//! Without the key the two differ on purpose: upstream's default is `0o777`, wz's `0o600`
//! (`crates/wz-runtime-tokio/src/unixpipe_pipeline.rs`, `DEFAULT_FILE_MASK`). That row is the
//! control on zenohd alone: the keyed rows must differ from it there, or the key is not what
//! decides the mode on this host. Each keyed row is then compared between the two. `0o700` is
//! off both defaults under any umask that leaves the owner's bits, so wz's match there cannot be
//! its default.

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_unixpipe_request_fifo,
    wz_ap_demo_binary, zenohd_unixpipe_binary, ChildGuard,
};

/// How long a listener gets to create its request FIFO.
const BOUND_WITHIN: Duration = Duration::from_secs(15);

/// The two listeners handed the document.
#[derive(Clone, Copy, Debug)]
enum Listener {
    Zenohd,
    Wz,
}

/// The document: the unixpipe kind's `file_access_mask` when `mask` states one, and nothing else.
/// JSON5 has no octal literal, so the mask is written in decimal, as upstream reads it.
fn document(mask: Option<u32>) -> String {
    match mask {
        Some(mask) => {
            format!("{{ transport: {{ link: {{ unixpipe: {{ file_access_mask: {mask} }} }} }} }}")
        }
        None => String::from("{ }"),
    }
}

/// The listener's command on `endpoint` with `document`.
fn listener_command(listener: Listener, endpoint: &str, document: &Path) -> Command {
    match listener {
        Listener::Zenohd => {
            let mut cmd = Command::new(zenohd_unixpipe_binary());
            cmd.args([
                "-l",
                endpoint,
                "--no-multicast-scouting",
                "--rest-http-port",
                "none",
            ])
            .arg("-c")
            .arg(document);
            cmd
        }
        Listener::Wz => {
            let mut cmd = Command::new(wz_ap_demo_binary());
            cmd.args(["--listen", endpoint, "--key", "demo/unixpipe-mask"])
                .arg("--config")
                .arg(document)
                .env("RUST_LOG", "info");
            cmd
        }
    }
}

/// Start `listener` on a fresh base with the document for `mask`, and return the permission bits
/// of the request FIFO it created, or `None` when it created none, with its output.
fn observe(listener: Listener, mask: Option<u32>) -> (Option<u32>, String) {
    let dir = tempfile::tempdir().expect("a directory for the pipe and the document");
    let base = dir.path().join("pipe").display().to_string();
    let file = dir.path().join("node.json5");
    std::fs::write(&file, document(mask)).expect("write the document");
    let endpoint = format!("unixpipe/{base}");
    let capture = tempfile::tempfile().expect("tempfile for the listener's output");
    let mut log = capture.try_clone().expect("dup the capture handle");
    let mut child = ChildGuard::wrap(
        format!("{listener:?} listening on {endpoint} with {mask:?}"),
        listener_command(listener, &endpoint, &file)
            .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
            .stderr(Stdio::from(capture))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {listener:?}: {e}")),
    );
    let mode = if wait_for_unixpipe_request_fifo(&base, BOUND_WITHIN) {
        std::fs::symlink_metadata(format!("{base}_uplink"))
            .map(|meta| meta.permissions().mode() & 0o777)
            .ok()
    } else {
        None
    };
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();
    (mode, read_captured(&mut log))
}

/// A unixpipe listener's request FIFO takes the mode the document's `file_access_mask` states, on
/// wz as on zenohd.
///
/// # Control
///
/// zenohd on the document without the key: each keyed row's mode on zenohd must differ from it,
/// so the key is what decided the mode.
// wz-proves: transport-link-unixpipe zenohd->wz partial
#[test]
#[ignore = "binary-dep: needs target/zenohd-unixpipe/zenohd + wz-ap-demo[+transport-link-unixpipe,zenoh-config]"]
fn a_unixpipe_listeners_request_fifo_takes_the_file_access_mask_as_zenohd_does() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let (unkeyed, unkeyed_log) = observe(Listener::Zenohd, None);
    let unkeyed = unkeyed.unwrap_or_else(|| {
        panic!("zenohd created no request FIFO without the key\n--- zenohd ---\n{unkeyed_log}")
    });
    // 0o700 and 0o640, in decimal.
    for mask in [448u32, 416] {
        let (by_zenohd, zenohd_log) = observe(Listener::Zenohd, Some(mask));
        let by_zenohd = by_zenohd.unwrap_or_else(|| {
            panic!(
                "zenohd created no request FIFO with mask {mask:o}\n--- zenohd ---\n{zenohd_log}"
            )
        });
        assert_ne!(
            by_zenohd, unkeyed,
            "zenohd's FIFO took {by_zenohd:o} with mask {mask:o} and {unkeyed:o} without it, so \
             this host's umask hides the key and the row cannot adjudicate wz"
        );
        let (by_wz, wz_log) = observe(Listener::Wz, Some(mask));
        assert_eq!(
            by_wz,
            Some(by_zenohd),
            "with mask {mask:o} the wz demo's request FIFO took {by_wz:?} where zenohd's took \
             {by_zenohd:o}\n--- wz ---\n{wz_log}"
        );
    }
}
