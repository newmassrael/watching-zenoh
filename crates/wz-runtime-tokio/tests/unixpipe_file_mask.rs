// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]

//! R2363 — the `#file_mask=<n>` locator config key REACHES `mkfifo`, on every
//! node the link creates and through the LOCATOR seam, not only the raw
//! pipeline API.
//!
//! zenoh's unixpipe link declares exactly one locator config key —
//! `io/zenoh-links/zenoh-link-unixpipe/src/unix/mod.rs`
//! @ `pub const FILE_ACCESS_MASK: &str = "file_mask";` — reads it at
//! `io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs`
//! @ `fn endpoint_to_pipe_path` and threads it into every `PipeR::new`, i.e.
//! into the BASE request channel AND into each connection's dedicated pair.
//! Until this round wz hard-coded 0o600 at its own `mkfifo` and read the key
//! nowhere, which is the residual `transport-link-unixpipe` carried.
//!
//! ## Why this file owns the process umask
//!
//! `mkfifo`'s mode argument is masked by the process umask, on BOTH sides (the
//! `unix_named_pipe` crate upstream uses is the same bare syscall), so an
//! assertion on the resulting permission bits is only exact with a known
//! umask. `umask()` is process-global, so these assertions live in their own
//! integration binary — one `#[test]`, driving its own runtime, that sets the
//! umask to 0 and restores it. No other test in this file creates a file.
//!
//! ## Population
//!
//! The nodes are not listed: each case binds inside its OWN empty directory and
//! the assertions walk what is actually there, so a node the implementation
//! creates and this file did not anticipate is still graded. The dedicated
//! pair's names carry a random suffix, which is exactly why listing is the only
//! honest way to reach them.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use wz_runtime_tokio::session_open::{bind_locator, AcceptConfig, BoundListener};
use wz_runtime_tokio::unixpipe_pipeline::{bind_unixpipe, dial_unixpipe, DEFAULT_FILE_MASK};
use wz_session_core::locator::parse_any_locator;

/// A fresh empty directory for one case, so the assertions can WALK the nodes
/// rather than name them.
fn case_dir(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wz-unixpipe-mask-{}-{}-{case}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("the case directory is creatable");
    dir
}

/// Every FIFO under `dir`, as `(file name, permission bits)`. The POPULATION of
/// an assertion — derived from the filesystem, never from a name this test
/// typed.
fn fifo_modes(dir: &Path) -> Vec<(String, u32)> {
    let mut out: Vec<(String, u32)> = std::fs::read_dir(dir)
        .expect("the case directory is readable")
        .map(|e| e.expect("a readable directory entry"))
        .filter_map(|e| {
            let meta = std::fs::metadata(e.path()).ok()?;
            // `S_IFIFO` — a plain file here would be a different bug and must
            // not be quietly counted as a FIFO.
            ((meta.permissions().mode() & libc::S_IFMT) == libc::S_IFIFO).then(|| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    meta.permissions().mode() & 0o7777,
                )
            })
        })
        .collect();
    out.sort();
    out
}

/// Set the process umask to 0 for the duration of the guard and restore it.
struct ZeroUmask(libc::mode_t);

impl ZeroUmask {
    fn take() -> Self {
        // SAFETY: `umask` is always safe to call; it only reads/writes the
        // calling process's own mask and cannot fail.
        Self(unsafe { libc::umask(0) })
    }
}

impl Drop for ZeroUmask {
    fn drop(&mut self) {
        // SAFETY: as above.
        unsafe { libc::umask(self.0) };
    }
}

/// The whole file, as ONE test: it owns the process umask (see the module doc),
/// so it must not run beside anything else that creates a file.
///
/// Each case RETURNS its complaints instead of panicking, and the test reports
/// all four together. A case that panicked would hide every case after it, and
/// what a control probe has to show is exactly WHICH claims it broke and which
/// it left standing — an aggregate that stops at the first failure cannot say
/// that.
#[test]
fn the_file_mask_reaches_every_fifo_the_link_creates() {
    let _umask = ZeroUmask::take();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a tokio runtime");

    let complaints: Vec<String> = rt.block_on(async {
        let mut all = Vec::new();
        for (case, mut found) in [
            ("default", default_when_the_locator_says_nothing().await),
            ("bind", a_bound_listener_carries_the_requested_mask().await),
            ("dedicated", the_dedicated_pair_carries_it_too().await),
            ("locator", the_locator_seam_carries_it().await),
        ] {
            all.extend(found.drain(..).map(|c| format!("[{case}] {c}")));
        }
        all
    });

    assert!(
        complaints.is_empty(),
        "the file mask did not reach every node:\n  {}",
        complaints.join("\n  ")
    );
}

/// `None` = "the locator said nothing", and that is [`DEFAULT_FILE_MASK`] —
/// wz's declared hardening over upstream's 0o777, which this asserts rather
/// than assumes so the divergence cannot drift silently.
async fn default_when_the_locator_says_nothing() -> Vec<String> {
    let dir = case_dir("default");
    let base = dir.join("p").to_string_lossy().into_owned();
    let acc = bind_unixpipe(&base, None)
        .await
        .expect("bind with no file mask");
    let nodes = fifo_modes(&dir);
    let mut out = Vec::new();
    if nodes.len() != 1 {
        out.push(format!(
            "only the base request channel is expected: {nodes:?}"
        ));
    }
    if nodes.first().map(|n| n.1) != Some(DEFAULT_FILE_MASK) {
        out.push(format!(
            "an unspecified mask is wz's own default {DEFAULT_FILE_MASK:o}, not upstream's 0o777: {nodes:?}"
        ));
    }
    drop(acc);
    out
}

/// A requested mask reaches the BASE request channel's `mkfifo`.
async fn a_bound_listener_carries_the_requested_mask() -> Vec<String> {
    // A value that DIFFERS from the default, or the case would pass over an
    // implementation that ignored the argument entirely.
    assert_ne!(
        0o660, DEFAULT_FILE_MASK,
        "this case is only load-bearing while its mask differs from the default"
    );
    let dir = case_dir("bind");
    let base = dir.join("p").to_string_lossy().into_owned();
    let acc = bind_unixpipe(&base, Some(0o660))
        .await
        .expect("bind with an explicit file mask");
    let nodes = fifo_modes(&dir);
    let mut out = Vec::new();
    if nodes.len() != 1 {
        out.push(format!(
            "only the base request channel is expected: {nodes:?}"
        ));
    }
    if nodes.first().map(|n| n.1) != Some(0o660) {
        out.push(format!(
            "the requested mask 0o660 must reach mkfifo: {nodes:?}"
        ));
    }
    drop(acc);
    out
}

/// The DEDICATED pair carries it too — the half a base-only implementation
/// would miss, and the half upstream threads through `dedicate_pipe`. Both
/// sides create nodes here (the dialer's `P_downlink{suffix}`, the listener's
/// `P_uplink{suffix}`), so both are graded.
async fn the_dedicated_pair_carries_it_too() -> Vec<String> {
    let dir = case_dir("dedicated");
    let base = dir.join("p").to_string_lossy().into_owned();
    let mut acc = bind_unixpipe(&base, Some(0o666))
        .await
        .expect("bind with an explicit file mask");
    let dialer = tokio::spawn({
        let base = base.clone();
        async move { dial_unixpipe(&base, Some(0o666)).await }
    });
    let accepted = acc.recv_new_link().await.expect("accept the client");
    let dialed = dialer.await.unwrap().expect("the dial completes");

    let nodes = fifo_modes(&dir);
    let mut out = Vec::new();
    // Base request channel + the dedicated pair. The count is asserted rather
    // than assumed, so a population that SHRANK (a node the handshake stopped
    // creating) cannot make the per-node loop below vacuously green.
    if nodes.len() < 3 {
        out.push(format!(
            "the base channel and the dedicated pair are expected, 3 nodes: {nodes:?}"
        ));
    }
    for (name, mode) in &nodes {
        if *mode != 0o666 {
            out.push(format!(
                "every node the link created must carry 0o666; {name} is {mode:o}"
            ));
        }
    }
    drop(dialed);
    drop(accepted);
    drop(acc);
    out
}

/// The LOCATOR seam, which is the one a deployment actually uses:
/// `unixpipe/<path>#file_mask=<n>` through `bind_locator`. A pipeline-API-only
/// wiring would leave this red, which is the point of the case.
async fn the_locator_seam_carries_it() -> Vec<String> {
    let dir = case_dir("locator");
    let base = dir.join("p").to_string_lossy().into_owned();
    // 0o640 in DECIMAL is 416 — upstream parses this key as a plain `u32`
    // (`val.parse()`), so a locator written for a zenohd spells it decimal too.
    let locator = format!("unixpipe/{base}#file_mask=416");
    let parsed = parse_any_locator(&locator).expect("the locator parses");
    let bound = bind_locator(parsed, &AcceptConfig::default())
        .await
        .expect("the locator binds");
    let mut out = Vec::new();
    if !matches!(bound, BoundListener::Unixpipe(_)) {
        out.push(String::from("the locator must bind a unixpipe listener"));
    }
    let nodes = fifo_modes(&dir);
    if nodes.len() != 1 {
        out.push(format!(
            "only the base request channel is expected: {nodes:?}"
        ));
    }
    if nodes.first().map(|n| n.1) != Some(0o640) {
        out.push(format!(
            "the locator's own #file_mask=416 must reach mkfifo as 0o640: {nodes:?}"
        ));
    }
    drop(bound);
    out
}
