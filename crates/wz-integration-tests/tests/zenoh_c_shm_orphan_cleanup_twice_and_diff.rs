// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — `zc_cleanup_orphaned_shm_segments` removes the POSIX
//! shm segments no process holds and keeps the ones some process does, on wz's
//! cdylib as on the real `libzenohc.so`.
//!
//! ## Upstream's rule
//!
//! Every `/dev/shm/{id}.zenoh` whose stem is a `u64` is a zenoh segment, and
//! one is an orphan when an EXCLUSIVE non-blocking `flock` on it succeeds —
//! every live holder keeps a SHARED one (`commons/zenoh-shm/src/shm/unix.rs` @
//! `.try_lock(FileLockMode::Exclusive)`). A no-op off Linux.
//!
//! ## The legs (R2954)
//!
//! The harness plants three files per arm, then runs one C program that calls
//! the function and nothing else:
//! - an ORPHAN: a `{id}.zenoh` nothing holds — must be removed;
//! - a HELD one: a `{id}.zenoh` this test keeps a shared `flock` on for the
//!   whole run — must be kept;
//! - a NON-ZENOH one: `{id}.wz` beside them, unlocked — must be kept, because
//!   the rule reads the extension first.
//!
//! The observable is the filesystem, read by the harness, so the two arms are
//! compared on the effect itself rather than on anything the program prints.
//! Each arm gets its own ids, so neither can see the other's files.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library,
};

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<PathBuf> {
    match zenoh_c_oracle() {
        Some((include, _libdir, _examples)) => Some(include),
        None => {
            eprintln!(
                "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers \
                 and libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX). \
                 Layer C1cc with WZ_C1CC_REQUIRE=1 fails instead of skipping."
            );
            None
        }
    }
}

const PROBE: &str = r#"#include <stdio.h>
#include "zenoh.h"

int main(void) {
    zc_cleanup_orphaned_shm_segments();
    printf("done\n");
    return 0;
}
"#;

/// The three files one arm is judged on, and the lock that makes one "held".
struct Planted {
    orphan: PathBuf,
    held: PathBuf,
    other: PathBuf,
    _holder: File,
}

impl Planted {
    /// Plant the three under ids derived from `salt`, above the `u32` range
    /// wz's own segment ids are drawn from, so they cannot meet a live one.
    fn new(salt: u64) -> Self {
        let base = (1u64 << 41) + (u64::from(std::process::id()) << 4) + salt * 4;
        let orphan = PathBuf::from(format!("/dev/shm/{}.zenoh", base));
        let held = PathBuf::from(format!("/dev/shm/{}.zenoh", base + 1));
        let other = PathBuf::from(format!("/dev/shm/{}.wz", base + 2));
        for path in [&orphan, &held, &other] {
            std::fs::write(path, [0u8; 64]).expect("plant a /dev/shm file");
        }
        let holder = File::options()
            .read(true)
            .write(true)
            .open(&held)
            .expect("open the held segment");
        // SAFETY: a borrowed, valid fd; the lock lives as long as `holder`.
        let rc = unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        assert_eq!(rc, 0, "take the holder's shared lock");
        Self {
            orphan,
            held,
            other,
            _holder: holder,
        }
    }

    /// Which of the three survived, in a form two arms can be diffed on.
    fn survivors(&self) -> String {
        format!(
            "orphan={} held={} other={}",
            self.orphan.exists(),
            self.held.exists(),
            self.other.exists()
        )
    }
}

impl Drop for Planted {
    fn drop(&mut self) {
        for path in [&self.orphan, &self.held, &self.other] {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Compile the probe against one library and run it over freshly planted
/// files, answering what survived.
fn run_arm(include: &Path, dir: &Path, libdir: &Path, lib: &str, salt: u64) -> String {
    let src_dir = dir.join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_shm_cleanup.c"), PROBE).expect("write the probe source");
    let exe = compile_zenoh_c_example("wz_shm_cleanup", dir, include, &src_dir, libdir, lib)
        .unwrap_or_else(|diag| panic!("the cleanup probe does not link against {lib}\n{diag}"));
    let planted = Planted::new(salt);
    let out = Command::new(&exe)
        .env("LD_LIBRARY_PATH", libdir)
        .output_bounded()
        .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success() && stdout.contains("done"),
        "the cleanup probe did not complete against {lib}:\n{stdout}"
    );
    planted.survivors()
}

/// THE GATE: the cleanup removes exactly the orphaned zenoh segment, on wz as
/// on libzenohc.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle and writes /dev/shm; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn orphaned_shm_segments_are_cleaned_up_identically_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    // The function exists only on the shared-memory-with-unstable arm, upstream's
    // and wz's alike, so an oracle built without it has nothing to adjudicate.
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h")).unwrap_or_default();
    let defines = |name: &str| {
        configure
            .lines()
            .any(|l| l.trim() == format!("#define {name}"))
    };
    if !(defines("Z_FEATURE_UNSTABLE_API") && defines("Z_FEATURE_SHARED_MEMORY")) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where zc_cleanup_orphaned_shm_segments does not exist."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);

    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let libdir_ref = reference.parent().expect("libzenohc.so has a parent");
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = run_arm(&include, &ref_dir, libdir_ref, "zenohc", 0);

    let wz_lib = wz_capi_c_cdylib();
    let wz_libdir = wz_lib.parent().expect("cdylib has a parent");
    let wz_dir = dir.path().join("wz");
    std::fs::create_dir_all(&wz_dir).expect("wz build dir");
    let on_wz = run_arm(&include, &wz_dir, wz_libdir, "wz_capi_c", 1);

    // The ORACLE first: two identical failures diff clean.
    assert_eq!(
        on_ref, "orphan=false held=true other=true",
        "the reference does not clean up by the rule this leg holds wz to"
    );
    assert_eq!(
        on_wz, on_ref,
        "§5.27 api-compat-c: wz's C ABI and libzenohc disagree about which \
         /dev/shm segments are orphaned"
    );
}
