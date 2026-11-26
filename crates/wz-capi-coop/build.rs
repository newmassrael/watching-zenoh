// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one statement of which builds keep the session's round of deliveries (`src/round.rs`) and
//! the work form that steps the faces as tasks of one set, as the cfg `wz_round` every use reads,
//! and of which give each value a session lends its links a lock of its own, as the cfg
//! `wz_value_locks` the engine's form reads (`src/form.rs`, `LockForm::SessionLock`).
//!
//! The read that hands each record out as it is read (`direct`), the faces a session listening
//! takes and the groups it joins among them, hands out every sample, token, query, reply and
//! declaration watch's event itself, and puts nothing in the round: its text keeps none of what
//! hands a round out. A read task beside the program's calls (`threads`) reads that way too where
//! each value has a lock of its own: it reaches a face's values with no session's lock held, and a
//! group's, of one thread's types, under that lock. A `threads` build keeps the round where its
//! form has no such lock.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(wz_round)");
    println!("cargo:rustc-check-cfg=cfg(wz_value_locks)");
    let value_locks = value_locks();
    if value_locks {
        println!("cargo:rustc-cfg=wz_value_locks");
    }
    if set("CARGO_FEATURE_THREADS") && !value_locks {
        println!("cargo:rustc-cfg=wz_round");
    }
}

/// Whether cargo set `feature` for this build.
fn set(feature: &str) -> bool {
    std::env::var_os(feature).is_some()
}

/// Whether the form of several threads gives each value a session lends its links a lock of its
/// own: a host lock (`std` or `host-sys`, the runtime's `host-lock`) on a target with 8- and
/// 64-bit atomics, the terms the runtime builds `wz_runtime_coop::sync::ManyThreads` by.
fn value_locks() -> bool {
    let host_lock = set("CARGO_FEATURE_STD") || set("CARGO_FEATURE_HOST_SYS");
    let atomics = std::env::var("CARGO_CFG_TARGET_HAS_ATOMIC").unwrap_or_default();
    let has = |width: &str| atomics.split(',').any(|held| held == width);
    host_lock && has("8") && has("64")
}
