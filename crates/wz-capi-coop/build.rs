// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one statement of which builds keep the session's round of deliveries (`src/round.rs`) and
//! the work form that steps the faces as tasks of one set, as the cfg `wz_round` every use reads:
//! a feature leaves this list once its faces are read where they lie.
//!
//! A build that joins a group (`group`) queues each record's callbacks in the round; the read that
//! hands each record out as it is read (`direct`), the faces a session listening takes among them,
//! hands out every sample, token, query, reply and declaration watch's event itself, and puts
//! nothing in the round: its text keeps none of what hands a round out. A read task beside the
//! program's calls (`threads`) reads that way too, where the engine's form gives each value a lock
//! of its own (`src/form.rs`, `LockForm::SessionLock`): it reaches a face's values with no
//! session's lock held. A `threads` build whose form has no such lock keeps the round.

/// The features whose builds keep the round, as cargo names them to a build script.
const KEEP_THE_ROUND: &[&str] = &["CARGO_FEATURE_GROUP"];

fn main() {
    println!("cargo:rustc-check-cfg=cfg(wz_round)");
    if KEEP_THE_ROUND.iter().any(|feature| set(feature)) || threads_keep_the_round() {
        println!("cargo:rustc-cfg=wz_round");
    }
}

/// Whether cargo set `feature` for this build.
fn set(feature: &str) -> bool {
    std::env::var_os(feature).is_some()
}

/// Whether a `threads` build keeps the round: where its form has no lock of each value's own,
/// which a host lock (`std` or `host-sys`) on a target with 8- and 64-bit atomics gives, as
/// `src/form.rs` chooses the session's lock kind by the same terms.
fn threads_keep_the_round() -> bool {
    if !set("CARGO_FEATURE_THREADS") {
        return false;
    }
    let host_lock = set("CARGO_FEATURE_STD") || set("CARGO_FEATURE_HOST_SYS");
    let atomics = std::env::var("CARGO_CFG_TARGET_HAS_ATOMIC").unwrap_or_default();
    let has = |width: &str| atomics.split(',').any(|held| held == width);
    !(host_lock && has("8") && has("64"))
}
