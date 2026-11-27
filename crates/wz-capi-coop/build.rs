// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one statement of which builds keep the session's round of deliveries (`src/round.rs`) and
//! the work form that steps the faces as tasks of one set, as the cfg `wz_round` every use reads,
//! of which give each value a session lends its links a lock of its own, as the cfg
//! `wz_value_locks` the engine's form reads (`src/form.rs`, `LockForm::SessionLock`), and of
//! which storage policy the session's tables take ([`TablePolicy`]), as the cfg of its name.
//!
//! The read that hands each record out as it is read (`direct`), the faces a session listening
//! takes and the groups it joins among them, hands out every sample, token, query, reply and
//! declaration watch's event itself, and puts nothing in the round: its text keeps none of what
//! hands a round out. A read task beside the program's calls (`threads`) reads that way too where
//! each value has a lock of its own: it reaches a face's values with no session's lock held, and a
//! group's, of one thread's types, under that lock. A `threads` build keeps the round where its
//! form has no such lock.
//!
//! The environment may withhold those locks from a build whose host would give them
//! (`WZ_COOP_VALUE_LOCKS=off`): the form of a `threads` image with no host lock, which keeps the
//! round, is then built on a host, whose tests have `std`. No feature can say it, since `std` is
//! both what the tests need and what gives the locks; a leg of the non-default tests gate builds
//! the crate's tests so, and it is the one host build that compiles the round.
//!
//! And of how the direct form's sends hold the faces they send on, where the read takes faces
//! past the dial role's (`listen`, `group`): each face's send place apart, taken before the
//! session's lock, as the cfg `wz_face_places` reads it, where `face-send-places` is named or a
//! read task beside the program's calls sends from another thread (`threads`); else one place for
//! every face, the session's lock on the one thread of the form, as the cfg `wz_one_send_place`
//! reads it (`src/engine/direct.rs`). A build whose only face is the dial role's has neither.

/// The environment word that withholds the value locks a host lock would give ([`withheld`]).
const VALUE_LOCKS: &str = "WZ_COOP_VALUE_LOCKS";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(wz_round)");
    println!("cargo:rustc-check-cfg=cfg(wz_value_locks)");
    println!("cargo:rustc-check-cfg=cfg(wz_face_places)");
    println!("cargo:rustc-check-cfg=cfg(wz_one_send_place)");
    println!("cargo:rustc-check-cfg=cfg(wz_lent)");
    println!("cargo:rustc-check-cfg=cfg(wz_on_use)");
    match table_policy() {
        TablePolicy::Region => {}
        TablePolicy::Lent => println!("cargo:rustc-cfg=wz_lent"),
        TablePolicy::OnUse => println!("cargo:rustc-cfg=wz_on_use"),
    }
    println!("cargo:rerun-if-env-changed={VALUE_LOCKS}");
    // Read whatever the target, so a word the script refuses is refused on every build.
    let withheld = withheld();
    let value_locks = value_locks() && !withheld;
    if value_locks {
        println!("cargo:rustc-cfg=wz_value_locks");
    }
    let threads = set("CARGO_FEATURE_THREADS");
    let round = threads && !value_locks;
    if round {
        println!("cargo:rustc-cfg=wz_round");
    }
    // A form that keeps the round reaches each link under the session's lock and holds no face's
    // send place at all.
    let takes_faces = set("CARGO_FEATURE_LISTEN") || set("CARGO_FEATURE_GROUP");
    if !round && takes_faces {
        if threads || set("CARGO_FEATURE_FACE_SEND_PLACES") {
            println!("cargo:rustc-cfg=wz_face_places");
        } else {
            println!("cargo:rustc-cfg=wz_one_send_place");
        }
    }
}

/// The storage policy of the session's tables (`wz_session_core::bounded::Storage`), chosen by two
/// facts the features state apart: where the tables' counts come from, the region the build lays
/// out or the config the open lays its plan out from (`runtime-plan`), and when the tables take
/// their memory, at the open or at each table's first row (`tables-on-use`). `src/lib.rs` names
/// the policy's type by the cfg of its name, and every item that differs by the policy reads that
/// cfg, so where the counts come from and when the memory is taken are read apart.
enum TablePolicy {
    /// Placed in the region the build lays out, at the open (`Region`): neither feature.
    Region,
    /// Lent from the arena the open lays out from its config, at the open (`Lent`, `wz_lent`).
    Lent,
    /// Taken from the allocator at each table's first row (`OnUse`, `wz_on_use`).
    OnUse,
}

/// The policy this build's features choose. A session laid out from its config takes its tables
/// at the open, `tables-on-use` or not: its open has no form that takes them on use yet.
fn table_policy() -> TablePolicy {
    let planned = set("CARGO_FEATURE_RUNTIME_PLAN");
    let on_use = set("CARGO_FEATURE_TABLES_ON_USE");
    match (planned, on_use) {
        (true, _) => TablePolicy::Lent,
        (false, true) => TablePolicy::OnUse,
        (false, false) => TablePolicy::Region,
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

/// Whether the environment withholds the value locks (`WZ_COOP_VALUE_LOCKS=off`). Any other
/// value is refused: a misspelt word would otherwise build the host's form under a leg that
/// claims the other.
fn withheld() -> bool {
    match std::env::var(VALUE_LOCKS) {
        Err(std::env::VarError::NotPresent) => false,
        Ok(word) if word == "off" => true,
        other => panic!("{VALUE_LOCKS} is `off` or unset, not {other:?}"),
    }
}
