// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one statement of which builds keep the session's round of deliveries (`src/round.rs`) and
//! the work form that steps the faces as tasks of one set, as the cfg `wz_round` every use reads:
//! a feature leaves this list once its faces are read where they lie.
//!
//! A build whose read runs beside the program's calls (`threads`, `listen`, `group`) queues each
//! record's callbacks in the round; the read that hands each record out as it is read (`direct`)
//! hands out every sample, token, query, reply and declaration watch's event itself, and puts
//! nothing in the round: its text keeps none of what hands a round out.

/// The features whose builds keep the round, as cargo names them to a build script.
const KEEP_THE_ROUND: &[&str] = &[
    "CARGO_FEATURE_THREADS",
    "CARGO_FEATURE_LISTEN",
    "CARGO_FEATURE_GROUP",
];

fn main() {
    println!("cargo:rustc-check-cfg=cfg(wz_round)");
    if KEEP_THE_ROUND
        .iter()
        .any(|feature| std::env::var_os(feature).is_some())
    {
        println!("cargo:rustc-cfg=wz_round");
    }
}
