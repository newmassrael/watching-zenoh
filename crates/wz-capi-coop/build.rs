// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one statement of which builds keep the session's round of deliveries (`src/round.rs`), as
//! the cfg `wz_round` every use reads.
//!
//! A build whose read runs beside the program's calls (`threads`, `listen`, `group`) queues each
//! record's callbacks in the round; the read that hands each record out as it is read (`direct`)
//! hands out every sample, token, query and declaration watch's event itself, and keeps the round
//! only for what a get's leg is told (`query`: the session core's sink of a leg holds the round a
//! reply it does not capture goes to). A build of none of them puts nothing in the round, and its
//! text keeps none of what hands a round out. Each kind leaves this list in the commit that hands
//! it out apart from the round.

/// The features whose builds keep the round, as cargo names them to a build script.
const KEEP_THE_ROUND: &[&str] = &[
    "CARGO_FEATURE_THREADS",
    "CARGO_FEATURE_LISTEN",
    "CARGO_FEATURE_GROUP",
    "CARGO_FEATURE_QUERY",
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
