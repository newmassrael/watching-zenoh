// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The revision of this library's wz-own contract, and the stamp that carries it.
//!
//! This crate is a drop-in for zenoh-pico, so the `z_*` / `zp_*` surface is upstream's contract and a
//! number minted here says nothing about it (the argument `wz-capi-c`'s `abi.rs` makes for its own).
//! What the revision covers is what a consumer of THIS build can depend on beyond upstream's header:
//! which arm of the header the library is (the layout switches below) and the set of wz-only
//! behaviours a deployment relies on.
//!
//! # The stamp
//!
//! A tool that describes this library for a device it cannot run on reads the family, the revision
//! and the layout arm from the artifact's bytes (`wz-abi-stamp`; `docs/target-build-contract.md`
//! T6). The four layout values are the switches that change the size of a struct a pico program
//! allocates, each documented where its feature is declared in `Cargo.toml`: a program links the
//! library of the arm it compiled its header against.
//!
//! # When it moves
//!
//! One integer, bumped when something a consumer built against the previous number cannot survive:
//! a removed or renamed wz-only door, or a changed meaning of one. A new door, and a new
//! capability that a consumer opts into, do not move it. It starts at 1 because the library had no
//! revision before this round, so there is no earlier number to be compatible with.

/// The revision the stamp carries.
///
/// It moved to 2 when the meaning of a wz-only behaviour changed: with a registered clock
/// (`wz_ext_clock_source_register`), `z_timestamp_new` gives a program the clock's time whatever
/// the clock's standing, and the `clock-quality-stamping` policy holds back only the data the node
/// stamps; at 1 a `trusted-only` build gave a program no time until the clock was reported trusted.
/// Also at 2, every time one session gives strictly increases, whichever clock it is read from and
/// whether a program asks for it (`z_timestamp_new`) or the session's advanced publisher stamps a
/// sample with it: one last time given per session, which the session's node clock learns. So a
/// stamp made after a registered clock ahead of the system clock is removed goes on from the last
/// one given, and a sample is never stamped at or before a time a program was given; at 1 the
/// first was the system clock's reading and the two were not ordered against each other.
pub const WZ_CAPI_PICO_ABI_REVISION: u32 = 2;

wz_abi_stamp::stamp!(
    family = "capi-pico",
    revision = WZ_CAPI_PICO_ABI_REVISION,
    layout = [
        ("multi_thread", cfg!(feature = "multi-thread")),
        ("unstable_api", cfg!(feature = "unstable-api")),
        ("local_subscriber", cfg!(feature = "local-subscriber")),
        ("local_queryable", cfg!(feature = "local-queryable")),
    ],
);
