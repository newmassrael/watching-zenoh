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
pub const WZ_CAPI_PICO_ABI_REVISION: u32 = 1;

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
