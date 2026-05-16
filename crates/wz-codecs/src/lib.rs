// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Generated wire codecs for the watching-zenoh Phase B5 codec set.
//!
//! Each `mod <stem>` block includes the sce-codegen Rust output for
//! the matching `sources/codecs/<stem>.scxml` file; `build.rs`
//! emits those files into `$OUT_DIR` at compile time via SCE's
//! in-process `compile_forge_with_imports` entry point.
//!
//! The codegen output references sibling modules with
//! `use super::X::Y;`, so all stems are declared at the same level in
//! this lib.rs (NOT nested) — that puts every codec module as a
//! direct child of the crate root, matching the codegen's `super::X`
//! lookup target.
//!
//! Walking-skeleton scope (R40): only the §6 payload trio (`msg_put`
//! / `msg_del`) and their dependency chain are wired. The full B5
//! codec catalog lands incrementally as Layer 3 wire-interop coverage
//! expands.
//!
//! Builds against `std` for R40 (AP target = Linux + tokio). MCU
//! `no_std + alloc` variant lands when the lwip runtime crate
//! arrives; the codegen output already supports both per
//! `sce-forge-runtime` baseline `no_std` contract.

pub mod timestamp {
    include!(concat!(env!("OUT_DIR"), "/timestamp.rs"));
}

pub mod encoding {
    include!(concat!(env!("OUT_DIR"), "/encoding.rs"));
}

pub mod ext_unit {
    include!(concat!(env!("OUT_DIR"), "/ext_unit.rs"));
}

pub mod ext_zint {
    include!(concat!(env!("OUT_DIR"), "/ext_zint.rs"));
}

pub mod ext_zbuf {
    include!(concat!(env!("OUT_DIR"), "/ext_zbuf.rs"));
}

pub mod ext_entry {
    include!(concat!(env!("OUT_DIR"), "/ext_entry.rs"));
}

pub mod msg_put {
    include!(concat!(env!("OUT_DIR"), "/msg_put.rs"));
}

pub mod msg_del {
    include!(concat!(env!("OUT_DIR"), "/msg_del.rs"));
}
