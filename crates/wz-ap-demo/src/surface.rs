// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The revision of this executable's argument and document surface, and the stamp that carries it.
//!
//! What a deployment tool depends on in this binary is how it is driven: the arguments of
//! `--help`, the keys of a `--sessions` document (including `driver`) and of a stock zenoh config
//! document. The revision is that surface's one integer, and it has no layout switch (a program
//! does not allocate this binary's types).
//!
//! # When it moves
//!
//! When a consumer that drove the previous number can no longer drive this one: an argument or a
//! document key removed or renamed, or its meaning changed. An argument, a key or a driver role
//! ADDED does not move it; which of them a build has is in the feature list the binary prints
//! (`BUILD FEATURES`), and the manifest of `docs/target-build-contract.md` lists the roles the
//! build contains. It starts at 1 because the surface had no revision before this round.

/// The revision the stamp carries.
///
/// Read only by the stamp, which exists on ELF targets; elsewhere nothing reads it.
#[allow(dead_code)]
pub(crate) const SURFACE_REVISION: u32 = 1;

wz_abi_stamp::stamp!(
    family = "ap-demo-surface",
    revision = SURFACE_REVISION,
    layout = [],
);

// What this build plays, computed from its own role table: the driver roles whose feature is on.
// A tool describing the executable for another operating system reads it from the file.
wz_abi_stamp::facts!(
    lists = [(
        "driver_roles",
        &crate::sessions_driver::roles::AVAILABLE_WORDS
    )]
);
