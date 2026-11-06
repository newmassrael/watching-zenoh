// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2103 (open-debt item 521) — this crate's `cdylib` gets a SONAME.
//!
//! Sharper here than anywhere else in the workspace: the whole claim of this
//! crate is that it is a BINARY DROP-IN for zenoh-c, and a library a consumer
//! cannot redistribute is not a drop-in for one it can. The reason and the
//! platform rule live in `wz_cdylib_build`.

fn main() {
    wz_cdylib_build::emit_soname("wz_capi_c");
    // The conformance digest of this build (docs/build-configuration.md, decision C15), which
    // `wz_capi_c_conformance_digest` hands out (`src/conformance.rs`).
    wz_conformance_build::emit("c");
}
