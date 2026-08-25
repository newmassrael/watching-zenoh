// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2103 (open-debt item 521) — this crate's `cdylib` gets a SONAME.
//!
//! Sharper here than anywhere else in the workspace: the whole claim of this
//! crate is that it is a BINARY DROP-IN for zenoh-c, and a library a consumer
//! cannot redistribute is not a drop-in for one it can. The reason and the
//! platform rule live in `wz_cdylib_build`.

fn main() {
    wz_cdylib_build::emit_soname("wz_capi_c");
}
