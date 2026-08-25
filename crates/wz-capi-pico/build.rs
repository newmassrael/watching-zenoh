// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2103 (open-debt item 521) — this crate's `cdylib` gets a SONAME.
//!
//! The zenoh-pico drop-in half of the same claim `wz-capi-c` makes: a program
//! written for zenoh-pico links this artifact, and could not redistribute what
//! it linked. The reason and the platform rule live in `wz_cdylib_build`.

fn main() {
    wz_cdylib_build::emit_soname("wz_capi_pico");
}
