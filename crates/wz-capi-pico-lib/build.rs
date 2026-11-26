// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The SONAME of the pico C library (`wz_cdylib_build` holds the reason and the platform rule).

fn main() {
    wz_cdylib_build::emit_soname("wz_capi_pico");
}
