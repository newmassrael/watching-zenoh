// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2103 (open-debt item 521) — this crate's `cdylib` gets a SONAME.
//!
//! Without one, a consumer linking `libwz_capi_dissect.so` BY PATH records that
//! absolute build-time path in its own `DT_NEEDED` and can no longer ship what
//! it built. This is the crate the downstream report arrived about; the reason
//! and the platform rule live in `wz_cdylib_build`.

fn main() {
    wz_cdylib_build::emit_soname("wz_capi_dissect");
}
