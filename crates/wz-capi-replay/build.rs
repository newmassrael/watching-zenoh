// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 2441 (open-debt item 693) — this crate's `cdylib` gets a SONAME.
//!
//! Same reason as `wz-capi-dissect`'s: without one, a consumer linking
//! `libwz_capi_replay.so` BY PATH records that absolute build-time path in its
//! own `DT_NEEDED` and can no longer ship what it built. The reason and the
//! platform rule live in `wz_cdylib_build`.

fn main() {
    wz_cdylib_build::emit_soname("wz_capi_replay");
}
