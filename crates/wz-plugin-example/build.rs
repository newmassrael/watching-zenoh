// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2103 (open-debt item 521) — this crate's `cdylib` gets a SONAME.
//!
//! This one is `dlopen`ed rather than linked, so no consumer's `DT_NEEDED` is
//! at stake — and it is fixed anyway, on purpose. It is the EXAMPLE a plugin
//! author copies, and an example that omits the SONAME teaches the defect to
//! every plugin written after it. The reason and the platform rule live in
//! `wz_cdylib_build`.

fn main() {
    wz_cdylib_build::emit_soname("wz_plugin_example");
}
