// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2103 (open-debt item 521) — this crate's `cdylib` gets a SONAME.
//!
//! THE FIFTH, and the one the downstream report did not contain: it named four
//! cdylibs and this workspace emits five. That is the whole argument for
//! `scripts/lib/cdylib_soname_gate.py` deriving its population from cargo
//! metadata instead of a list — the list was already wrong on the day it was
//! written. Like `wz-plugin-example` this one is `dlopen`ed rather than linked,
//! and is fixed for the same reason: it is what a volume author copies. The
//! reason and the platform rule live in `wz_cdylib_build`.

fn main() {
    wz_cdylib_build::emit_soname("wz_volume_example");
}
