// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// The body of both stubs: what `zenoh` re-exports that the code the macros write names. The
// two stubs differ only in whose crates `zenoh_keyexpr` and `zenoh_result` are.

/// `zenoh::Result`, the error type of a parse of a format.
pub use zenoh_result::ZResult as Result;

/// `zenoh::key_expr`, the key expression crate.
pub mod key_expr {
    pub use zenoh_keyexpr::*;
}
