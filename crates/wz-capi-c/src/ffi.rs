// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The panic guard every exported symbol runs inside.
//!
//! A Rust panic unwinding across an `extern "C"` boundary aborts the process
//! (and, before Rust 1.71, was undefined). A C program that passed a bad
//! argument should get an error CODE, not a dead process, so every export
//! catches and maps.
//!
//! The fallback is [`Z_EINVAL`](crate::result::Z_EINVAL) rather than a dedicated
//! "we panicked" code, because zenoh-c has no such code and inventing one would
//! put a value in a C program's error handling that upstream's vocabulary does
//! not contain.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::result::{ZResult, Z_EINVAL};

/// Run `body`, mapping a panic onto [`Z_EINVAL`].
pub(crate) fn guarded<F>(body: F) -> ZResult
where
    F: FnOnce() -> ZResult,
{
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(Z_EINVAL)
}

/// Run `body`, returning `fallback` if it panics — for exports whose return type
/// is not a status code.
pub(crate) fn guard_val<F, T>(fallback: T, body: F) -> T
where
    F: FnOnce() -> T,
{
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fallback)
}
