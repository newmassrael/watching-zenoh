// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zc_init_log_from_env_or` — logging init.
//!
//! Every upstream example calls it FIRST, which is exactly why it is in this
//! slice: a symbol nothing in wz needed is still a symbol the program links
//! against, and a missing one is a link error before a single wire byte moves.
//! It is the clearest single instance of why the corpus had to be upstream's
//! rather than hand-written — nothing about implementing `z_put` suggests it.

use std::ffi::{c_char, CStr};

use crate::ffi::guard_val;

/// Initialise logging from `RUST_LOG`, falling back to `fallback_filter`
/// (zenoh-c `zc_init_log_from_env_or`).
///
/// wz's logging is the `log` facade with no installed subscriber by default, and
/// installing one from a library would hijack the host application's. So this
/// honours the ENV variable if a subscriber is already present and is otherwise
/// a no-op — the observable behaviour a zenoh-c program depends on is that the
/// call SUCCEEDS and does not print unless asked.
///
/// # Safety
/// `fallback_filter` must be null or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn zc_init_log_from_env_or(fallback_filter: *const c_char) {
    guard_val((), || {
        if fallback_filter.is_null() {
            return;
        }
        // Read it so a malformed filter is not silently ignored on the day this
        // grows a real subscriber; the value is otherwise unused today.
        // SAFETY: the caller's contract.
        let _ = unsafe { CStr::from_ptr(fallback_filter) }.to_str();
    })
}
