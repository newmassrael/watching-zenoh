// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The platform helpers upstream's examples call to stay alive.
//!
//! `z_sleep_s` is not zenoh — it is a portability shim zenoh-c exports so an
//! example does not have to `#include <unistd.h>` per platform. It is here
//! because a drop-in that does not export it does not link `z_sub.c`, which is
//! the only reason it is in this slice.

use crate::ffi::guarded;
use crate::result::{ZResult, Z_OK};

/// Sleep for `time` seconds (zenoh-c `z_sleep_s`).
///
/// Upstream returns a `z_result_t`; on a std host the sleep does not fail, so
/// this is always `Z_OK`.
///
/// # Safety
/// No pointers are dereferenced. `unsafe` for signature parity with the rest of
/// the exported surface would be noise, so this one is safe — the ABI is
/// unaffected either way.
#[no_mangle]
pub extern "C" fn z_sleep_s(time: usize) -> ZResult {
    guarded(|| {
        std::thread::sleep(std::time::Duration::from_secs(time as u64));
        Z_OK
    })
}
