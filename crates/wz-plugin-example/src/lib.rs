// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A real loadable plugin, written the way a third party would write one.
//!
//! Its whole dependency list is `wz-plugin-abi`. That is the demonstration: the
//! ABI crate is sufficient to author a plugin, with no session, no runtime and
//! no wz internals behind it. If this file ever needs another wz crate to
//! compile, the ABI has leaked and the leak is the bug.
//!
//! ## What it does, and why it does anything at all
//!
//! `start` records that it ran, in a process-global counter the plugin owns, and
//! `stop` records the same. A plugin that only returned `OK` would let a loader
//! that never called through the vtable still pass every test — the counters are
//! what make "the host called into the `.so`" observable rather than assumed,
//! and the example exposes them through an extra exported symbol so a test can
//! read them WITHOUT going through the vtable it is trying to check.
//!
//! `start` also honours its `config` argument: a JSON object containing
//! `"refuse": true` makes it return [`wz_plugin_abi::ERR`]. That is not
//! decoration either — a plugin that cannot refuse gives the host's
//! start-failure path no way to be exercised, and an unexercised error path is
//! the one that is wrong when it finally runs.

use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicU32, Ordering};

use wz_plugin_abi::{PluginEntry, PluginVTable, ERR, OK};

/// Times `start` has returned [`OK`]. Read via [`wz_plugin_example_starts`].
static STARTS: AtomicU32 = AtomicU32::new(0);
/// Times `stop` has been called.
static STOPS: AtomicU32 = AtomicU32::new(0);

const ID: &[u8] = b"wz_example\0";
const NAME: &[u8] = b"wz_example\0";
const VERSION: &[u8] = b"0.1.0\0";

unsafe extern "C" fn id() -> *const c_char {
    ID.as_ptr().cast()
}

unsafe extern "C" fn name() -> *const c_char {
    NAME.as_ptr().cast()
}

unsafe extern "C" fn version() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// Activate.
///
/// # Safety
/// `config` is null or a NUL-terminated C string owned by the caller for the
/// duration of the call.
unsafe extern "C" fn start(config: *const c_char) -> c_int {
    // The refusal path, driven by the host's own config rather than by a build
    // flag, so ONE loaded `.so` can exercise both arms of the loader's
    // start-failure handling in one test process.
    if !config.is_null() {
        let mut len = 0usize;
        // SAFETY: the caller's contract is a NUL-terminated string; walk to it.
        while unsafe { *config.add(len) } != 0 {
            len += 1;
            if len > 4096 {
                // A config this long is not one we wrote; refuse rather than
                // walk further into memory we were handed on trust.
                return ERR;
            }
        }
        // SAFETY: `len` bytes before the NUL, from a pointer valid for the call.
        let bytes = unsafe { core::slice::from_raw_parts(config.cast::<u8>(), len) };
        if let Ok(text) = core::str::from_utf8(bytes) {
            if text.contains("\"refuse\"") && text.contains("true") {
                return ERR;
            }
        }
    }
    STARTS.fetch_add(1, Ordering::SeqCst);
    OK
}

unsafe extern "C" fn stop() -> c_int {
    STOPS.fetch_add(1, Ordering::SeqCst);
    OK
}

static VTABLE: PluginVTable = PluginVTable {
    id,
    name,
    version,
    start,
    stop,
};

static ENTRY: PluginEntry = PluginEntry::new(&VTABLE as *const PluginVTable);

/// The one symbol the host resolves. See `wz_plugin_abi::ENTRY_SYMBOL`.
///
/// # Safety
/// Returns a pointer to a `static`, so it is valid for as long as this library
/// stays loaded — the lifetime the ABI contract requires.
#[no_mangle]
pub unsafe extern "C" fn wz_plugin_entry() -> *const PluginEntry {
    &ENTRY as *const PluginEntry
}

/// Out-of-band witness: how many times `start` returned OK.
///
/// Deliberately NOT part of the vtable. A test that read this through the vtable
/// would be asking the mechanism under test to vouch for itself; resolving a
/// separate symbol means the count is evidence about the vtable rather than
/// evidence from it.
///
/// # Safety
/// Reads a `static` atomic; safe to call from any thread at any time.
#[no_mangle]
pub unsafe extern "C" fn wz_plugin_example_starts() -> u32 {
    STARTS.load(Ordering::SeqCst)
}

/// Out-of-band witness: how many times `stop` was called.
///
/// # Safety
/// As [`wz_plugin_example_starts`].
#[no_mangle]
pub unsafe extern "C" fn wz_plugin_example_stops() -> u32 {
    STOPS.load(Ordering::SeqCst)
}
