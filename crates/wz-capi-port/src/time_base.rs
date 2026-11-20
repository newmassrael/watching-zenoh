// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A time base the program supplies, made from the calls a C ABI's door is handed: the read of
//! the program's time and the program's drop of its context. Both C ABIs make theirs here (the
//! pico ABI's `wz_ext_time_base_new`, the zenoh-c ABI's `wz_capi_c_time_base_new`) and name only
//! their types and result codes; what a time base is and how a session runs on it are
//! `wz_node_time::time_base`'s.

use std::ffi::c_void;

use wz_node_time::time_base::{ProgramTime, TimeBaseHold};

/// The program's read of its time: nanoseconds since an epoch of its choosing.
pub type NowFn = unsafe extern "C" fn(context: *mut c_void) -> u64;

/// The program's `drop(context)`, run once when the time base is gone.
pub type DropFn = unsafe extern "C" fn(context: *mut c_void);

/// The program's calls, as the time base's read. The program's own `drop(context)` runs when
/// this does, which is when the last hold of the time base goes.
struct ProgramCalls {
    context: *mut c_void,
    now_ns: NowFn,
    drop: Option<DropFn>,
}

// SAFETY: the context and the function pointers are the program's, and each ABI header's threading
// contract is the program's promise that its read may be made from any thread of the library.
unsafe impl Send for ProgramCalls {}
// SAFETY: as above; the calls hold no state of their own, so a shared reference adds nothing.
unsafe impl Sync for ProgramCalls {}

impl ProgramTime for ProgramCalls {
    fn now_ns(&self) -> u64 {
        // SAFETY: the program's read, with its own context.
        unsafe { (self.now_ns)(self.context) }
    }
}

impl Drop for ProgramCalls {
    fn drop(&mut self) {
        if let Some(drop) = self.drop {
            // SAFETY: the program's drop, once, after the last read.
            unsafe { drop(self.context) }
        }
    }
}

/// A time base over the program's `now_ns` and `drop` with `context`, and its first hold.
///
/// # Safety
/// `now_ns` must be safe to call with `context` from any thread for as long as a hold of the time
/// base remains, and `drop`, when given, once with it after the last read.
pub unsafe fn over_calls(
    context: *mut c_void,
    now_ns: NowFn,
    drop: Option<DropFn>,
) -> TimeBaseHold {
    TimeBaseHold::new(Box::new(ProgramCalls {
        context,
        now_ns,
        drop,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// The program's time and how often its drop ran.
    #[derive(Default)]
    struct Program {
        now_ns: AtomicU64,
        drops: AtomicUsize,
    }

    unsafe extern "C" fn read(context: *mut c_void) -> u64 {
        // SAFETY: the test's own context, alive for the test.
        unsafe { (*(context as *const Program)).now_ns.load(Ordering::SeqCst) }
    }

    unsafe extern "C" fn dropped(context: *mut c_void) {
        // SAFETY: as above.
        unsafe {
            (*(context as *const Program))
                .drops
                .fetch_add(1, Ordering::SeqCst)
        };
    }

    #[test]
    fn the_programs_read_is_the_time_and_its_drop_runs_once_with_the_last_hold() {
        let program = Program::default();
        program.now_ns.store(42, Ordering::SeqCst);
        let context = &program as *const Program as *mut c_void;
        // SAFETY: `program` outlives every hold below.
        let hold = unsafe { over_calls(context, read, Some(dropped)) };
        assert_eq!(hold.now_ns(), 42);
        let other = hold.clone();
        drop(hold);
        assert_eq!(program.drops.load(Ordering::SeqCst), 0, "a hold remains");
        drop(other);
        assert_eq!(program.drops.load(Ordering::SeqCst), 1);
    }
}
