// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The clock a program registers, and what it tells the library about whether that clock is
//! synchronised (`docs/observation-plane.md` M1).
//!
//! A device often has a better clock than the system's, a disciplined hardware clock or a time
//! master on its bus. A program registers it as a read callback, and a timestamp is then stamped
//! with it. The rules for which source answers, and for a source that cannot say what time it is,
//! are those of [`wz_node_time::clock_registry`]; this is the C face of that registry and adds
//! none.
//!
//! The library cannot know whether the registered clock follows a reference. The program can, so
//! it reports it ([`report`]), and a build whose `clock-quality-stamping` policy is `trusted-only`
//! stamps nothing until it has said so.

use std::ffi::c_void;

use wz_node_time::clock_registry::{SourceId, GLOBAL};
use wz_session_core::epoch::{EpochSource, EpochUnavailable, SinceEpoch};

use super::Refusal;

/// What a registered clock is read through: the time since the Unix epoch, as whole seconds and
/// the nanoseconds within the second.
///
/// Returns 0 with both outputs written, or any other value when the clock cannot say what time it
/// is (not set, not yet synchronised, its bus silent). It is called from whichever thread stamps,
/// possibly several at once, and must be safe to call that way.
pub type ReadFn = unsafe extern "C" fn(context: *mut c_void, secs: *mut u64, nanos: *mut u32) -> i8;

/// The clock follows a reference, for the first time or again after a loss.
pub const SYNC_ACQUIRED: u8 = 0;
/// The reference is gone.
pub const SYNC_LOST: u8 = 1;
/// The program's bound on running without a reference has passed.
pub const HOLDOVER_EXPIRED: u8 = 2;

/// A C read callback and the context it is called with.
struct CallbackEpoch {
    read: ReadFn,
    context: *mut c_void,
}

// SAFETY: the registering program owns the callback's thread-safety and the context's lifetime;
// both are the contract `ReadFn` states and each ABI's header repeats. The context is opaque to
// the library and only ever handed back to the callback.
unsafe impl Send for CallbackEpoch {}
unsafe impl Sync for CallbackEpoch {}

impl EpochSource for CallbackEpoch {
    fn try_since_epoch(&self) -> Result<SinceEpoch, EpochUnavailable> {
        let (mut secs, mut nanos) = (0u64, 0u32);
        // SAFETY: the pointers are to locals that outlive the call; the callback is the
        // program's, under the contract above.
        let code = unsafe { (self.read)(self.context, &mut secs, &mut nanos) };
        // A callback that says it read a time but names a nanosecond past the second has not read
        // one.
        if code == 0 && nanos < 1_000_000_000 {
            Ok(SinceEpoch { secs, nanos })
        } else {
            Err(EpochUnavailable)
        }
    }
}

/// Register a clock the library reads in place of the system clock, after those already
/// registered (the first that can say what time it is answers). The handle it returns is what
/// [`unregister`] takes. [`Refusal::Full`] when the build's `CLOCK_SOURCES` are all taken.
///
/// # Safety
/// `read` must be a function that is safe to call from any thread for as long as the source is
/// registered, and `context` must stay valid for as long.
pub unsafe fn register(read: ReadFn, context: *mut c_void) -> Result<u32, Refusal> {
    GLOBAL
        .register(Box::new(CallbackEpoch { read, context }))
        .map(SourceId::into_raw)
        .map_err(|_| Refusal::Full)
}

/// Remove a clock registered earlier. [`Refusal::Invalid`] for a handle that is not registered.
///
/// After it returns the library no longer calls the callback, and the program may release the
/// context. A call already running on another thread may still be inside the callback.
pub fn unregister(handle: u32) -> Result<(), Refusal> {
    if GLOBAL.unregister(SourceId::from_raw(handle)) {
        Ok(())
    } else {
        Err(Refusal::Invalid)
    }
}

/// Tell the library whether the registered clock follows a reference: one of [`SYNC_ACQUIRED`],
/// [`SYNC_LOST`] and [`HOLDOVER_EXPIRED`]. [`Refusal::Invalid`] for another value. Reporting what
/// is already so is not an error.
pub fn report(event: u8) -> Result<(), Refusal> {
    let standing = GLOBAL.standing();
    match event {
        SYNC_ACQUIRED => {
            standing.report_sync_acquired();
        }
        SYNC_LOST => {
            standing.report_sync_lost();
        }
        HOLDOVER_EXPIRED => {
            standing.report_holdover_expired();
        }
        _ => return Err(Refusal::Invalid),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A clock the test drives through its context: `*context` is the seconds it reads, and 0 is a
    /// clock that is not set.
    unsafe extern "C" fn read_from_context(
        context: *mut c_void,
        secs: *mut u64,
        nanos: *mut u32,
    ) -> i8 {
        let at = (*(context as *const AtomicU64)).load(Ordering::Relaxed);
        if at == 0 {
            return -1;
        }
        *secs = at;
        *nanos = 5;
        0
    }

    unsafe extern "C" fn reads_a_bad_nanosecond(
        _context: *mut c_void,
        secs: *mut u64,
        nanos: *mut u32,
    ) -> i8 {
        *secs = 1;
        *nanos = 1_000_000_000;
        0
    }

    #[test]
    fn a_callback_that_reads_a_time_is_an_epoch_source() {
        let at = AtomicU64::new(123);
        let source = CallbackEpoch {
            read: read_from_context,
            context: &at as *const AtomicU64 as *mut c_void,
        };
        assert_eq!(
            source.try_since_epoch(),
            Ok(SinceEpoch {
                secs: 123,
                nanos: 5
            })
        );
        at.store(0, Ordering::Relaxed);
        assert_eq!(source.try_since_epoch(), Err(EpochUnavailable));
    }

    #[test]
    fn a_callback_naming_a_nanosecond_past_the_second_has_not_read_a_time() {
        let source = CallbackEpoch {
            read: reads_a_bad_nanosecond,
            context: std::ptr::null_mut(),
        };
        assert_eq!(source.try_since_epoch(), Err(EpochUnavailable));
    }

    #[test]
    fn an_unknown_handle_and_event_are_invalid() {
        assert_eq!(unregister(u32::MAX), Err(Refusal::Invalid));
        assert_eq!(report(99), Err(Refusal::Invalid));
    }
}
