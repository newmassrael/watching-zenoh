// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_time_base_*` and `wz_ext_config_time_base`: a time base the program supplies, which
//! the timers of a session opened from a config naming it run on in place of the system's
//! monotonic clock.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `time-base` capability implies `unstable-api`.
//!
//! A program that runs its sessions on a time of its own (a network simulator's, paused, or
//! faster or slower than the wall clock) hands the library a read of that time. A session opened
//! from a config given the time base times its lease, its keep-alive, its handshake and its other
//! deadlines by it, so a deadline passes when the program's time passes it, however long the wall
//! clock has run. The time base is `wz_node_time::time_base`'s, the same for either engine; this
//! file is the pico ABI's names, result codes and ownership around it.
//!
//! # Telling the library the time moved
//!
//! The cooperative engine reads the time at each step the program has it take (`zp_read`,
//! `zp_spin_once`, a pass of the read task), so a deadline the program's time has passed is acted
//! on at the next step. The tokio engine waits for its deadlines on threads of its own, and such a
//! wait ends only when the program says its time has moved (`wz_ext_time_base_advanced`). A
//! program calls it each time its time moves on, whichever engine the build has.
//!
//! # Who owns the time base
//!
//! As with a transport the program supplies: the program makes it (`wz_ext_time_base_new`) and
//! holds it, a config given it holds a reference, and so does a session opened from that config,
//! for as long as it runs. The program's `drop(context)` runs once, when the last of them goes.

use core::ffi::c_void;

use wz_node_time::time_base::{ProgramTime, TimeBaseHold};

use crate::abi::z_loaned_config_t;
use crate::config::ConfigState;
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

/// The program's read of its time: nanoseconds since an epoch of its choosing.
pub type wz_ext_time_base_now_fn = unsafe extern "C" fn(context: *mut c_void) -> u64;

/// The program's `drop(context)`, run once when the time base is gone.
pub type wz_ext_time_base_drop_fn = unsafe extern "C" fn(context: *mut c_void);

/// The calls the program supplies. `now_ns` is required; `drop` may be NULL.
#[repr(C)]
pub struct wz_ext_time_base_t {
    pub context: *mut c_void,
    pub now_ns: Option<wz_ext_time_base_now_fn>,
    pub drop: Option<wz_ext_time_base_drop_fn>,
}

/// An owned time base: the handle in its one word, null for the gravestone.
#[repr(C)]
pub struct wz_ext_owned_time_base_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned time base: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_time_base_t {
    pub(crate) handle: *mut c_void,
}

/// A moved time base (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_time_base_t {
    pub(crate) _this: wz_ext_owned_time_base_t,
}

impl wz_ext_owned_time_base_t {
    fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
        }
    }
}

/// The program's read, as the time base's. The program's own `drop(context)` runs when this
/// does, which is when the last hold of the time base goes.
struct ProgramRead {
    context: *mut c_void,
    now_ns: wz_ext_time_base_now_fn,
    drop: Option<wz_ext_time_base_drop_fn>,
}

// SAFETY: the context and the function pointers are the program's, and the header's threading
// contract is the program's promise that its read may be made from any thread of the library.
unsafe impl Send for ProgramRead {}
// SAFETY: as above; the read holds no state of its own, so a shared reference adds nothing.
unsafe impl Sync for ProgramRead {}

impl ProgramTime for ProgramRead {
    fn now_ns(&self) -> u64 {
        // SAFETY: the program's read, with its own context.
        unsafe { (self.now_ns)(self.context) }
    }
}

impl Drop for ProgramRead {
    fn drop(&mut self) {
        if let Some(drop) = self.drop {
            // SAFETY: the program's drop, once, after the last read.
            unsafe { drop(self.context) }
        }
    }
}

/// The hold behind a loan, or `None` for a null loan or a gravestone.
///
/// # Safety
/// `this_` is null or a loan of a live owned time base.
unsafe fn hold_of<'a>(this_: *const wz_ext_loaned_time_base_t) -> Option<&'a TimeBaseHold> {
    if this_.is_null() || (*this_).handle.is_null() {
        return None;
    }
    Some(&*((*this_).handle as *const TimeBaseHold))
}

/// A time base over the program's calls in `time_base`, which are copied. `this_` holds the
/// gravestone on every error.
///
/// Z_OK; Z_ERR_NULL for a NULL `this_` or `time_base`, or a NULL `now_ns`.
///
/// # Safety
/// `this_` is writable; `time_base` is null or readable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_time_base_new(
    this_: *mut wz_ext_owned_time_base_t,
    time_base: *const wz_ext_time_base_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        *this_ = wz_ext_owned_time_base_t::null_value();
        if time_base.is_null() {
            return Z_ERR_NULL;
        }
        let calls = &*time_base;
        let Some(now_ns) = calls.now_ns else {
            return Z_ERR_NULL;
        };
        let read = ProgramRead {
            context: calls.context,
            now_ns,
            drop: calls.drop,
        };
        let hold = Box::new(TimeBaseHold::new(Box::new(read)));
        *this_ = wz_ext_owned_time_base_t {
            handle: Box::into_raw(hold) as *mut c_void,
        };
        Z_OK
    })
}

/// The session opened from `config` times its deadlines by `time_base`. A second call replaces
/// the first. The config holds a reference: the program may drop its own time base after this.
///
/// Z_OK; Z_ERR_NULL for a NULL config, a NULL time base or a gravestone.
///
/// # Safety
/// `config` is null or a loaned config; `time_base` is null or a loan of a live time base.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_config_time_base(
    config: *mut z_loaned_config_t,
    time_base: *const wz_ext_loaned_time_base_t,
) -> ZResult {
    guarded(|| {
        if config.is_null() || (*config).handle.is_null() {
            return Z_ERR_NULL;
        }
        let Some(hold) = hold_of(time_base) else {
            return Z_ERR_NULL;
        };
        let state = &mut *((*config).handle as *mut ConfigState);
        state.time_base = Some(hold.clone());
        Z_OK
    })
}

/// The program's time has moved on: every wait of a session on `time_base` whose time has come by
/// the program's reading now ends.
///
/// Z_OK; Z_ERR_NULL for a NULL time base or a gravestone.
///
/// # Safety
/// `time_base` is null or a loan of a live time base.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_time_base_advanced(
    time_base: *const wz_ext_loaned_time_base_t,
) -> ZResult {
    guarded(|| {
        let Some(hold) = hold_of(time_base) else {
            return Z_ERR_NULL;
        };
        hold.advanced();
        Z_OK
    })
}

/// The loan of a time base: a cast.
///
/// # Safety
/// `this_` is null or an owned time base.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_time_base_loan(
    this_: *const wz_ext_owned_time_base_t,
) -> *const wz_ext_loaned_time_base_t {
    this_.cast::<wz_ext_loaned_time_base_t>()
}

/// The moved form of a time base, for `wz_ext_time_base_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned time base.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_time_base_move(
    this_: *mut wz_ext_owned_time_base_t,
) -> *mut wz_ext_moved_time_base_t {
    this_.cast::<wz_ext_moved_time_base_t>()
}

/// Release the program's reference and leave the gravestone. The configs and sessions that hold
/// the time base keep it; the program's `drop(context)` runs when the last of them goes. A second
/// drop, and a drop of the gravestone, do nothing.
///
/// # Safety
/// `this_` is null or a moved time base.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_time_base_drop(this_: *mut wz_ext_moved_time_base_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        let handle = (*this_)._this.handle;
        (*this_)._this = wz_ext_owned_time_base_t::null_value();
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut TimeBaseHold));
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_time_base_null(this_: *mut wz_ext_owned_time_base_t) {
    if !this_.is_null() {
        *this_ = wz_ext_owned_time_base_t::null_value();
    }
}

/// Whether the slot holds a time base.
///
/// # Safety
/// `this_` is null or an owned time base.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_time_base_check(
    this_: *const wz_ext_owned_time_base_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}

/// The clock a session of the cooperative engine runs on: the host's, or the time base the
/// program supplies. Every timer of the engine reads it (its runtime's timer queue, its sessions'
/// deadlines, its own handshake, redial and get deadlines).
#[cfg(not(feature = "engine-tokio"))]
#[derive(Clone)]
pub(crate) enum SessionClock {
    Host(crate::coop_host::Clock),
    Program(TimeBaseHold),
}

#[cfg(not(feature = "engine-tokio"))]
impl wz_capi_coop::ClockSource for SessionClock {
    fn now_us(&self) -> u64 {
        match self {
            Self::Host(clock) => wz_capi_coop::ClockSource::now_us(clock),
            Self::Program(time_base) => time_base.now_ns() / 1_000,
        }
    }
}

/// The clock of a cooperative session the config gave `time_base`, or the host's when it gave
/// none.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn session_clock(time_base: Option<TimeBaseHold>) -> SessionClock {
    match time_base {
        Some(time_base) => SessionClock::Program(time_base),
        None => SessionClock::Host(crate::coop_host::clock()),
    }
}

/// A wait that ends at the program's word that its time moved on after the mark `seen`.
#[cfg(not(feature = "engine-tokio"))]
struct MovedSince {
    time_base: TimeBaseHold,
    seen: u64,
}

#[cfg(not(feature = "engine-tokio"))]
impl wz_capi_coop::LinkReadiness for MovedSince {
    fn wait_readable(&self, timeout_ms: u32) {
        let _ = self.time_base.wait_moved(
            self.seen,
            core::time::Duration::from_millis(timeout_ms.into()),
        );
    }
}

/// The program's word, as the cooperative engine's reads wait on it.
#[cfg(not(feature = "engine-tokio"))]
struct TimeBaseMoves(TimeBaseHold);

#[cfg(not(feature = "engine-tokio"))]
impl wz_capi_coop::ClockMoves for TimeBaseMoves {
    fn moved(&self) -> std::sync::Arc<dyn wz_capi_coop::LinkReadiness> {
        std::sync::Arc::new(MovedSince {
            seen: self.0.moves(),
            time_base: self.0.clone(),
        })
    }
}

/// What tells a read of a cooperative session on `clock` that its clock moved on: the program's
/// word, for a session on a time base; none for one on the host's clock, which moves by itself.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn clock_moves(
    clock: &SessionClock,
) -> Option<std::sync::Arc<dyn wz_capi_coop::ClockMoves>> {
    match clock {
        SessionClock::Host(_) => None,
        SessionClock::Program(time_base) => {
            Some(std::sync::Arc::new(TimeBaseMoves(time_base.clone())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use crate::abi::z_owned_config_t;
    use crate::config::{z_config_default, z_config_drop, z_config_loan_mut, z_config_move};

    /// The program's time and how often its drop ran: the context the test's calls read.
    #[derive(Default)]
    struct Program {
        now_ns: AtomicU64,
        drops: AtomicUsize,
    }

    unsafe extern "C" fn read(context: *mut c_void) -> u64 {
        (*(context as *const Program)).now_ns.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn dropped(context: *mut c_void) {
        (*(context as *const Program))
            .drops
            .fetch_add(1, Ordering::SeqCst);
    }

    fn calls(program: &Program) -> wz_ext_time_base_t {
        wz_ext_time_base_t {
            context: program as *const Program as *mut c_void,
            now_ns: Some(read),
            drop: Some(dropped),
        }
    }

    fn null_time_base() -> wz_ext_owned_time_base_t {
        wz_ext_owned_time_base_t::null_value()
    }

    #[test]
    fn a_null_slot_calls_or_read_is_refused_with_the_gravestone_left() {
        let program = Program::default();
        unsafe {
            assert_eq!(
                wz_ext_time_base_new(core::ptr::null_mut(), &calls(&program)),
                Z_ERR_NULL
            );
            // A slot that holds something, so that the gravestone is seen to be written.
            let mut time_base = wz_ext_owned_time_base_t {
                handle: core::ptr::NonNull::dangling().as_ptr(),
            };
            assert_eq!(
                wz_ext_time_base_new(&mut time_base, core::ptr::null()),
                Z_ERR_NULL
            );
            assert!(!wz_ext_internal_time_base_check(&time_base));
            let no_read = wz_ext_time_base_t {
                now_ns: None,
                ..calls(&program)
            };
            assert_eq!(wz_ext_time_base_new(&mut time_base, &no_read), Z_ERR_NULL);
            assert!(!wz_ext_internal_time_base_check(&time_base));
        }
        assert_eq!(program.drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_config_and_an_advance_refuse_a_null_or_a_gravestone() {
        let gravestone = null_time_base();
        unsafe {
            let mut config: z_owned_config_t = core::mem::zeroed();
            assert_eq!(z_config_default(&mut config), Z_OK);
            assert_eq!(
                wz_ext_config_time_base(z_config_loan_mut(&mut config), core::ptr::null()),
                Z_ERR_NULL
            );
            assert_eq!(
                wz_ext_config_time_base(
                    z_config_loan_mut(&mut config),
                    wz_ext_time_base_loan(&gravestone)
                ),
                Z_ERR_NULL
            );
            assert!((*(config.handle as *const ConfigState)).time_base.is_none());
            z_config_drop(z_config_move(&mut config));
            assert_eq!(wz_ext_time_base_advanced(core::ptr::null()), Z_ERR_NULL);
            assert_eq!(
                wz_ext_time_base_advanced(wz_ext_time_base_loan(&gravestone)),
                Z_ERR_NULL
            );
        }
    }

    #[test]
    fn the_programs_drop_runs_once_when_the_last_holder_goes() {
        let program = Program::default();
        unsafe {
            let mut time_base = null_time_base();
            assert_eq!(wz_ext_time_base_new(&mut time_base, &calls(&program)), Z_OK);
            assert!(wz_ext_internal_time_base_check(&time_base));
            let mut config: z_owned_config_t = core::mem::zeroed();
            assert_eq!(z_config_default(&mut config), Z_OK);
            assert_eq!(
                wz_ext_config_time_base(
                    z_config_loan_mut(&mut config),
                    wz_ext_time_base_loan(&time_base)
                ),
                Z_OK
            );
            program.now_ns.store(42, Ordering::SeqCst);
            let held = (*(config.handle as *const ConfigState))
                .time_base
                .as_ref()
                .expect("the config holds the time base");
            assert_eq!(
                held.now_ns(),
                42,
                "the config's reference reads the program"
            );

            wz_ext_time_base_drop(wz_ext_time_base_move(&mut time_base));
            assert!(!wz_ext_internal_time_base_check(&time_base));
            assert_eq!(
                program.drops.load(Ordering::SeqCst),
                0,
                "the config still holds it"
            );
            wz_ext_time_base_drop(wz_ext_time_base_move(&mut time_base));

            z_config_drop(z_config_move(&mut config));
            assert_eq!(program.drops.load(Ordering::SeqCst), 1);
        }
    }

    /// A session that listens on a port of the loopback, opened from a config given `time_base`
    /// when there is one: it opens without a peer, so the test needs no other node.
    #[cfg(feature = "peer")]
    unsafe fn listening(
        time_base: Option<&wz_ext_owned_time_base_t>,
    ) -> crate::session::z_owned_session_t {
        use crate::config::{zp_config_insert, Z_CONFIG_LISTEN_KEY};
        let port = wz_runtime_tokio_test_support::free_port();
        let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).expect("a locator");
        let mut config: z_owned_config_t = core::mem::zeroed();
        assert_eq!(z_config_default(&mut config), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut config),
                Z_CONFIG_LISTEN_KEY,
                listen.as_ptr()
            ),
            Z_OK
        );
        if let Some(time_base) = time_base {
            assert_eq!(
                wz_ext_config_time_base(
                    z_config_loan_mut(&mut config),
                    wz_ext_time_base_loan(time_base)
                ),
                Z_OK
            );
        }
        let mut session: crate::session::z_owned_session_t = core::mem::zeroed();
        assert_eq!(
            crate::session::z_open(&mut session, z_config_move(&mut config), core::ptr::null()),
            Z_OK
        );
        session
    }

    /// The engine behind `session`, whichever the build has.
    #[cfg(feature = "peer")]
    unsafe fn engine_of(
        session: &crate::session::z_owned_session_t,
    ) -> std::sync::Arc<crate::session::Engine> {
        let handle = crate::session::session_handle(crate::session::z_session_loan(session))
            .expect("an open session");
        crate::session::engine_of(handle)
    }

    #[cfg(feature = "peer")]
    unsafe fn close(mut session: crate::session::z_owned_session_t) {
        use crate::session::{z_close, z_session_drop, z_session_loan_mut, z_session_move};
        z_close(z_session_loan_mut(&mut session), core::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }

    /// A session opened from a config given a time base runs on the program's time, whichever
    /// engine the build has: the engine's clock stands still while the wall clock runs, and moves
    /// exactly as far as the program's time does.
    #[cfg(feature = "peer")]
    #[test]
    fn a_session_opened_on_a_time_base_runs_on_the_programs_time() {
        let program = Program::default();
        program.now_ns.store(5_000_000_000, Ordering::SeqCst);
        unsafe {
            let mut time_base = null_time_base();
            assert_eq!(wz_ext_time_base_new(&mut time_base, &calls(&program)), Z_OK);
            let session = listening(Some(&time_base));
            let engine = engine_of(&session);
            let opened = engine.now_ms();
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert_eq!(
                engine.now_ms(),
                opened,
                "the wall clock moved the session's time"
            );
            program.now_ns.fetch_add(1_500_000_000, Ordering::SeqCst);
            assert_eq!(
                wz_ext_time_base_advanced(wz_ext_time_base_loan(&time_base)),
                Z_OK
            );
            assert_eq!(engine.now_ms(), opened + 1_500);
            drop(engine);
            close(session);
            wz_ext_time_base_drop(wz_ext_time_base_move(&mut time_base));
        }
    }

    /// The CONTROL: a session given no time base runs on the system's clock, which the wall clock
    /// moves.
    #[cfg(feature = "peer")]
    #[test]
    fn a_session_given_no_time_base_runs_on_the_systems_clock() {
        unsafe {
            let session = listening(None);
            let engine = engine_of(&session);
            let opened = engine.now_ms();
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert!(
                engine.now_ms() >= opened + 100,
                "the system's clock did not move with the wall clock"
            );
            drop(engine);
            close(session);
        }
    }

    /// The cooperative engine's clock reads the program's time, in microseconds, with a time base,
    /// and the host's without one.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    fn the_cooperative_sessions_clock_is_the_programs_when_it_has_a_time_base() {
        use wz_capi_coop::ClockSource;
        let program = Program::default();
        program.now_ns.store(7_000_000, Ordering::SeqCst);
        let program_read = ProgramRead {
            context: &program as *const Program as *mut c_void,
            now_ns: read,
            drop: None,
        };
        let clock = session_clock(Some(TimeBaseHold::new(Box::new(program_read))));
        assert_eq!(clock.now_us(), 7_000);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(clock.now_us(), 7_000, "the wall clock moved it");
        assert!(
            clock_moves(&clock).is_some(),
            "a session on a time base waits for the program's word"
        );

        let host = session_clock(None);
        assert!(
            clock_moves(&host).is_none(),
            "the host's clock moves by itself"
        );
        let before = host.now_us();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(
            host.now_us() >= before + 20_000,
            "CONTROL: without a time base the host's clock runs"
        );
    }
}
