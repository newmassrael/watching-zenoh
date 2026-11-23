// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y530 — the SCOUTING plane: `z_scout` and the `z_owned_hello_t` /
//! `z_owned_string_array_t` families it hands a C callback.
//!
//! The measurement that selected it: of the ten upstream examples that did not
//! link, `z_scout` was the only one whose whole missing set was EIGHT symbols
//! with no shared mechanism owed to any other program — the channel bundle
//! needs a refcounted handler collection (six programs behind one ~30-symbol
//! mechanism), advanced pub/sub needs a cache. This plane is self-contained and
//! its counterparty is a REAL zenohd, which answers a multicast Scout with a
//! Hello carrying its own zid, role and listeners — so every field the callback
//! prints is chosen by a foreign process.
//!
//! ## What is wz's and what is upstream's
//!
//! Nothing here re-implements scouting. `wz_session_core::scouting_host`
//! owns the Scout emit / Hello decode window (`§scouting-active`), the engine
//! the build runs pumps it over its own sockets (`window`), and this module is
//! the C-ABI adapter over them: read the config, run the window for the
//! caller's budget, and project each scouted hello into the borrowed pico
//! shape.
//!
//! ## Sizes are measured, not guessed
//!
//! A C program stack-allocates `z_owned_closure_hello_t` (24 B) and, in the
//! ownership family, `z_owned_hello_t` (56 B) / `z_owned_string_array_t`
//! (32 B). Those are pico's numbers, measured against the pinned headers, and
//! `hello_and_string_array_abi` pins them here. The CONTENTS are wz's: pico's
//! header never dereferences these structs' fields (every read goes through an
//! exported accessor), so a handle in slot 0 with zero padding to the pico size
//! is a faithful representation.
//!
//! ## The cycle divergence, retired — and the claim it rested on, corrected
//!
//! This module used to carry a named divergence: "pico's `z_scout` calls the
//! user closure the instant a Hello decodes", while wz drove discovery in
//! CYCLES and emitted each cycle's new hellos when that cycle returned, so a
//! callback could lag the wire by up to one cycle.
//!
//! The cycling is gone — it existed only because the scouting statechart left
//! `AwaitingHello` on the FIRST Hello, so one window could report one peer, and
//! the FSM now carries pico's `exit_on_first == false` arm
//! (`src/session/scout.c:121-123`). One Scout goes out for the caller's whole
//! budget instead of one per cycle, and the zid set that suppressed the
//! duplicate answers the re-scouting provoked is gone with it.
//!
//! The premise was ALSO wrong, and reading `_z_scout` to close the divergence
//! is what found it: upstream does NOT call the closure from inside its
//! scouting loop. `_z_scout_inner` runs the whole window and RETURNS a list,
//! which `_z_scout` then drains (`src/net/primitives.c:81-90`) — after the
//! window, and newest-first, because the list is built by prepending. So the
//! shape that looked like a wz concession is upstream's own, and wz matches it
//! deliberately in `wz_session_core::scouting_host::deliver_in_upstream_order` rather
//! than firing per-Hello, which would have been a divergence in wz's favour.
//! The order is the session's too, so both engines hand the peers over the same way.

use core::ffi::c_void;
use core::net::IpAddr;

use crate::prelude::*;

use wz_session_core::caps;
use wz_session_core::scouting_host::{
    parse_multicast_locator, HelloFacts, MULTICAST_LOCATOR_DEFAULT, SCOUTING_TIMEOUT_DEFAULT_MS,
    SCOUTING_WHAT_DEFAULT,
};

use wz_session_core::limits::SessionLimits;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::session_zid::SessionZid;

use crate::abi::z_loaned_string_t;
use crate::config::{ConfigState, Z_CONFIG_SESSION_ZID_KEY};
use crate::config_policy::PolicyStatements;
use crate::pubsub::z_closure_drop_callback_t;
use crate::result::ZResult;
use crate::string_array::{z_loaned_string_array_t, z_owned_string_array_t, StringArrayState};
use crate::whatami::z_whatami_t;
use crate::zid::z_id_t;

/// pico `Z_CONFIG_MULTICAST_LOCATOR_KEY` (config.h.in:132) — the scouting group
/// locator (`udp/224.0.0.224:7446` by default).
pub const Z_CONFIG_MULTICAST_LOCATOR_KEY: u8 = 0x46;
/// pico `Z_CONFIG_SCOUTING_TIMEOUT_KEY` (config.h.in:140) — the scout budget in
/// milliseconds, as a decimal string.
pub const Z_CONFIG_SCOUTING_TIMEOUT_KEY: u8 = 0x47;
/// pico `Z_CONFIG_SCOUTING_WHAT_KEY` (config.h.in:148) — the `z_what_t` bitmask,
/// as a decimal string.
pub const Z_CONFIG_SCOUTING_WHAT_KEY: u8 = 0x48;
// The defaults pico's config carries (`Z_CONFIG_MULTICAST_LOCATOR_DEFAULT`,
// `Z_CONFIG_SCOUTING_TIMEOUT_DEFAULT`, `Z_CONFIG_SCOUTING_WHAT_DEFAULT`), the locator grammar and the
// window itself are the session's (`wz_session_core::scouting_host`): both C ABIs and both engines
// read one set of them. What differs per engine is the host that pumps the window, which is the
// `window` module below.

/// The scouting window of the engine this build runs its sessions on, by the same rule `z_open`
/// picks the engine with: a build has one engine, the tokio engine or the cooperative one. A scout
/// needs no session, so the window is a plane beside the engine and not one of its methods; each
/// engine's is the host that pumps the session's window rules over its sockets.
///
/// Each window is handed the two snapshots of the scout's config. The tokio engine opens its
/// sockets under its policies; the cooperative engine's sockets read no policy of it, and its
/// windows read each datagram into a buffer of the multicast batch its limits hold
/// (`PICO_MULTICAST_BATCH_BYTES`), as zenoh-pico reads a scout.
mod window {
    use core::net::IpAddr;

    use wz_session_core::limits::SessionLimits;
    use wz_session_core::policy::SessionPolicy;
    #[cfg(not(feature = "engine-tokio"))]
    use wz_session_core::scouting_host::HelloRow;
    use wz_session_core::scouting_host::ScoutedHello;
    use wz_session_core::session_zid::SessionZid;

    use crate::config::ConfigState;
    use crate::result::ZResult;
    #[cfg(not(feature = "engine-tokio"))]
    use crate::result::WZ_EXT_ERR_SCOUT_REENTERED;

    /// The process's one table of a cooperative window's Hellos, and the buffer the window reads
    /// each datagram into: in the library's static memory, reserved when it is built, never on a
    /// stack and never on the heap. A window holds both for its run and its delivery. A window
    /// that finds them held by another thread's window waits for them, at most its own budget, on
    /// a condition variable the holder signals when it lets go; one that finds them held by its
    /// own thread, a scout asked from inside a scout's callback, is refused at once.
    #[cfg(not(feature = "engine-tokio"))]
    pub(in crate::scout) mod table {
        use core::cell::UnsafeCell;
        use core::mem::MaybeUninit;

        use wz_capi_port::os;
        use wz_capi_port::sync::Lock;
        use wz_session_core::caps;
        use wz_session_core::limits::SessionLimits;
        use wz_session_core::scouting_host::HelloTable;

        struct Region(UnsafeCell<HelloTable>);

        // SAFETY: the table is reached only by the one holder of the claim, through it.
        unsafe impl Sync for Region {}

        static TABLE: Region = Region(UnsafeCell::new(HelloTable::new()));

        /// The buffer a window reads each datagram into: the build's multicast batch, which
        /// zenoh-pico reads a scout into, and of which a window uses its session limits' value.
        struct Buffer(UnsafeCell<[u8; caps::PICO_MULTICAST_BATCH_BYTES]>);

        // SAFETY: the buffer is reached only by the one holder of the claim, through it.
        unsafe impl Sync for Buffer {}

        static BUFFER: Buffer = Buffer(UnsafeCell::new([0; caps::PICO_MULTICAST_BATCH_BYTES]));

        /// Which thread holds the table, by its word, and the condition its waiters sleep on.
        struct Holder {
            thread: os::Mutex<Option<usize>>,
            freed: os::Condvar,
        }

        /// Whether the holder is made yet.
        enum Made {
            No,
            Making,
            Yes,
        }

        /// The holder's place in static memory: the kernel's mutex and condition variable are made
        /// at run time, so the first window that asks makes them, once.
        struct HolderPlace {
            made: Lock<Made>,
            place: UnsafeCell<MaybeUninit<Holder>>,
        }

        // SAFETY: the place is written once, by the thread that moved `made` to `Making`, and read
        // only once `made` reads `Yes`; the holder's own fields are a mutex and a condition
        // variable.
        unsafe impl Sync for HolderPlace {}

        static HOLDER: HolderPlace = HolderPlace {
            made: Lock::new(Made::No),
            place: UnsafeCell::new(MaybeUninit::uninit()),
        };

        fn holder() -> &'static Holder {
            loop {
                let made = HOLDER.made.with(|made| match made {
                    Made::No => {
                        *made = Made::Making;
                        None
                    }
                    Made::Making => Some(false),
                    Made::Yes => Some(true),
                });
                match made {
                    None => {
                        // SAFETY: this thread alone moved `made` to `Making`, so it alone writes.
                        unsafe {
                            (*HOLDER.place.get()).write(Holder {
                                thread: os::Mutex::new(None),
                                freed: os::Condvar::new(),
                            });
                        }
                        HOLDER.made.with(|made| *made = Made::Yes);
                    }
                    // Another thread makes the two kernel objects, once in the process's life.
                    Some(false) => os::sleep_ms(1),
                    // SAFETY: `Yes` is set only once the place is written, and it is never
                    // written again.
                    Some(true) => return unsafe { (*HOLDER.place.get()).assume_init_ref() },
                }
            }
        }

        /// Why a window has no table.
        #[derive(Debug, PartialEq, Eq)]
        pub(in crate::scout) enum Unclaimed {
            /// The calling thread's own window holds it: a scout asked from a scout's callback.
            Reentered,
            /// Another thread's window held it for the whole of the caller's budget.
            Expired,
        }

        /// The table, held by one window at a time and given back when the claim is dropped.
        pub(in crate::scout) struct Claim(());

        impl Claim {
            /// The table, waiting while another thread's window holds it, for at most `budget_ms`
            /// as `now_ms` reads the time: the claim, and what is left of the budget.
            pub(in crate::scout) fn within(
                budget_ms: u64,
                now_ms: impl Fn() -> u64,
            ) -> Result<(Self, u64), Unclaimed> {
                let me = os::current_word();
                let holder = holder();
                let start = now_ms();
                let mut thread = holder.thread.lock();
                loop {
                    match *thread {
                        None => {
                            *thread = Some(me);
                            let waited = now_ms().saturating_sub(start);
                            return Ok((Self(()), budget_ms.saturating_sub(waited)));
                        }
                        Some(owner) if owner == me => return Err(Unclaimed::Reentered),
                        Some(_) => {}
                    }
                    let waited = now_ms().saturating_sub(start);
                    if waited >= budget_ms {
                        return Err(Unclaimed::Expired);
                    }
                    thread = holder.freed.wait_timeout_ms(thread, budget_ms - waited).0;
                }
            }

            /// The table and the read buffer the claim holds, the buffer as long as the multicast
            /// batch `limits` state, at most the build's.
            pub(in crate::scout) fn parts(
                &mut self,
                limits: &SessionLimits,
            ) -> (&mut HelloTable, &mut [u8]) {
                // SAFETY: one claim exists at a time, and it lends the table and the buffer through
                // `&mut self`.
                let (table, buffer) = unsafe { (&mut *TABLE.0.get(), &mut *BUFFER.0.get()) };
                let room = limits.pico_multicast_batch_bytes().min(buffer.len());
                (table, &mut buffer[..room])
            }
        }

        impl Drop for Claim {
            fn drop(&mut self) {
                let holder = holder();
                *holder.thread.lock() = None;
                holder.freed.notify_all();
            }
        }
    }

    /// The table for a window of `budget_ms` on `clock`, and what is left of the budget once it
    /// is held; `None` when another thread's window held it for the whole budget, which is a window
    /// nobody answered, and `WZ_EXT_ERR_SCOUT_REENTERED` for a scout asked from a scout's callback.
    #[cfg(not(feature = "engine-tokio"))]
    fn hold_table(clock: &Clock, budget_ms: u64) -> Result<Option<(table::Claim, u64)>, ZResult> {
        use wz_capi_coop::ClockSource;
        match table::Claim::within(budget_ms, || clock.now_us() / 1000) {
            Ok(held) => Ok(Some(held)),
            Err(table::Unclaimed::Expired) => Ok(None),
            Err(table::Unclaimed::Reentered) => Err(WZ_EXT_ERR_SCOUT_REENTERED),
        }
    }

    /// The clock a window is timed by: the system's, or the time base the scout's config names
    /// (`time-base`), which a window then runs on as a session opened from that config does.
    #[cfg(feature = "engine-tokio")]
    pub(super) type Clock = wz_capi_core::runtime::runtime_impl::TokioTime;
    /// See the tokio engine's twin.
    #[cfg(all(not(feature = "engine-tokio"), feature = "time-base"))]
    pub(super) type Clock = crate::time_base::SessionClock;
    /// See the tokio engine's twin.
    #[cfg(all(not(feature = "engine-tokio"), not(feature = "time-base")))]
    pub(super) type Clock = crate::coop_host::Clock;

    /// The clock of a window `cfg` scouts with. A clock made over a time base reads it only while
    /// `cfg`, which holds it, lives: the caller keeps `cfg` for the window.
    #[cfg(all(feature = "engine-tokio", feature = "time-base"))]
    pub(super) fn clock_of(cfg: Option<&ConfigState>) -> Clock {
        match cfg.and_then(|cfg| cfg.time_base.as_ref()) {
            Some(time_base) => Clock::on_time_base(time_base.time()),
            None => Clock::new(),
        }
    }

    /// See the twin of the build with a time base.
    #[cfg(all(feature = "engine-tokio", not(feature = "time-base")))]
    pub(super) fn clock_of(_cfg: Option<&ConfigState>) -> Clock {
        Clock::new()
    }

    /// See the tokio engine's twin.
    #[cfg(all(not(feature = "engine-tokio"), feature = "time-base"))]
    pub(super) fn clock_of(cfg: Option<&ConfigState>) -> Clock {
        crate::time_base::session_clock(cfg.and_then(|cfg| cfg.time_base.clone()))
    }

    /// See the tokio engine's twin.
    #[cfg(all(not(feature = "engine-tokio"), not(feature = "time-base")))]
    pub(super) fn clock_of(_cfg: Option<&ConfigState>) -> Clock {
        crate::coop_host::clock()
    }

    /// Scout `group:port` for `budget_ms` of `clock`, handing each peer that answered to
    /// `on_hello` after the window, last responder first; the number delivered, or the code of a
    /// window that could not be run.
    #[cfg(feature = "engine-tokio")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run(
        clock: &Clock,
        group: IpAddr,
        port: u16,
        what: u8,
        zid: Option<SessionZid>,
        budget_ms: u64,
        policy: &SessionPolicy,
        _limits: &SessionLimits,
        on_hello: impl FnMut(&ScoutedHello),
    ) -> Result<usize, ZResult> {
        Ok(wz_capi_core::scouting::run_scout(
            *clock, group, port, what, zid, budget_ms, policy, on_hello,
        ))
    }

    /// Scout and answer the first node that replies, or `None` when none does in the window.
    #[cfg(feature = "engine-tokio")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn first(
        clock: &Clock,
        group: IpAddr,
        port: u16,
        what: u8,
        zid: Option<SessionZid>,
        budget_ms: u64,
        policy: &SessionPolicy,
        _limits: &SessionLimits,
    ) -> Result<Option<ScoutedHello>, ZResult> {
        Ok(wz_capi_core::scouting::scout_first(
            *clock, group, port, what, zid, budget_ms, policy,
        ))
    }

    // The cooperative engine on a host with `scout`: a socket for each interface.
    #[cfg(all(not(feature = "engine-tokio"), feature = "scout"))]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run(
        clock: &Clock,
        group: IpAddr,
        port: u16,
        what: u8,
        zid: Option<SessionZid>,
        budget_ms: u64,
        _policy: &SessionPolicy,
        limits: &SessionLimits,
        on_hello: impl FnMut(&HelloRow),
    ) -> Result<usize, ZResult> {
        let Some((mut claim, budget_ms)) = hold_table(clock, budget_ms)? else {
            return Ok(0);
        };
        let (table, buffer) = claim.parts(limits);
        let delivered = wz_capi_coop::scout::run_scout::<crate::coop_host::Multicast, _>(
            clock, group, port, what, zid, budget_ms, table, buffer, on_hello,
        );
        Ok(delivered)
    }

    #[cfg(all(not(feature = "engine-tokio"), feature = "scout"))]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn first(
        clock: &Clock,
        group: IpAddr,
        port: u16,
        what: u8,
        zid: Option<SessionZid>,
        budget_ms: u64,
        _policy: &SessionPolicy,
        limits: &SessionLimits,
    ) -> Result<Option<ScoutedHello>, ZResult> {
        let Some((mut claim, budget_ms)) = hold_table(clock, budget_ms)? else {
            return Ok(None);
        };
        let (table, buffer) = claim.parts(limits);
        let first = wz_capi_coop::scout::scout_first::<crate::coop_host::Multicast, _>(
            clock, group, port, what, zid, budget_ms, table, buffer,
        );
        Ok(first)
    }

    // The cooperative engine with `scout-mcu` alone: one datagram socket of the stack its links
    // run on (`crate::coop_host`), as zenoh-pico scouts where it has no interface iterator.
    #[cfg(all(not(feature = "engine-tokio"), not(feature = "scout")))]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run(
        clock: &Clock,
        group: IpAddr,
        port: u16,
        what: u8,
        zid: Option<SessionZid>,
        budget_ms: u64,
        _policy: &SessionPolicy,
        limits: &SessionLimits,
        on_hello: impl FnMut(&HelloRow),
    ) -> Result<usize, ZResult> {
        let Some((mut claim, budget_ms)) = hold_table(clock, budget_ms)? else {
            return Ok(0);
        };
        let (table, buffer) = claim.parts(limits);
        Ok(crate::coop_host::run_scout(
            clock, group, port, what, zid, budget_ms, table, buffer, on_hello,
        ))
    }

    #[cfg(all(not(feature = "engine-tokio"), not(feature = "scout")))]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn first(
        clock: &Clock,
        group: IpAddr,
        port: u16,
        what: u8,
        zid: Option<SessionZid>,
        budget_ms: u64,
        _policy: &SessionPolicy,
        limits: &SessionLimits,
    ) -> Result<Option<ScoutedHello>, ZResult> {
        let Some((mut claim, budget_ms)) = hold_table(clock, budget_ms)? else {
            return Ok(None);
        };
        let (table, buffer) = claim.parts(limits);
        Ok(crate::coop_host::scout_first(
            clock, group, port, what, zid, budget_ms, table, buffer,
        ))
    }
}

// ---------------------------------------------------------------------------
// z_owned_hello_t
// ---------------------------------------------------------------------------

/// The payload behind a hello handle: one decoded `Hello`, plus the
/// locator array it lends out.
///
/// `locators_loan` is a PRE-BUILT loaned handle rather than something
/// `zp_hello_locators` synthesises per call, because that function returns a
/// POINTER and a stack temporary would dangle the moment it returned. This is
/// the same cached-self-view shape `StringState` uses for `z_string_loan`.
pub(crate) struct HelloState {
    zid: z_id_t,
    whatami: z_whatami_t,
    /// The locators an owned hello keeps (`z_hello_clone`), the target of `locators_loan`'s
    /// handle, boxed so its address is stable when this state moves; none for the hello a scout
    /// lends its callback, whose array lends the scouted Hello's own strings.
    _owned: Option<Box<StringArrayState>>,
    locators_loan: z_loaned_string_array_t,
}

impl HelloState {
    /// A hello that owns copies of `locators`.
    fn new(zid: z_id_t, whatami: z_whatami_t, locators: Vec<String>) -> Box<Self> {
        let locators = StringArrayState::new(locators);
        let locators_loan = loan_of(&locators);
        Box::new(Self {
            zid,
            whatami,
            _owned: Some(locators),
            locators_loan,
        })
    }

    /// A hello over `locators`, an array its caller keeps for as long as it lends the hello.
    fn lent(zid: z_id_t, whatami: z_whatami_t, locators: &StringArrayState) -> Self {
        Self {
            zid,
            whatami,
            _owned: None,
            locators_loan: loan_of(locators),
        }
    }

    /// The array the hello lends its locators in.
    fn locators(&self) -> &StringArrayState {
        // SAFETY: the loan's handle is the array the hello was made over: its own box, or the
        // array the caller of `Self::lent` keeps for as long as it lends the hello.
        unsafe { &*(self.locators_loan.handle as *const StringArrayState) }
    }
}

/// The loaned handle of `locators`.
fn loan_of(locators: &StringArrayState) -> z_loaned_string_array_t {
    z_loaned_string_array_t {
        handle: locators as *const StringArrayState as *mut c_void,
        _pad: [core::ptr::null_mut(); 3],
    }
}

/// Hand `on_hello` the scouted `hello` as pico's callback reads it, its locators lent from the
/// Hello's own strings (the window's row, or the host's Hello), so a delivery copies none of them.
/// A Hello with more locators than a table of views holds (`MAX_ADMIN_LOCATORS`) is handed through
/// an array of its own copies.
fn lend_hello(hello: &impl HelloFacts, on_hello: &mut impl FnMut(&mut HelloState)) {
    let whatami = hello.whatami().map_or(0, |w| u32::from(w.to_api()));
    let zid = z_id_t::from_wire(hello.zid());
    let count = hello.locator_count();
    if count > caps::MAX_ADMIN_LOCATORS {
        let copies = (0..count)
            .filter_map(|k| hello.locator(k))
            .map(String::from)
            .collect();
        on_hello(&mut HelloState::new(zid, whatami, copies));
        return;
    }
    let views: [z_loaned_string_t; caps::MAX_ADMIN_LOCATORS] =
        core::array::from_fn(|k| match hello.locator(k) {
            Some(locator) => z_loaned_string_t {
                _start: locator.as_ptr(),
                _len: locator.len(),
            },
            None => z_loaned_string_t {
                _start: core::ptr::null(),
                _len: 0,
            },
        });
    // SAFETY: `views` and the Hello's strings outlive the array, which this frame keeps.
    let array = unsafe { StringArrayState::lent(&views[..count]) };
    on_hello(&mut HelloState::lent(zid, whatami, &array));
}

/// Owned hello (pico `z_owned_hello_t`, 56 B measured).
#[repr(C)]
pub struct z_owned_hello_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 6],
}

/// Loaned hello — identical layout, slot 0 is the same handle.
#[repr(C)]
pub struct z_loaned_hello_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 6],
}

/// Moved hello (pico `z_moved_hello_t`).
#[repr(C)]
pub struct z_moved_hello_t {
    pub(crate) _this: z_owned_hello_t,
}

impl z_owned_hello_t {
    pub(crate) fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 6],
        }
    }
}

unsafe fn hello_state<'a>(hello: *const z_loaned_hello_t) -> Option<&'a HelloState> {
    let hello = hello.as_ref()?;
    (hello.handle as *const HelloState).as_ref()
}

/// The peer's zid (pico `z_hello_zid`), BY VALUE.
///
/// 16 bytes, so SysV returns it in a register pair rather than through a hidden
/// out-pointer — the trap that bit the y529 harness on 32-byte returns does not
/// apply here, but the size is load-bearing either way.
///
/// # Safety
/// `hello` must be a live loaned hello (or null, which reads the empty id).
#[no_mangle]
pub unsafe extern "C" fn z_hello_zid(hello: *const z_loaned_hello_t) -> z_id_t {
    hello_state(hello).map_or_else(z_id_t::empty, |s| s.zid)
}

/// The peer's role (pico `z_hello_whatami`).
///
/// A Hello whose role bits decoded to nothing wz recognises reports 0, which
/// `z_whatami_to_view_string` renders `"Other"` — the unknown stays DISTINCT
/// from a role rather than defaulting to one.
///
/// # Safety
/// See [`z_hello_zid`].
#[no_mangle]
pub unsafe extern "C" fn z_hello_whatami(hello: *const z_loaned_hello_t) -> z_whatami_t {
    hello_state(hello).map_or(0, |s| s.whatami)
}

/// The peer's advertised locators (pico `zp_hello_locators`).
///
/// # Safety
/// `hello` must be a live loaned hello; the returned array borrows it.
#[no_mangle]
pub unsafe extern "C" fn zp_hello_locators(
    hello: *const z_loaned_hello_t,
) -> *const z_loaned_string_array_t {
    match hello_state(hello) {
        Some(state) => &state.locators_loan as *const z_loaned_string_array_t,
        None => core::ptr::null(),
    }
}

/// The peer's advertised locators as an OWNED copy (pico `z_hello_locators`).
///
/// Distinct from [`zp_hello_locators`], which borrows: upstream ships both, and
/// the owned form is what a caller keeps after the hello goes away.
///
/// # Safety
/// `hello` must be a live loaned hello; `out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn z_hello_locators(
    hello: *const z_loaned_hello_t,
    out: *mut z_owned_string_array_t,
) {
    if out.is_null() {
        return;
    }
    let items = hello_state(hello).map_or_else(Vec::new, |s| s.locators().to_strings());
    *out = z_owned_string_array_t {
        handle: Box::into_raw(StringArrayState::new(items)) as *mut c_void,
        _pad: [core::ptr::null_mut(); 3],
    };
}

/// Null an owned hello (pico `z_internal_hello_null`).
///
/// # Safety
/// `hello` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn z_internal_hello_null(hello: *mut z_owned_hello_t) {
    if let Some(hello) = hello.as_mut() {
        *hello = z_owned_hello_t::null_value();
    }
}

/// Whether an owned hello holds a value (pico `z_internal_hello_check`).
///
/// # Safety
/// `hello` must be a live owned hello.
#[no_mangle]
pub unsafe extern "C" fn z_internal_hello_check(hello: *const z_owned_hello_t) -> bool {
    hello.as_ref().is_some_and(|h| !h.handle.is_null())
}

/// Borrow an owned hello (pico `z_hello_loan`) — offset-0 identity.
///
/// # Safety
/// `hello` must be a live owned hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_loan(hello: *const z_owned_hello_t) -> *const z_loaned_hello_t {
    hello as *const z_loaned_hello_t
}

/// Mutably borrow an owned hello (pico `z_hello_loan_mut`).
///
/// # Safety
/// See [`z_hello_loan`].
#[no_mangle]
pub unsafe extern "C" fn z_hello_loan_mut(hello: *mut z_owned_hello_t) -> *mut z_loaned_hello_t {
    hello as *mut z_loaned_hello_t
}

/// Release an owned hello (pico `z_hello_drop`).
///
/// # Safety
/// `hello` must be a live moved hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_drop(hello: *mut z_moved_hello_t) {
    if let Some(moved) = hello.as_mut() {
        let handle = moved._this.handle;
        moved._this = z_owned_hello_t::null_value();
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut HelloState));
        }
    }
}

/// Move an owned hello (pico `z_hello_move`) — offset-0 identity.
///
/// # Safety
/// `hello` must be a live owned hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_move(hello: *mut z_owned_hello_t) -> *mut z_moved_hello_t {
    hello as *mut z_moved_hello_t
}

/// Take an owned hello out of a moved wrapper (pico `z_hello_take`).
///
/// # Safety
/// Both pointers must be live and non-overlapping.
#[no_mangle]
pub unsafe extern "C" fn z_hello_take(dst: *mut z_owned_hello_t, src: *mut z_moved_hello_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = [core::ptr::null_mut(); 6];
    (*src)._this = z_owned_hello_t::null_value();
}

/// Clone a loaned hello into owned storage (pico `z_hello_clone`).
///
/// # Safety
/// `hello` must be a live loaned hello; `dst` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn z_hello_clone(
    dst: *mut z_owned_hello_t,
    hello: *const z_loaned_hello_t,
) -> ZResult {
    if dst.is_null() {
        return crate::result::Z_ERR_INVALID;
    }
    let Some(state) = hello_state(hello) else {
        *dst = z_owned_hello_t::null_value();
        return crate::result::Z_ERR_INVALID;
    };
    let cloned = HelloState::new(state.zid, state.whatami, state.locators().to_strings());
    *dst = z_owned_hello_t {
        handle: Box::into_raw(cloned) as *mut c_void,
        _pad: [core::ptr::null_mut(); 6],
    };
    crate::result::Z_OK
}

// ---------------------------------------------------------------------------
// z_owned_closure_hello_t
// ---------------------------------------------------------------------------

/// pico `z_closure_hello_callback_t`: `void call(z_loaned_hello_t*, void*)`.
pub type z_closure_hello_callback_t =
    Option<unsafe extern "C" fn(*mut z_loaned_hello_t, *mut c_void)>;

/// Owned hello closure (pico `z_owned_closure_hello_t`, 24 B measured).
///
/// Field ORDER is `{ context, call, drop }` and is written DIRECTLY by pico's
/// `z_closure` macro without ever calling into this library — so, exactly as
/// for the zid closure, a wrong order is invisible to the linker and caught
/// only by this module's offset pin.
#[repr(C)]
pub struct z_owned_closure_hello_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_hello_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned hello closure, same layout.
#[repr(C)]
pub struct z_loaned_closure_hello_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_hello_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved hello closure (pico `z_moved_closure_hello_t`).
#[repr(C)]
pub struct z_moved_closure_hello_t {
    pub(crate) _this: z_owned_closure_hello_t,
}

impl z_owned_closure_hello_t {
    pub(crate) fn null_value() -> Self {
        Self {
            context: core::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// Null an owned hello closure (pico `z_internal_closure_hello_null`).
///
/// # Safety
/// `closure` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_hello_null(closure: *mut z_owned_closure_hello_t) {
    if let Some(closure) = closure.as_mut() {
        *closure = z_owned_closure_hello_t::null_value();
    }
}

/// Whether an owned hello closure carries a callback (pico
/// `z_internal_closure_hello_check`).
///
/// # Safety
/// `closure` must be a live owned hello closure.
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_hello_check(
    closure: *const z_owned_closure_hello_t,
) -> bool {
    closure.as_ref().is_some_and(|c| c.call.is_some())
}

/// Borrow an owned hello closure (pico `z_closure_hello_loan`).
///
/// # Safety
/// `closure` must be a live owned hello closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_hello_loan(
    closure: *const z_owned_closure_hello_t,
) -> *const z_loaned_closure_hello_t {
    closure as *const z_loaned_closure_hello_t
}

/// Move an owned hello closure (pico `z_closure_hello_move`) — offset-0
/// identity. THE symbol `z_scout.c` needs beyond the accessors: `z_closure`
/// itself is a header macro, so only the move seam crosses the ABI.
///
/// # Safety
/// `closure` must be a live owned hello closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_hello_move(
    closure: *mut z_owned_closure_hello_t,
) -> *mut z_moved_closure_hello_t {
    closure as *mut z_moved_closure_hello_t
}

/// Release an owned hello closure (pico `z_closure_hello_drop`): run the
/// caller's `drop` on its context exactly once, then null the slot.
///
/// # Safety
/// `closure` must be a live moved hello closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_hello_drop(closure: *mut z_moved_closure_hello_t) {
    if let Some(moved) = closure.as_mut() {
        let dropper = moved._this.drop;
        let context = moved._this.context;
        moved._this = z_owned_closure_hello_t::null_value();
        if let Some(dropper) = dropper {
            dropper(context);
        }
    }
}

/// Take an owned hello closure out of a moved wrapper (pico
/// `z_closure_hello_take`).
///
/// # Safety
/// Both pointers must be live and non-overlapping.
#[no_mangle]
pub unsafe extern "C" fn z_closure_hello_take(
    dst: *mut z_owned_closure_hello_t,
    src: *mut z_moved_closure_hello_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    *dst = z_owned_closure_hello_t {
        context: (*src)._this.context,
        call: (*src)._this.call,
        drop: (*src)._this.drop,
    };
    (*src)._this = z_owned_closure_hello_t::null_value();
}

/// Invoke a loaned hello closure (pico `z_closure_hello_call`).
///
/// # Safety
/// `closure` and `hello` must be live.
#[no_mangle]
pub unsafe extern "C" fn z_closure_hello_call(
    closure: *const z_loaned_closure_hello_t,
    hello: *mut z_loaned_hello_t,
) {
    if let Some(closure) = closure.as_ref() {
        if let Some(call) = closure.call {
            call(hello, closure.context);
        }
    }
}

// ---------------------------------------------------------------------------
// z_scout
// ---------------------------------------------------------------------------

/// pico `z_what_t`, the bitmask of roles a scout asks for: a C enum, as wide as the target's C ABI
/// makes it (`crate::c_enum`).
pub type z_what_t = crate::c_enum::PicoEnum;

/// pico `z_scout_options_t` (`api/types.h:553-556`), 8 B measured on a host:
/// `{ uint32_t timeout_ms; z_what_t what; }`.
#[repr(C)]
pub struct z_scout_options_t {
    /// Total discovery budget in milliseconds.
    pub timeout_ms: u32,
    /// `z_what_t` bitmask of roles to scout for.
    pub what: z_what_t,
}

/// Default scout options (pico `z_scout_options_default`) — the same values
/// pico's config defaults carry, so the options form and the config form agree.
///
/// # Safety
/// `options` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn z_scout_options_default(options: *mut z_scout_options_t) {
    if let Some(options) = options.as_mut() {
        options.timeout_ms = u32::try_from(SCOUTING_TIMEOUT_DEFAULT_MS).unwrap_or(u32::MAX);
        options.what = z_what_t::from(SCOUTING_WHAT_DEFAULT);
    }
}

/// A fresh random scouting identity, from the same entropy source the session plane mints its
/// per-session zid with, or `None` when there is none to draw (a profile that cannot open a
/// session either), which asks as nobody.
fn fresh_scout_zid() -> Option<SessionZid> {
    let mut zid = [0u8; 16];
    draw_zid_bytes(&mut zid)?;
    SessionZid::new(&zid).ok()
}

/// The tokio engine's sessions draw from the host's generator, which the `getrandom` crate reads.
#[cfg(feature = "engine-tokio")]
fn draw_zid_bytes(zid: &mut [u8; 16]) -> Option<()> {
    getrandom::getrandom(zid).ok()
}

/// The cooperative engine's sessions draw from the random source the build's host hands the engine
/// (`crate::coop_host`): the host's kernel, or a Zephyr image's board, which has no `getrandom`.
#[cfg(not(feature = "engine-tokio"))]
fn draw_zid_bytes(zid: &mut [u8; 16]) -> Option<()> {
    use wz_session_core::entropy::EntropySource;
    crate::coop_host::entropy().try_fill_bytes(zid).ok()
}

/// What a scout reads from a pico config: each key's value, or pico's default for it.
/// `z_scout` with NULL options and `z_open`'s lookup read the same four keys
/// (`vendor/zenoh-pico/src/net/session.c` @ `static z_result_t _z_locators_by_scout(`), so
/// they read them here, once.
struct ScoutConfig<'a> {
    what: u8,
    budget_ms: u64,
    locator: &'a str,
    /// The id the config states for the session, read as `z_open` reads it
    /// (`crate::session::stated_zid`), or `None` when it states none.
    zid: Option<SessionZid>,
}

impl<'a> ScoutConfig<'a> {
    /// The config's scouting keys, or `Z_ERR_INVALID` when it states an id `z_open` refuses: a
    /// caller that named an identity and scouted as another, or as nobody, would not know it.
    /// pico reads whatever its fixed indexes land on there (`vendor/zenoh-pico/src/api/api.c` @
    /// `_z_uuid_to_bytes(zid.id, zid_str);`), which is no id the caller named.
    fn read(cfg: Option<&'a ConfigState>) -> Result<Self, ZResult> {
        let get = |key: u8| cfg.and_then(|c| c.get(key)).map(str::trim);
        Ok(Self {
            what: get(Z_CONFIG_SCOUTING_WHAT_KEY)
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(SCOUTING_WHAT_DEFAULT),
            budget_ms: get(Z_CONFIG_SCOUTING_TIMEOUT_KEY)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(SCOUTING_TIMEOUT_DEFAULT_MS),
            locator: get(Z_CONFIG_MULTICAST_LOCATOR_KEY).unwrap_or(MULTICAST_LOCATOR_DEFAULT),
            zid: crate::session::stated_zid(cfg.and_then(|c| c.get(Z_CONFIG_SESSION_ZID_KEY)))?,
        })
    }
}

/// The locators a `z_open` whose config names none opens on: pico's `_z_locators_by_scout`,
/// which scouts with the config's `what`, group and budget, stops at the first Hello, and
/// hands that node's locators to the open as its connect locators
/// (`vendor/zenoh-pico/src/net/session.c` @
/// `ret = _z_locators_by_scout(config, zid, &connect_locators);`). Nobody answering, or a
/// node that answered with no locator, is `Z_ERR_SCOUT_NO_RESULTS`, as there; a group this
/// crate cannot scout on is `Z_ERR_INVALID`, as `z_scout` answers it.
///
/// pico's lookup names the session's zid, which it minted when the config stated none; the
/// engine mints this session's later, so a config that states none asks with a fresh one.
///
/// `policy` and `limits` are the snapshots the open resolved, which the lookup's window is run
/// under.
pub(crate) fn locators_by_scout(
    cfg: &ConfigState,
    policy: &SessionPolicy,
    limits: &SessionLimits,
) -> Result<Vec<String>, ZResult> {
    let read = ScoutConfig::read(Some(cfg))?;
    let Some((group, port)) = parse_multicast_locator(read.locator) else {
        return Err(crate::result::Z_ERR_INVALID);
    };
    let zid = read.zid.or_else(fresh_scout_zid);
    // On the time base the config names, which `cfg` holds for the window, as the session opened
    // from it will run on.
    let clock = window::clock_of(Some(cfg));
    window::first(
        &clock,
        group,
        port,
        read.what,
        zid,
        read.budget_ms,
        policy,
        limits,
    )?
    .map(|hello| hello.locators)
    .filter(|locators| !locators.is_empty())
    .ok_or(crate::result::Z_ERR_SCOUT_NO_RESULTS)
}

/// Active multicast scouting (pico `z_scout`).
///
/// BLOCKS for the resolved budget, invoking `callback` once per Hello decoded,
/// then runs the closure's `drop` on its context and consumes both the config
/// and the closure — upstream's ownership contract verbatim
/// (`src/api/api.c:773-830`).
///
/// Resolution order for `what` / `timeout_ms` follows upstream: the `options`
/// struct when non-NULL, else the config keys, else pico's documented defaults.
/// The group comes from `Z_CONFIG_MULTICAST_LOCATOR_KEY` either way — upstream
/// gives it no options field.
///
/// The Scout names the id `Z_CONFIG_SESSION_ZID_KEY` states, and no asker when
/// it states none, as upstream's starts from `_z_id_empty()`; an id `z_open`
/// would refuse is refused here with the same `Z_ERR_INVALID`.
///
/// # Safety
/// `config` and `callback` must be live moved values; both are consumed.
#[no_mangle]
pub unsafe extern "C" fn z_scout(
    config: *mut crate::abi::z_moved_config_t,
    callback: *mut z_moved_closure_hello_t,
    options: *const z_scout_options_t,
) -> ZResult {
    if config.is_null() || callback.is_null() {
        return crate::result::Z_ERR_INVALID;
    }
    // Take the closure APART first, exactly as upstream does: the context is
    // lifted out and the slot nulled, so the `drop` this function runs at the
    // end cannot also be run by a later `z_closure_hello_drop` on the same
    // storage.
    let user_call = (*callback)._this.call;
    let user_drop = (*callback)._this.drop;
    let user_ctx = (*callback)._this.context;
    (*callback)._this = z_owned_closure_hello_t::null_value();

    // Consume the config: read what we need, then release the handle. Done
    // before the scout runs so an early return cannot leak it.
    let config_handle = (*config)._this.handle;
    (*config)._this = crate::abi::z_owned_config_t::null_value();
    let cfg: Option<Box<ConfigState>> = if config_handle.is_null() {
        None
    } else {
        Some(Box::from_raw(config_handle as *mut ConfigState))
    };
    let read = ScoutConfig::read(cfg.as_deref());
    // The scout's two snapshots, resolved as `z_open` resolves them from its config: a scout
    // handed no config reads pico's defaults, the empty config, and one whose policies or limits
    // the build refuses is refused with the open's code.
    let unstated = PolicyStatements::none();
    let snapshots =
        crate::session::resolve_snapshots(cfg.as_deref().map_or(&unstated, |cfg| &cfg.policies));
    // The window's clock: the time base the config names, which `cfg` holds and is kept for the
    // window, or the system's.
    let clock = window::clock_of(cfg.as_deref());
    let (read, (policy, limits)) = match (read, snapshots) {
        (Ok(read), Ok(snapshots)) => (read, snapshots),
        (Err(code), _) | (Ok(_), Err(code)) => {
            if let Some(drop_fn) = user_drop {
                drop_fn(user_ctx);
            }
            return code;
        }
    };
    let (what, budget_ms) = match options.as_ref() {
        Some(o) => (o.what as u8, u64::from(o.timeout_ms)),
        None => (read.what, read.budget_ms),
    };
    let ScoutConfig { locator, zid, .. } = read;

    let Some((group, port)) = parse_multicast_locator(locator) else {
        if let Some(drop_fn) = user_drop {
            drop_fn(user_ctx);
        }
        return crate::result::Z_ERR_INVALID;
    };

    let scouted = run_scout(
        &clock,
        group,
        port,
        what,
        zid,
        budget_ms,
        &policy,
        &limits,
        |hello| {
            // The callback takes a MUTABLE loaned pointer (pico's signature), but
            // this side keeps ownership: the state lives in `lend_hello`'s frame
            // for the call, matching upstream, where the hello is owned by the
            // scouting task and only borrowed by the user.
            if let Some(call) = user_call {
                let mut loaned = z_loaned_hello_t {
                    handle: hello as *mut HelloState as *mut c_void,
                    _pad: [core::ptr::null_mut(); 6],
                };
                call(&mut loaned as *mut z_loaned_hello_t, user_ctx);
            }
        },
    );
    drop(cfg);

    // The closure's `drop` runs exactly once, AFTER the last callback — the
    // signal `z_scout.c` uses to print its "found nothing" / "dropping" line,
    // so emitting it early would reorder that program's own output.
    if let Some(drop_fn) = user_drop {
        drop_fn(user_ctx);
    }
    match scouted {
        Ok(_) => crate::result::Z_OK,
        Err(code) => code,
    }
}

/// Drive one scouting window for `budget_ms` and hand each peer that answered
/// to `on_hello`. Returns the number delivered, or the code of a window that
/// could not be run (the cooperative engine's table held by another window).
///
/// DELEGATES to the window of the engine the build runs (`window::run`), whose rules are the
/// session's. This function used to carry its own copy of that loop, and the copy is what let
/// the two ABIs disagree — the pico side re-entered whole scouting CYCLES (because the
/// statechart left `AwaitingHello` on the first Hello, so a single window could report only one
/// peer), which re-sent a Scout per cycle and needed a zid set to suppress the duplicate answers
/// its own re-scouting provoked. The FSM carries pico's `exit_on_first == false` survey arm now,
/// so the shared drive is a single window, and the WHEN and the ORDER of the callbacks — after
/// the window, last responder first — are settled once in
/// `wz_session_core::scouting_host::deliver_in_upstream_order` against upstream rather than
/// twice here and there.
///
/// All this side keeps is the ABI mapping: a scouted hello becomes the `HelloState` behind
/// pico's `z_loaned_hello_t`. `policy` and `limits` are the scout's snapshots, handed to the
/// window.
#[allow(clippy::too_many_arguments)]
fn run_scout(
    clock: &window::Clock,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Option<SessionZid>,
    budget_ms: u64,
    policy: &SessionPolicy,
    limits: &SessionLimits,
    mut on_hello: impl FnMut(&mut HelloState),
) -> Result<usize, ZResult> {
    window::run(
        clock,
        group,
        port,
        what,
        zid,
        budget_ms,
        policy,
        limits,
        |hello| lend_hello(hello, &mut on_hello),
    )
}

/// Adopt a loaned hello into an owned one (pico `z_hello_take_from_loaned`).
///
/// R311y559 — a symbol the census found missing. A DEEP COPY that leaves the
/// source EMPTY, routed through the same `HelloState::new` `z_hello_clone`
/// uses so the two cannot render a peer differently. Copying rather than moving
/// the handle: a loaned hello is the scout dispatcher's own state, still
/// borrowed by the frame around the callback — the same argument
/// `z_sample_take_from_loaned` makes.
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a live loaned hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_take_from_loaned(
    dst: *mut z_owned_hello_t,
    src: *mut z_loaned_hello_t,
) -> ZResult {
    crate::ffi::guarded(|| {
        if dst.is_null() || src.is_null() {
            return crate::result::Z_ERR_NULL;
        }
        let rc = z_hello_clone(dst, src as *const z_loaned_hello_t);
        if rc == crate::result::Z_OK {
            // Empty the source, as every `take_from_loaned` in this crate does.
            (*src).handle = core::ptr::null_mut();
        }
        rc
    })
}

/// Build an owned hello closure from a callback + drop + context (pico
/// `z_closure_hello`).
///
/// R311y559 — the CONSTRUCTOR of a family whose `_call` / `_drop` / `_loan`
/// half already existed. A pico program builds its scout closure with this
/// function, so without it the whole scouting example could not link.
///
/// # Safety
/// `closure` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_closure_hello(
    closure: *mut z_owned_closure_hello_t,
    call: z_closure_hello_callback_t,
    drop: crate::pubsub::z_closure_drop_callback_t,
    context: *mut core::ffi::c_void,
) -> ZResult {
    crate::ffi::guarded(|| {
        if closure.is_null() {
            return crate::result::Z_ERR_NULL;
        }
        *closure = z_owned_closure_hello_t {
            context,
            call,
            drop,
        };
        crate::result::Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string_array::{z_string_array_get, z_string_array_len};
    use wz_session_core::scouting_host::{HelloRow, ScoutedHello};

    /// The three C-allocated structs of this plane, pinned against the sizes
    /// MEASURED off the pinned zenoh-pico headers on a 64-bit host (56 / 32 / 24). A C
    /// program stack-allocates each, so a drift here corrupts its frame — and the
    /// linker cannot see it, because a size mismatch is not a symbol mismatch.
    ///
    /// Each is held as the words it is declared in: seven, four and three, which are those
    /// sizes on a 64-bit host. On a 32-bit one pico's hello keeps its 16-byte id and its two
    /// small fields, so it is larger than the seven words the handle model writes into it,
    /// which is the direction that cannot write past a program's storage.
    #[test]
    fn hello_and_string_array_abi() {
        let word = std::mem::size_of::<*mut c_void>();
        assert_eq!(std::mem::size_of::<z_owned_hello_t>(), 7 * word);
        assert_eq!(std::mem::size_of::<z_owned_string_array_t>(), 4 * word);
        assert_eq!(std::mem::size_of::<z_owned_closure_hello_t>(), 3 * word);
        assert_eq!(std::mem::size_of::<z_scout_options_t>(), 8);
        // Every loan in this crate is an offset-0 identity cast, which is only
        // sound while the loaned form has the owned form's layout.
        assert_eq!(
            std::mem::size_of::<z_loaned_hello_t>(),
            std::mem::size_of::<z_owned_hello_t>()
        );
        assert_eq!(
            std::mem::size_of::<z_loaned_string_array_t>(),
            std::mem::size_of::<z_owned_string_array_t>()
        );
    }

    /// A scout reads the id its config states as `z_open` reads it, a UUID in the order written,
    /// asks as nobody when it states none, and refuses what the open refuses: text pico's reader
    /// was not written for (hex without the dashes among it) and the id of sixteen zero bytes.
    #[test]
    fn a_scout_reads_the_stated_id_as_the_open_does() {
        let stated = |text: Option<&str>| {
            let mut cfg = ConfigState::default();
            if let Some(text) = text {
                cfg.insert(Z_CONFIG_SESSION_ZID_KEY, text);
            }
            ScoutConfig::read(Some(&cfg)).map(|read| read.zid)
        };
        assert_eq!(stated(None), Ok(None), "no id stated: no asker");
        assert_eq!(ScoutConfig::read(None).map(|read| read.zid), Ok(None));
        assert_eq!(
            stated(Some("01020304-0506-0708-090a-0b0c0d0e0f10")),
            Ok(Some(SessionZid::from([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
            ])))
        );
        assert_eq!(
            stated(Some("aabbccdd-eeff-0000-0000-000000000000")),
            Ok(Some(SessionZid::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))),
            "trimmed to the last non-zero byte, as the open's INIT carries it"
        );
        for refused in [
            "",
            "ff000000000000000000000000000001",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert_eq!(
                stated(Some(refused)),
                Err(crate::result::Z_ERR_INVALID),
                "the stated id `{refused}`"
            );
        }
    }

    /// `z_scout` with a stated id the open refuses answers `Z_ERR_INVALID` before it scouts: the
    /// closure is never called and its drop runs once, as on every other exit.
    #[test]
    fn a_scout_refuses_a_stated_id_the_open_refuses() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        unsafe extern "C" fn count_drop(context: *mut c_void) {
            (*(context as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
        }

        let mut cfg = ConfigState::default();
        cfg.insert(
            Z_CONFIG_SESSION_ZID_KEY,
            "00000000-0000-0000-0000-000000000000",
        );
        let mut config = crate::abi::z_moved_config_t {
            _this: crate::abi::z_owned_config_t {
                handle: Box::into_raw(Box::new(cfg)) as *mut c_void,
                _pad: [core::ptr::null_mut(); 3],
            },
        };
        let drops = AtomicUsize::new(0);
        let mut closure = z_moved_closure_hello_t {
            _this: z_owned_closure_hello_t {
                context: &drops as *const AtomicUsize as *mut c_void,
                call: None,
                drop: Some(count_drop),
            },
        };
        // SAFETY: both values are live locals, and `z_scout` consumes them.
        let rc = unsafe { z_scout(&mut config, &mut closure, core::ptr::null()) };
        assert_eq!(rc, crate::result::Z_ERR_INVALID);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "the drop ran once");
        assert!(config._this.handle.is_null(), "the config was consumed");
    }

    /// `z_scout` with a config whose policies the build refuses answers the open's
    /// `Z_ERR_CONFIG_INVALID_VALUE` before it scouts, and runs the closure's drop once. Only a
    /// build with the policy doors holds a statement to refuse.
    #[cfg(feature = "config-policy")]
    #[test]
    fn a_scout_refuses_a_config_whose_policies_the_open_refuses() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        unsafe extern "C" fn count_drop(context: *mut c_void) {
            (*(context as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
        }

        let cfg = ConfigState {
            policies: PolicyStatements::unchecked("no-such-policy", "on"),
            ..ConfigState::default()
        };
        let mut config = crate::abi::z_moved_config_t {
            _this: crate::abi::z_owned_config_t {
                handle: Box::into_raw(Box::new(cfg)) as *mut c_void,
                _pad: [core::ptr::null_mut(); 3],
            },
        };
        let drops = AtomicUsize::new(0);
        let mut closure = z_moved_closure_hello_t {
            _this: z_owned_closure_hello_t {
                context: &drops as *const AtomicUsize as *mut c_void,
                call: None,
                drop: Some(count_drop),
            },
        };
        // SAFETY: both values are live locals, and `z_scout` consumes them.
        let rc = unsafe { z_scout(&mut config, &mut closure, core::ptr::null()) };
        assert_eq!(rc, crate::result::Z_ERR_CONFIG_INVALID_VALUE);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "the drop ran once");
        assert!(config._this.handle.is_null(), "the config was consumed");
    }

    /// A hello lends its locator array by POINTER, so the array handle must
    /// survive the call that returns it. A `zp_hello_locators` that built its
    /// return value on the stack would pass a same-statement read and dangle
    /// the moment the caller stored it — this holds the pointer across a
    /// second call before reading through it.
    /// A scout that names no id asks as a fresh one, drawn from the source the build's sessions
    /// mint theirs from: two draws are two ids, and neither is the all-zero id no node has.
    #[test]
    fn a_scout_without_an_id_draws_a_fresh_one_each_time() {
        let first = fresh_scout_zid().expect("the build's random source gave no id");
        let second = fresh_scout_zid().expect("the build's random source gave no second id");
        assert_eq!(first.as_slice().len(), 16);
        assert!(first != second, "two draws gave one id");
    }

    #[test]
    fn hello_lends_a_locator_array_that_outlives_the_call() {
        let state = HelloState::new(
            z_id_t::from_wire(&[0xAB, 0xCD]),
            2,
            vec!["tcp/127.0.0.1:7447".to_string()],
        );
        let loaned = z_loaned_hello_t {
            handle: (&*state) as *const HelloState as *mut c_void,
            _pad: [core::ptr::null_mut(); 6],
        };
        unsafe {
            let locs = zp_hello_locators(&loaned);
            assert_eq!(z_hello_whatami(&loaned), 2);
            assert_eq!(z_hello_zid(&loaned).id[0], 0xAB);
            assert_eq!(z_string_array_len(locs), 1);
        }
    }
    /// The loaned form of the hello `state`, as a scout hands it to the callback.
    fn lent_to_callback(state: &mut HelloState) -> z_loaned_hello_t {
        z_loaned_hello_t {
            handle: (state as *mut HelloState).cast::<c_void>(),
            _pad: [core::ptr::null_mut(); 6],
        }
    }

    /// A Hello of `count` locators from the node whose id is all `7`s.
    fn scouted(count: usize) -> ScoutedHello {
        ScoutedHello {
            version: 9,
            whatami: None,
            zid: SessionZid::from([7; 16]),
            locators: (0..count).map(|k| format!("tcp/10.0.0.{k}:7447")).collect(),
        }
    }

    /// A scouted Hello is handed to the callback with its locators lent from its own strings:
    /// each view the callback reads points at the bytes the window decoded, so a delivery copies
    /// none of them. Turned red by a delivery that copies the locators.
    #[test]
    fn a_delivered_hello_lends_the_scouted_locators() {
        let hello = scouted(caps::MAX_ADMIN_LOCATORS.min(2));
        let mut seen = 0;
        lend_hello(&hello, &mut |state: &mut HelloState| {
            let loaned = lent_to_callback(state);
            // SAFETY: a live hello, lent for this call.
            unsafe {
                let locators = zp_hello_locators(&loaned);
                assert_eq!(z_string_array_len(locators), hello.locators.len());
                for (k, locator) in hello.locators.iter().enumerate() {
                    let view = &*z_string_array_get(locators, k);
                    assert_eq!(view._start, locator.as_ptr(), "locator {k} is lent");
                    assert_eq!(view._len, locator.len());
                }
                assert_eq!(z_hello_zid(&loaned).id[0], 7);
                assert_eq!(z_hello_whatami(&loaned), 0);
            }
            seen += 1;
        });
        assert_eq!(seen, 1);
    }

    /// A Hello with more locators than the table of views holds is handed whole, through copies,
    /// and a clone of a delivered hello, lent or not, owns copies that outlive the scouted Hello.
    #[test]
    fn a_long_hello_is_handed_whole_and_a_clone_outlives_the_scouted_one() {
        for count in [
            caps::MAX_ADMIN_LOCATORS.min(2),
            caps::MAX_ADMIN_LOCATORS + 1,
        ] {
            let hello = scouted(count);
            let mut cloned = z_owned_hello_t::null_value();
            lend_hello(&hello, &mut |state: &mut HelloState| {
                let loaned = lent_to_callback(state);
                // SAFETY: a live hello, lent for this call, and a writable destination.
                unsafe {
                    assert_eq!(z_string_array_len(zp_hello_locators(&loaned)), count);
                    assert_eq!(z_hello_clone(&mut cloned, &loaned), crate::result::Z_OK);
                }
            });
            drop(hello);
            // SAFETY: the clone is a live owned hello, dropped once.
            unsafe {
                let locators = zp_hello_locators(z_hello_loan(&cloned));
                assert_eq!(z_string_array_len(locators), count, "{count} locators");
                if count > 0 {
                    let first = &*z_string_array_get(locators, 0);
                    let bytes = core::slice::from_raw_parts(first._start, first._len);
                    assert_eq!(bytes, b"tcp/10.0.0.0:7447");
                }
                z_hello_drop(z_hello_move(&mut cloned));
            }
        }
    }
    /// A window's row is lent as a host's Hello is: each view points into the row's own text, so a
    /// scout over the cooperative engine copies no locator either. Turned red by a delivery that
    /// copies the row's locators.
    #[test]
    fn a_window_row_lends_its_own_text() {
        let hello = scouted(caps::MAX_ADMIN_LOCATORS.min(2));
        let row = HelloRow::of(&hello);
        let start = (&row as *const HelloRow).cast::<u8>();
        let span = start..start.wrapping_add(core::mem::size_of::<HelloRow>());
        let mut seen = 0;
        lend_hello(&row, &mut |state: &mut HelloState| {
            let loaned = lent_to_callback(state);
            // SAFETY: a live hello, lent for this call.
            unsafe {
                let locators = zp_hello_locators(&loaned);
                assert_eq!(z_string_array_len(locators), hello.locators.len());
                for (k, locator) in hello.locators.iter().enumerate() {
                    let view = &*z_string_array_get(locators, k);
                    assert!(span.contains(&view._start), "locator {k} is the row's");
                    let bytes = core::slice::from_raw_parts(view._start, view._len);
                    assert_eq!(bytes, locator.as_bytes());
                }
            }
            seen += 1;
        });
        assert_eq!(seen, 1);
    }

    /// The cooperative engine's table of Hellos is one: a scout asked on the thread whose window
    /// holds it is refused at once, another thread's waits for it and has it once it is given back,
    /// with what is left of its budget, and one whose budget runs out first goes without. Turned red
    /// by a table claimed twice at once, a re-entered scout that waits, or a waiter that is not woken.
    #[cfg(all(not(feature = "engine-tokio"), feature = "std"))]
    #[test]
    fn the_static_table_is_waited_for_and_refused_only_to_its_own_thread() {
        use std::time::{Duration, Instant};

        let epoch = Instant::now();
        let now_ms = move || epoch.elapsed().as_millis() as u64;
        let (held, _) = window::table::Claim::within(5_000, now_ms).expect("the table is had");
        let started = Instant::now();
        assert_eq!(
            window::table::Claim::within(5_000, now_ms).err(),
            Some(window::table::Unclaimed::Reentered)
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "refused at once"
        );

        let short = std::thread::spawn(move || {
            window::table::Claim::within(30, now_ms).map(|(_, left)| left)
        });
        assert_eq!(
            short.join().expect("the thread"),
            Err(window::table::Unclaimed::Expired)
        );

        let waiter = std::thread::spawn(move || {
            window::table::Claim::within(5_000, now_ms).map(|(_, left)| left)
        });
        std::thread::sleep(Duration::from_millis(50));
        drop(held);
        let left = waiter
            .join()
            .expect("the thread")
            .expect("the table is given back");
        assert!(left < 5_000, "the wait is taken from the budget");
        assert!(left > 3_000, "the waiter was woken, not timed out");
    }

    /// Two threads that scout at once both complete: the second waits for the table the first
    /// holds, within its own budget, and neither is refused. Over the host's sockets, on a group
    /// nobody answers. Turned red by a scout refused because another thread scouts.
    #[cfg(all(not(feature = "engine-tokio"), feature = "std"))]
    #[test]
    fn two_threads_that_scout_at_once_both_complete() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        unsafe extern "C" fn count_drop(context: *mut c_void) {
            (*(context as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
        }

        fn scout() -> (ZResult, usize) {
            let mut cfg = ConfigState::default();
            cfg.insert(Z_CONFIG_MULTICAST_LOCATOR_KEY, "udp/239.255.91.79:47479");
            cfg.insert(Z_CONFIG_SCOUTING_TIMEOUT_KEY, "150");
            let mut config = crate::abi::z_moved_config_t {
                _this: crate::abi::z_owned_config_t {
                    handle: Box::into_raw(Box::new(cfg)) as *mut c_void,
                    _pad: [core::ptr::null_mut(); 3],
                },
            };
            let drops = AtomicUsize::new(0);
            let mut closure = z_moved_closure_hello_t {
                _this: z_owned_closure_hello_t {
                    context: &drops as *const AtomicUsize as *mut c_void,
                    call: None,
                    drop: Some(count_drop),
                },
            };
            // SAFETY: both values are live locals, and `z_scout` consumes them.
            let rc = unsafe { z_scout(&mut config, &mut closure, core::ptr::null()) };
            (rc, drops.load(Ordering::SeqCst))
        }

        let first = std::thread::spawn(scout);
        let second = std::thread::spawn(scout);
        for scouted in [first, second] {
            assert_eq!(
                scouted.join().expect("the thread"),
                (crate::result::Z_OK, 1),
                "the scout completed and its drop ran once"
            );
        }
    }
}
