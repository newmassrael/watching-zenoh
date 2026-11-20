// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The SCOUT plane — multicast peer discovery, and the `hello` a discovered
//! peer is reported as.
//!
//! The DRIVE is [`wz_capi_core::scouting`], shared with the zenoh-pico ABI: bind
//! the group, cycle the scouting FSM until the budget is spent, report each
//! distinct peer once. This module is only the shim — read the config, map a
//! neutral hello onto zenoh-c's types, and call the C closure.
//!
//! ## `whatami` is an INDEXED BITMASK, not an ordinal list
//!
//! `Z_WHATAMI_ROUTER` is 1, `PEER` is 2 and `CLIENT` is 4, so 3 is
//! "router|peer" — a COMBINATION, not a third role. Rendering it as a role list
//! indexed by the value is the mistake this module pins against, and it is
//! invisible to a test that only checks the two single-bit values.

use std::ffi::{c_int, c_void};
use std::net::SocketAddr;

use wz_capi_core::runtime::runtime_impl::TokioTime;
use wz_capi_core::runtime::zenoh_config::scout_multicast_socket;
use wz_capi_core::scouting::{run_scout, SCOUTING_TIMEOUT_DEFAULT_MS, SCOUTING_WHAT_DEFAULT};
use wz_session_core::session_zid::SessionZid;

use crate::abi::{
    z_loaned_hello_t, z_moved_closure_hello_t, z_moved_config_t, z_moved_hello_t,
    z_owned_closure_hello_t, z_owned_hello_t, z_owned_string_array_t, z_view_string_t, Handle,
};
use crate::config::ConfigState;
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::string::view_string_over;
use crate::string_array::StringArrayState;
use crate::zid::z_id_t;

/// What `z_scout` reads before it scouts: the roles asked for, the budget, the
/// group, and the asker its Scout names.
struct ScoutRequest {
    what: u8,
    budget_ms: u64,
    /// The group `scouting/multicast/address` names, read as the open reads it; `None` for text
    /// that names no socket, which the scout refuses rather than scouting elsewhere.
    group: Option<SocketAddr>,
    asker: Option<SessionZid>,
}

impl ScoutRequest {
    /// Read off the config and the options.
    ///
    /// A missing `options` falls back to the CONFIG, then to upstream's
    /// defaults — not straight to the defaults. `z_scout.c` passes its own
    /// options, but a program that configured `scouting/timeout` and passed
    /// NULL means that timeout, and ignoring it would scout for the wrong
    /// budget while looking like it worked.
    ///
    /// The Scout names no asker, whatever `id` the config states: the scout
    /// zenoh-c wraps writes `zid: None` (`zenoh/src/net/runtime/orchestrator.rs`
    /// @ `zid: None,`, in `pub(crate) async fn scout`). An `id` the reader
    /// refuses never reaches here: the config's insert doors refuse it.
    ///
    /// The group is the socket `scouting/multicast/address` names in zenoh's
    /// form, by the one reader the open's scouting reads the key with
    /// (`scout_multicast_socket`), and not a zenoh-pico locator.
    fn read(cfg: Option<&ConfigState>, options: Option<&z_scout_options_t>) -> Self {
        let cfg_get = |key: &str| -> Option<String> {
            cfg.and_then(|c| c.first(key)).map(|s| s.trim().to_string())
        };
        let (what, budget_ms) = match options {
            Some(options) => (options.what as u8, options.timeout_ms),
            None => (
                SCOUTING_WHAT_DEFAULT,
                cfg_get(crate::config::SCOUTING_TIMEOUT_KEY)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(SCOUTING_TIMEOUT_DEFAULT_MS),
            ),
        };
        Self {
            what,
            budget_ms,
            group: scout_multicast_socket(cfg_get(crate::config::MULTICAST_ADDRESS_KEY).as_deref())
                .ok(),
            asker: None,
        }
    }
}

/// The clock a scout's window is timed by, and the hold that keeps it read: the time base the
/// scout's config names (`wz_capi_c_config_time_base`), which the window then runs on as a session
/// opened from that config does, or the system's clock and no hold. A window is a deadline of its
/// own, and a program that runs its sessions on its time runs their discovery on it too.
#[cfg(feature = "time-base")]
fn window_clock(
    cfg: Option<&ConfigState>,
) -> (
    TokioTime,
    Option<wz_capi_core::runtime::time_base::TimeBaseHold>,
) {
    let held = cfg.and_then(|cfg| cfg.time_base.clone());
    let clock = match &held {
        Some(time_base) => TokioTime::on_time_base(time_base.time()),
        None => TokioTime::new(),
    };
    (clock, held)
}

/// `Z_WHATAMI_ROUTER` = 1.
pub const Z_WHATAMI_ROUTER: c_int = 1;
/// `Z_WHATAMI_PEER` = 2.
pub const Z_WHATAMI_PEER: c_int = 2;
/// `Z_WHATAMI_CLIENT` = 4.
pub const Z_WHATAMI_CLIENT: c_int = 4;

/// The three roles as DATA symbols, which zenoh-c exports beside the `z_whatami_t` enum
/// (`zenoh_commons.h`: `extern const unsigned int Z_ROUTER`, `Z_PEER`, `Z_CLIENT`). A program
/// that names them without the enum links against these, and a shared library that lacks them
/// leaves it with an undefined reference; the values are the bits of the role mask above.
#[no_mangle]
pub static Z_ROUTER: std::ffi::c_uint = Z_WHATAMI_ROUTER as std::ffi::c_uint;
#[no_mangle]
pub static Z_PEER: std::ffi::c_uint = Z_WHATAMI_PEER as std::ffi::c_uint;
#[no_mangle]
pub static Z_CLIENT: std::ffi::c_uint = Z_WHATAMI_CLIENT as std::ffi::c_uint;

/// zenoh-c `z_scout_options_t` (`zenoh_commons.h:1115-1125`) — 16 bytes.
#[repr(C)]
pub struct z_scout_options_t {
    /// The scouting budget in milliseconds.
    pub timeout_ms: u64,
    /// Which roles to scout for — a BITMASK (`z_what_t`).
    pub what: c_int,
}

const _: () = {
    assert!(std::mem::size_of::<z_scout_options_t>() == 16);
    assert!(std::mem::align_of::<z_scout_options_t>() == 8);
};

/// Fill default scout options (zenoh-c `z_scout_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_scout_options_default(this_: *mut z_scout_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_scout_options_t {
            timeout_ms: SCOUTING_TIMEOUT_DEFAULT_MS,
            what: c_int::from(SCOUTING_WHAT_DEFAULT),
        }
    };
}

/// Render a `whatami` bitmask as a static view string (zenoh-c
/// `z_whatami_to_view_string`).
///
/// The strings are `'static`, so the view borrows nothing the caller can
/// outlive.
///
/// # Safety
/// `str_out` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_whatami_to_view_string(
    whatami: c_int,
    str_out: *mut z_view_string_t,
) -> ZResult {
    guarded(|| {
        if str_out.is_null() {
            return Z_ENULL;
        }
        // Written before the lookup so an unknown mask leaves an empty string
        // rather than a stale stack value.
        // SAFETY: the caller's contract.
        unsafe { *str_out = z_view_string_t::null_value() };
        // Indexed by the MASK, so the combinations render as combinations. A
        // list indexed by role ordinal would print "client" for router|peer.
        let text = match whatami {
            1 => "router",
            2 => "peer",
            3 => "router|peer",
            4 => "client",
            5 => "router|client",
            6 => "peer|client",
            7 => "router|peer|client",
            _ => return Z_EINVAL,
        };
        // SAFETY: the caller's contract; `text` is `'static`.
        unsafe { *str_out = view_string_over(text) };
        Z_OK
    })
}

/// Behind a hello handle: one discovered peer.
#[repr(C)]
pub(crate) struct HelloState {
    /// This state's own address, set once it sits where it stays: the first word a loaned
    /// pointer names (`crate::loan_at`), so a pointer to the state and a pointer to an owned
    /// hello that holds it both read back as this state.
    me: usize,
    zid: z_id_t,
    whatami: c_int,
    locators: Vec<String>,
}

impl HelloState {
    fn new(zid: z_id_t, whatami: c_int, locators: Vec<String>) -> Self {
        Self {
            me: 0,
            zid,
            whatami,
            locators,
        }
    }

    /// Record the address this state is at. Call it once the state is where it stays.
    fn bind(&mut self) {
        self.me = self as *const HelloState as usize;
    }
}

/// Read the [`HelloState`] behind a loaned hello.
///
/// # Safety
/// `this_` must be null or a valid loaned hello whose handle is live.
unsafe fn hello_state<'a>(this_: *const z_loaned_hello_t) -> Option<&'a HelloState> {
    // SAFETY: the caller's contract — the first word at `this_` is the state's address, whether
    // `this_` is the state or the owned hello that holds it (`crate::loan_at`).
    let at = unsafe { crate::loan_at::state_addr(this_ as *const c_void) };
    if at == 0 {
        return None;
    }
    // SAFETY: a live `HelloState` this crate owns.
    Some(unsafe { &*(at as *const HelloState) })
}

/// The discovered peer's zid (zenoh-c `z_hello_zid`).
///
/// # Safety
/// `this_` must be null or a live loaned hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_zid(this_: *const z_loaned_hello_t) -> z_id_t {
    guard_val(z_id_t::empty(), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { hello_state(this_) }.map_or_else(z_id_t::empty, |s| s.zid)
    })
}

/// The discovered peer's role (zenoh-c `z_hello_whatami`).
///
/// # Safety
/// `this_` must be null or a live loaned hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_whatami(this_: *const z_loaned_hello_t) -> c_int {
    guard_val(Z_WHATAMI_PEER, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { hello_state(this_) }.map_or(Z_WHATAMI_PEER, |s| s.whatami)
    })
}

/// The discovered peer's advertised locators (zenoh-c `z_hello_locators`).
///
/// Writes an OWNED array the caller drops, rather than a borrow: `z_scout.c`
/// reads the locators inside the callback and drops them there, but nothing in
/// the ABI stops it from keeping them, and a borrow would dangle the moment the
/// callback returned.
///
/// # Safety
/// `this_` must be null or a live loaned hello; `locators_out` must be null or
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_hello_locators(
    this_: *const z_loaned_hello_t,
    locators_out: *mut z_owned_string_array_t,
) {
    guard_val((), || {
        if locators_out.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *locators_out = z_owned_string_array_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        let locators = match unsafe { hello_state(this_) } {
            Some(state) => state.locators.clone(),
            None => Vec::new(),
        };
        let handle = Box::into_raw(Box::new(StringArrayState::from_strings(&locators))) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *locators_out = z_owned_string_array_t::from_handle(handle) };
    });
}

/// Borrow an owned hello (zenoh-c `z_hello_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_loan(this_: *const z_owned_hello_t) -> *const z_loaned_hello_t {
    this_ as *const z_loaned_hello_t
}

/// `true` iff the owned hello holds a live state (zenoh-c
/// `z_internal_hello_check`).
///
/// # Safety
/// `this_` must be null or a valid owned hello.
#[no_mangle]
pub unsafe extern "C" fn z_internal_hello_check(this_: *const z_owned_hello_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned hello (zenoh-c `z_internal_hello_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned hello.
#[no_mangle]
pub unsafe extern "C" fn z_internal_hello_null(this_: *mut z_owned_hello_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_hello_t::null_value() };
    }
}

// --- R311y568: the hello's mutable loan + the owned-copy pair ---------------

/// Mutably borrow an owned hello (zenoh-c `z_hello_loan_mut`).
///
/// A CAST, like its immutable twin: owned and loaned hello share one layout with
/// the handle at offset 0, which is what lets `hello_state` serve both.
///
/// # Safety
/// `this_` must be null or a valid owned hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_loan_mut(this_: *mut z_owned_hello_t) -> *mut z_loaned_hello_t {
    this_ as *mut z_loaned_hello_t
}

/// Deep-copy a borrowed hello into an owned one (zenoh-c `z_hello_clone`).
///
/// The reason a hello NEEDS an owned copy: `z_scout.c` reads inside the callback,
/// but nothing in the ABI stops a program from keeping the peer's identity, and
/// the borrow it was handed dies when the callback returns — the same argument
/// [`z_hello_locators`] already makes for handing back an OWNED locator array
/// rather than a view.
///
/// # Safety
/// `dst` must be null or valid and writable; `this_` must be null or a live
/// loaned hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_clone(dst: *mut z_owned_hello_t, this_: *const z_loaned_hello_t) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // The gravestone first, so cloning a null hello yields an empty owned
        // value rather than leaving a stale stack one.
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_hello_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        let Some(state) = (unsafe { hello_state(this_) }) else {
            return;
        };
        let mut copy = Box::new(HelloState::new(
            state.zid,
            state.whatami,
            state.locators.clone(),
        ));
        copy.bind();
        let handle = Box::into_raw(copy) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_hello_t::from_handle(handle) };
    });
}

/// Take ownership of a mutably borrowed hello (zenoh-c
/// `z_hello_take_from_loaned`).
///
/// A MOVE out of an owned hello, a COPY out of a callback's argument, for the reason spelled out
/// at [`crate::sample::z_sample_take_from_loaned`]: the loaned pointer names either a live owned
/// value, which is emptied, or a callback frame's state, which is copied (`crate::loan_at`).
///
/// # Safety
/// `dst` must be null or valid and writable; `src` must be null, a live owned hello or a live
/// loaned hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_take_from_loaned(
    dst: *mut z_owned_hello_t,
    src: *mut z_loaned_hello_t,
) {
    if dst.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    match unsafe { crate::loan_at::take_slot(src as *mut c_void, z_owned_hello_t::null_value()) } {
        Some(handle) => {
            // SAFETY: the caller's contract — `dst` is writable. The word moved is not followed.
            unsafe { *dst = z_owned_hello_t::from_handle(handle as Handle) }
        }
        // SAFETY: the caller's contract, delegated.
        None => unsafe { z_hello_clone(dst, src as *const z_loaned_hello_t) },
    }
}

/// Free an owned hello (zenoh-c `z_hello_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_drop(this_: *mut z_moved_hello_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<HelloState>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut HelloState) });
            unsafe { (*this_)._this = z_owned_hello_t::null_value() };
        }
        Z_OK
    });
}

/// Construct a hello closure from its parts (zenoh-c `z_closure_hello`).
///
/// # Safety
/// `this_` must be valid and writable; `call` / `drop` must be null or valid C
/// function pointers.
#[no_mangle]
pub unsafe extern "C" fn z_closure_hello(
    this_: *mut z_owned_closure_hello_t,
    call: crate::abi::z_closure_hello_callback_t,
    drop: crate::abi::z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_closure_hello_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Drop a hello closure that was never used (zenoh-c `z_closure_hello_drop`).
///
/// # Safety
/// `closure_` must be null or a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_hello_drop(closure_: *mut z_moved_closure_hello_t) {
    let _ = guarded(|| {
        if closure_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*closure_)._this };
        if let Some(dropfn) = owned.drop {
            let ctx = owned.context;
            // SAFETY: upstream's contract — drop runs once; unwinds are caught.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
        *owned = z_owned_closure_hello_t::null_value();
        Z_OK
    });
}

/// Scout the network for peers (zenoh-c `z_scout`), consuming the config and
/// the closure.
///
/// BLOCKS for the whole budget, which is upstream's contract: `z_scout.c` calls
/// it and then prints its summary line, so returning early would reorder that
/// program's output.
///
/// The closure's `drop` runs exactly ONCE, AFTER the last callback — that is the
/// signal `z_scout.c` prints "Dropping scout" on.
///
/// # Safety
/// `config` must be null or a valid moved config, which is consumed;
/// `callback` must be null or a valid moved closure, which is consumed;
/// `options` must be null or a valid scout options struct.
#[no_mangle]
pub unsafe extern "C" fn z_scout(
    config: *mut z_moved_config_t,
    callback: *mut z_moved_closure_hello_t,
    options: *const z_scout_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // Take the closure APART first, exactly as upstream does: the parts are
        // lifted out and the slot nulled, so the `drop` this function runs at
        // the end cannot also be run by a later `z_closure_hello_drop` on the
        // same storage.
        // SAFETY: the caller's contract.
        let (user_call, user_drop, user_ctx) = unsafe {
            let owned = &mut (*callback)._this;
            let parts = (owned.call, owned.drop, owned.context);
            *owned = z_owned_closure_hello_t::null_value();
            parts
        };
        // The user's drop is armed on EVERY exit path below — an early return
        // that skipped it would leave the C program waiting for a completion
        // signal that never comes.
        let run_drop = || {
            if let Some(dropfn) = user_drop {
                // SAFETY: upstream's contract — drop runs once; unwinds caught.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                    dropfn(user_ctx);
                }));
            }
        };

        // Consume the config: read what we need, then release the handle.
        let cfg: Option<Box<ConfigState>> = if config.is_null() {
            None
        } else {
            // SAFETY: the caller's contract.
            unsafe {
                let handle = (*config)._this.handle;
                (*config)._this = crate::abi::z_owned_config_t::null_value();
                if handle.is_null() {
                    None
                } else {
                    Some(Box::from_raw(handle as *mut ConfigState))
                }
            }
        };
        // SAFETY: the caller's contract: `options` is null or a valid struct.
        let request = ScoutRequest::read(cfg.as_deref(), unsafe { options.as_ref() });
        // The window's clock. The hold keeps a time base the config names read for the whole
        // window, after the config itself is gone.
        #[cfg(feature = "time-base")]
        let (clock, _held) = window_clock(cfg.as_deref());
        #[cfg(not(feature = "time-base"))]
        let clock = TokioTime::new();
        drop(cfg);
        let ScoutRequest {
            what,
            budget_ms,
            group,
            asker,
        } = request;

        let Some(group) = group else {
            run_drop();
            return Z_EINVAL;
        };

        // The scout's snapshot, resolved as an open resolves its own: the scout reads no node
        // document of its config, so the open's resolution of none.
        let policy = wz_capi_core::open_plan::resolve_policy(None);
        run_scout(
            clock,
            group.ip(),
            group.port(),
            what,
            asker,
            budget_ms,
            &policy,
            |hello| {
                let Some(call) = user_call else {
                    return;
                };
                let mut state = HelloState::new(
                    z_id_t::from_wire(&hello.zid),
                    hello
                        .whatami
                        .map_or(Z_WHATAMI_PEER, |w| c_int::from(w.to_api())),
                    hello.locators.clone(),
                );
                // Bound where it stays: the callback's argument is the state itself, the first word
                // of which is its address (`crate::loan_at`).
                state.bind();
                let loaned = &state as *const HelloState as *mut z_loaned_hello_t;
                // SAFETY: `call` is the C callback and `state` outlives it; the
                // borrowed hello is valid only for its duration. An unwind across
                // the C boundary is UB, so it is caught.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                    call(loaned, user_ctx);
                }));
            },
        );

        run_drop();
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::z_moved_string_array_t;
    use crate::string_array::{
        z_string_array_drop, z_string_array_get, z_string_array_len, z_string_array_loan,
    };

    /// A scout names no asker, with an `id` in its config and without one, as
    /// the scout zenoh-c wraps writes `zid: None` whatever its config states
    /// (`zenoh/src/net/runtime/orchestrator.rs` @ `zid: None,`, in
    /// `pub(crate) async fn scout`). The config is built through the C doors,
    /// so the stated `id` is one the insert accepted.
    #[test]
    fn a_scout_names_no_asker_whatever_id_its_config_states() {
        use crate::abi::{z_moved_config_t, z_owned_config_t};
        use crate::config::{
            config_state, z_config_default, z_config_drop, z_config_loan_mut,
            zc_config_insert_json5,
        };

        let asker_of = |id: Option<&str>| {
            // SAFETY: a zeroed owned config is the gravestone this ABI defines.
            let mut cfg: z_owned_config_t = unsafe { std::mem::zeroed() };
            // SAFETY: a writable owned slot.
            assert_eq!(unsafe { z_config_default(&mut cfg) }, Z_OK);
            if let Some(id) = id {
                let key = std::ffi::CString::new("id").expect("no NUL");
                let value = std::ffi::CString::new(format!("\"{id}\"")).expect("no NUL");
                // SAFETY: a live config and two NUL-terminated strings.
                let rc = unsafe {
                    zc_config_insert_json5(
                        z_config_loan_mut(&mut cfg),
                        key.as_ptr(),
                        value.as_ptr(),
                    )
                };
                assert_eq!(rc, Z_OK, "the insert takes the id `{id}`");
            }
            // SAFETY: a live config.
            let state = unsafe { config_state(z_config_loan_mut(&mut cfg)) }.expect("a config");
            let asker = ScoutRequest::read(Some(&*state), None).asker;
            // SAFETY: the owned config is live and dropped once.
            unsafe {
                z_config_drop((&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>())
            };
            asker
        };
        assert!(asker_of(None).is_none(), "no id stated");
        assert!(asker_of(Some("c11e47c11e49")).is_none(), "an id stated");
        assert!(ScoutRequest::read(None, None).asker.is_none(), "no config");
    }

    /// The group is the socket the config's `scouting/multicast/address` names in zenoh's form,
    /// upstream's default where it names none, and no group (which `z_scout` refuses with
    /// `Z_EINVAL`) for a zenoh-pico locator or a group with no port. The config is built through
    /// the C doors, which take every one of these texts.
    #[test]
    fn a_scout_reads_its_group_as_the_socket_zenohs_config_names() {
        use crate::abi::{z_moved_config_t, z_owned_config_t};
        use crate::config::{
            config_state, z_config_default, z_config_drop, z_config_loan_mut,
            zc_config_insert_json5,
        };

        let group_of = |address: Option<&str>| {
            // SAFETY: a zeroed owned config is the gravestone this ABI defines.
            let mut cfg: z_owned_config_t = unsafe { std::mem::zeroed() };
            // SAFETY: a writable owned slot.
            assert_eq!(unsafe { z_config_default(&mut cfg) }, Z_OK);
            if let Some(address) = address {
                let key = std::ffi::CString::new("scouting/multicast/address").expect("no NUL");
                let value = std::ffi::CString::new(format!("\"{address}\"")).expect("no NUL");
                // SAFETY: a live config and two NUL-terminated strings.
                let rc = unsafe {
                    zc_config_insert_json5(
                        z_config_loan_mut(&mut cfg),
                        key.as_ptr(),
                        value.as_ptr(),
                    )
                };
                assert_eq!(rc, Z_OK, "the insert takes `{address}`");
            }
            // SAFETY: a live config.
            let state = unsafe { config_state(z_config_loan_mut(&mut cfg)) }.expect("a config");
            let group = ScoutRequest::read(Some(&*state), None).group;
            // SAFETY: the owned config is live and dropped once.
            unsafe {
                z_config_drop((&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>())
            };
            group
        };
        let socket = |text: &str| text.parse::<SocketAddr>().expect("a socket");
        let default = Some(socket("224.0.0.224:7446"));
        assert_eq!(group_of(None), default, "upstream's default");
        assert_eq!(ScoutRequest::read(None, None).group, default, "no config");
        assert_eq!(
            group_of(Some("224.0.0.231:7493")),
            Some(socket("224.0.0.231:7493"))
        );
        assert_eq!(
            group_of(Some("[ff05::231]:7493")),
            Some(socket("[ff05::231]:7493"))
        );
        assert_eq!(
            group_of(Some("udp/224.0.0.231:7493")),
            None,
            "a zenoh-pico locator"
        );
        assert_eq!(group_of(Some("224.0.0.231")), None, "a group with no port");
    }

    /// The whatami map is an INDEXED BITMASK: 3 is "router|peer", not a third
    /// role. A table indexed by role ordinal would print "client" here, and a
    /// test that only checked ROUTER and PEER could not tell the difference.
    #[test]
    fn whatami_renders_the_bitmask_combinations() {
        let render = |w: c_int| -> Option<String> {
            let mut out = z_view_string_t::null_value();
            // SAFETY: `out` is a live local.
            let rc = unsafe { z_whatami_to_view_string(w, &mut out) };
            if rc != Z_OK {
                return None;
            }
            // SAFETY: `out` now views a `'static` string.
            Some(unsafe {
                String::from_utf8_lossy(std::slice::from_raw_parts(out.ptr, out.len)).into_owned()
            })
        };
        assert_eq!(render(1).as_deref(), Some("router"));
        assert_eq!(render(2).as_deref(), Some("peer"));
        assert_eq!(render(3).as_deref(), Some("router|peer"));
        assert_eq!(render(4).as_deref(), Some("client"));
        assert_eq!(render(7).as_deref(), Some("router|peer|client"));
        assert_eq!(
            render(0),
            None,
            "0 is not a role and must not render as one"
        );
        assert_eq!(render(8), None);
    }

    /// The defaults are upstream's: a one-second budget scouting for
    /// ROUTER|PEER.
    #[test]
    fn the_scout_options_default_is_one_second_router_peer() {
        let mut opts = z_scout_options_t {
            timeout_ms: 0,
            what: 0,
        };
        // SAFETY: `opts` is a live local.
        unsafe { z_scout_options_default(&mut opts) };
        assert_eq!(opts.timeout_ms, 1000);
        assert_eq!(opts.what, 3);
    }

    /// Every accessor answers a NULL hello without dereferencing it.
    #[test]
    fn the_hello_accessors_answer_null_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            assert_eq!(z_hello_whatami(std::ptr::null()), Z_WHATAMI_PEER);
            let mut arr = z_owned_string_array_t::from_handle(1 as Handle);
            z_hello_locators(std::ptr::null(), &mut arr);
            assert_eq!(z_string_array_len(z_string_array_loan(&arr)), 0);
            let mut moved = z_moved_string_array_t { _this: arr };
            z_string_array_drop(&mut moved);
            assert!(!z_internal_hello_check(std::ptr::null()));
            z_hello_drop(std::ptr::null_mut());
            assert_eq!(z_string_array_len(std::ptr::null()), 0);
            assert!(z_string_array_get(std::ptr::null(), 0).is_null());
        }
    }
}
