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

use wz_capi_core::drive::ConfiguredZid;
use wz_capi_core::scouting::{
    fresh_scout_zid, parse_multicast_locator, run_scout, MULTICAST_LOCATOR_DEFAULT,
    SCOUTING_TIMEOUT_DEFAULT_MS, SCOUTING_WHAT_DEFAULT,
};

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

/// The zid a scout announces: the id the config states, in the form zenoh puts
/// on the wire, or a fresh one when it states none.
///
/// It reads the text the way [`ConfiguredZid`] does, which is the way `z_open`
/// reads it, so the scouter a responder logs is the node a later open stands on.
/// This used to read it PER BYTE in the order written, which is the reverse of
/// zenoh's reading (`c11e47c11e49` is the bytes `49 1e c1 47 1e c1`), and it
/// refused an odd number of digits that zenoh accepts.
fn announced_zid(configured: Option<&str>) -> Vec<u8> {
    configured
        .and_then(ConfiguredZid::from_zenoh_text)
        .map(|zid| zid.wire().to_vec())
        .unwrap_or_else(fresh_scout_zid)
}

/// `Z_WHATAMI_ROUTER` = 1.
pub const Z_WHATAMI_ROUTER: c_int = 1;
/// `Z_WHATAMI_PEER` = 2.
pub const Z_WHATAMI_PEER: c_int = 2;
/// `Z_WHATAMI_CLIENT` = 4.
pub const Z_WHATAMI_CLIENT: c_int = 4;

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
pub(crate) struct HelloState {
    zid: z_id_t,
    whatami: c_int,
    locators: Vec<String>,
}

/// Read the [`HelloState`] behind a loaned hello.
///
/// # Safety
/// `this_` must be null or a valid loaned hello whose handle is live.
unsafe fn hello_state<'a>(this_: *const z_loaned_hello_t) -> Option<&'a HelloState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `HelloState` this crate owns for the callback's duration.
    Some(unsafe { &*(handle as *const HelloState) })
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
        let handle = Box::into_raw(Box::new(HelloState {
            zid: state.zid,
            whatami: state.whatami,
            locators: state.locators.clone(),
        })) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_hello_t::from_handle(handle) };
    });
}

/// Take ownership of a mutably borrowed hello (zenoh-c
/// `z_hello_take_from_loaned`).
///
/// A COPY rather than a move, for the reason spelled out at
/// [`crate::sample::z_sample_take_from_loaned`]: the loaned pointer's storage
/// belongs to a callback frame or to a live owned value, and nothing in the
/// pointer says which.
///
/// # Safety
/// `dst` must be null or valid and writable; `src` must be null or a live loaned
/// hello.
#[no_mangle]
pub unsafe extern "C" fn z_hello_take_from_loaned(
    dst: *mut z_owned_hello_t,
    src: *mut z_loaned_hello_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_hello_clone(dst, src as *const z_loaned_hello_t) };
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
        let cfg_get = |key: &str| -> Option<String> {
            cfg.as_ref()
                .and_then(|c| c.first(key))
                .map(|s| s.trim().to_string())
        };

        // A NULL options pointer falls back to the CONFIG, then to upstream's
        // defaults — not straight to the defaults. `z_scout.c` passes its own
        // options, but a program that configured `scouting/timeout` and passed
        // NULL means that timeout, and ignoring it would scout for the wrong
        // budget while looking like it worked.
        let (what, budget_ms) = if options.is_null() {
            (
                SCOUTING_WHAT_DEFAULT,
                cfg_get(crate::config::SCOUTING_TIMEOUT_KEY)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(SCOUTING_TIMEOUT_DEFAULT_MS),
            )
        } else {
            // SAFETY: the caller's contract.
            unsafe { ((*options).what as u8, (*options).timeout_ms) }
        };
        let locator = cfg_get(crate::config::MULTICAST_LOCATOR_KEY)
            .unwrap_or_else(|| MULTICAST_LOCATOR_DEFAULT.into());
        // The Scout announces the identity this node would open a session with,
        // so a responder that logs the scouter names the same zid a later
        // InitSyn would carry.
        let zid = announced_zid(cfg_get(crate::config::SESSION_ZID_KEY).as_deref());
        drop(cfg);

        let Some((group, port)) = parse_multicast_locator(&locator) else {
            run_drop();
            return Z_EINVAL;
        };

        run_scout(group, port, what, zid, budget_ms, |hello| {
            let Some(call) = user_call else {
                return;
            };
            let state = HelloState {
                zid: z_id_t::from_wire(&hello.zid),
                whatami: hello
                    .whatami
                    .map_or(Z_WHATAMI_PEER, |w| c_int::from(w.to_api())),
                locators: hello.locators.clone(),
            };
            let mut loaned =
                z_loaned_hello_t::from_handle(&state as *const HelloState as *mut c_void);
            // SAFETY: `call` is the C callback and `state` outlives it; the
            // borrowed hello is valid only for its duration. An unwind across
            // the C boundary is UB, so it is caught.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                call(&mut loaned as *mut z_loaned_hello_t, user_ctx);
            }));
        });

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

    /// A scout announces the id its config states in zenoh's reading of it.
    ///
    /// The expected bytes are derived here from the documented reading and not
    /// from [`ConfiguredZid`]: the text is a `u128` in big-endian hex and the wire
    /// carries the id's little-endian bytes with the trailing zeros trimmed, so a
    /// renderer or a parser that read the text per byte in written order would
    /// pass the reversed bytes and fail on the first assertion. The odd-digit id
    /// is the second: zenoh accepts `abc`, and the per-byte reader refused it.
    #[test]
    fn a_scout_announces_the_id_its_config_states_as_zenoh_reads_it() {
        let read = |text: &str| -> Vec<u8> {
            let id = u128::from_str_radix(text, 16).expect("hex");
            let mut bytes = id.to_le_bytes().to_vec();
            while bytes.last() == Some(&0) {
                bytes.pop();
            }
            bytes
        };
        for text in [
            "c11e47c11e49",
            "abc",
            "1",
            "ffffffffffffffffffffffffffffffff",
        ] {
            assert_eq!(
                announced_zid(Some(text)),
                read(text),
                "the announced zid for `{text}`"
            );
        }
        assert_eq!(announced_zid(Some("c11e47c11e49")).len(), 6);

        // No id stated: a fresh sixteen-byte one, and two calls differ.
        let (a, b) = (announced_zid(None), announced_zid(None));
        assert_eq!((a.len(), b.len()), (16, 16));
        assert_ne!(a, b, "a scout with no configured id must not reuse one");
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
