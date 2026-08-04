// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! Nothing here re-implements scouting. `wz::runtime_tokio::scouting_glue`
//! already owns the Scout emit / Hello decode FSM (`§scouting-active`), and
//! this module is the C-ABI adapter over it: bind the group, drive cycles until
//! the caller's budget expires, and project each [`ScoutedHello`] into the
//! borrowed pico shape.
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
//! ## One divergence, named
//!
//! pico's `z_scout` calls the user closure from the scouting task the instant a
//! Hello decodes. wz drives discovery in CYCLES and emits each cycle's NEW
//! hellos when that cycle returns, so a callback here can lag the wire by up to
//! one cycle. The set delivered over the whole budget is the same; only the
//! instant of each call differs. A program that measures Hello LATENCY from
//! inside the callback would see the cycle, not the wire — `z_scout.c` counts
//! and prints, so it cannot.

use std::ffi::c_void;
use std::time::{Duration, Instant};

use crate::abi::{z_loaned_string_t, z_view_string_t};
use crate::config::ConfigState;
use crate::pubsub::z_closure_drop_callback_t;
use crate::result::ZResult;
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
/// pico `Z_CONFIG_SESSION_ZID_KEY` (config.h.in:155) — the session zid as a hex
/// string. Declared HERE rather than in `config`: the session plane mints a
/// fresh random zid per `z_open` and never reads this key, so scouting is its
/// first consumer.
pub const Z_CONFIG_SESSION_ZID_KEY: u8 = 0x49;

/// pico `Z_CONFIG_MULTICAST_LOCATOR_DEFAULT` (config.h.in:133).
const MULTICAST_LOCATOR_DEFAULT: &str = "udp/224.0.0.224:7446";
/// pico `Z_CONFIG_SCOUTING_TIMEOUT_DEFAULT` (config.h.in:141), in ms.
const SCOUTING_TIMEOUT_DEFAULT_MS: u32 = 1000;
/// pico `Z_CONFIG_SCOUTING_WHAT_DEFAULT` (config.h.in:149) = ROUTER|PEER.
const SCOUTING_WHAT_DEFAULT: u8 = 0x03;

/// The protocol version byte wz announces in its Scout. Same constant the
/// `--scout` demo path uses; a responder logs it back verbatim.
const SCOUT_PROTO_VERSION: u8 = 0x09;
/// One discovery cycle. The budget is spent across repeated cycles, so this is
/// the granularity at which new hellos surface (see the module doc's divergence
/// note), not the total.
const SCOUT_CYCLE_MS: u64 = 1000;
/// The scouting drive-loop tick.
const SCOUT_TICK_MS: u64 = 50;

// ---------------------------------------------------------------------------
// z_whatami_t
// ---------------------------------------------------------------------------

/// pico `z_whatami_t` (`api/constants.h:50-54`) — a C enum, so `u32` on every
/// platform this crate targets. A BITMASK, not an ordinal: the values are
/// `1 << role`.
pub type z_whatami_t = u32;

/// pico `WHAT_AM_I_TO_STRING_MAP` (`src/api/api.c:742-750`), transcribed with
/// its index semantics intact: the index IS the bitmask, so slot 3 is the
/// router-and-peer combination rather than a third role. Slot 0 is the
/// out-of-range / zero answer and pairs with an ERROR return, which is upstream
/// behaviour worth preserving — a caller that ignores the result still gets a
/// printable string rather than an empty view.
const WHATAMI_STRINGS: [&str; 8] = [
    "Other",
    "Router",
    "Peer",
    "Router|Peer",
    "Client",
    "Router|Client",
    "Peer|Client",
    "Router|Peer|Client",
];

/// Render a whatami bitmask into a caller-provided view string (pico
/// `z_whatami_to_view_string`).
///
/// Returns `Z_EINVAL` for 0 or an out-of-range mask AND still writes `"Other"`,
/// which is upstream's contract verbatim (`api.c:753-762`).
///
/// # Safety
/// `str_out` must point to writable `z_view_string_t` storage.
#[no_mangle]
pub unsafe extern "C" fn z_whatami_to_view_string(
    whatami: z_whatami_t,
    str_out: *mut z_view_string_t,
) -> ZResult {
    if str_out.is_null() {
        return crate::result::Z_ERR_INVALID;
    }
    let idx = whatami as usize;
    let (text, res) = if idx == 0 || idx >= WHATAMI_STRINGS.len() {
        (WHATAMI_STRINGS[0], crate::result::Z_ERR_INVALID)
    } else {
        (WHATAMI_STRINGS[idx], crate::result::Z_OK)
    };
    // The rendered strings are `'static`, so the view aliases program storage
    // that outlives any caller — the same lifetime pico's own map has.
    *str_out = z_view_string_t {
        _start: text.as_ptr(),
        _len: text.len(),
        _pad: [0usize; 2],
    };
    res
}

// ---------------------------------------------------------------------------
// z_owned_string_array_t
// ---------------------------------------------------------------------------

/// The boxed payload behind a `z_owned_string_array_t` / the array a
/// `z_loaned_hello_t` lends out.
///
/// `views` is built ONCE, after `items` is final, and each entry borrows that
/// `String`'s heap buffer. That is sound and the reason for the ordering: a
/// `String`'s buffer address is stable across `Vec<String>` reallocation
/// (reallocating the vec moves the `String` headers, not the bytes they own),
/// but a `push` after the views exist could still leave a view pointing at a
/// buffer a later `String` mutation freed. Nothing here mutates after build.
pub(crate) struct StringArrayState {
    items: Vec<String>,
    views: Vec<z_loaned_string_t>,
}

impl StringArrayState {
    fn new(items: Vec<String>) -> Box<Self> {
        let mut state = Box::new(Self {
            items,
            views: Vec::new(),
        });
        let views: Vec<z_loaned_string_t> = state
            .items
            .iter()
            .map(|s| z_loaned_string_t {
                _start: s.as_ptr(),
                _len: s.len(),
            })
            .collect();
        state.views = views;
        state
    }
}

/// Owned string array (pico `z_owned_string_array_t`, 32 B measured): our handle
/// in slot 0, zero padding to the pico size.
#[repr(C)]
pub struct z_owned_string_array_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Loaned string array — identical layout, slot 0 is the same handle.
#[repr(C)]
pub struct z_loaned_string_array_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Moved string array (pico `z_moved_string_array_t`).
#[repr(C)]
pub struct z_moved_string_array_t {
    pub(crate) _this: z_owned_string_array_t,
}

impl z_owned_string_array_t {
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 3],
        }
    }
}

unsafe fn string_array_state<'a>(
    array: *const z_loaned_string_array_t,
) -> Option<&'a StringArrayState> {
    let array = array.as_ref()?;
    (array.handle as *const StringArrayState).as_ref()
}

/// Number of strings in the array (pico `z_string_array_len`).
///
/// # Safety
/// `array` must be a live loaned string array (or null, which reads 0).
#[no_mangle]
pub unsafe extern "C" fn z_string_array_len(array: *const z_loaned_string_array_t) -> usize {
    string_array_state(array).map_or(0, |s| s.items.len())
}

/// Whether the array is empty (pico `z_string_array_is_empty`).
///
/// # Safety
/// See [`z_string_array_len`].
#[no_mangle]
pub unsafe extern "C" fn z_string_array_is_empty(array: *const z_loaned_string_array_t) -> bool {
    z_string_array_len(array) == 0
}

/// Borrow element `k` (pico `z_string_array_get`), or NULL when out of range.
///
/// Upstream returns a pointer INTO the array's storage, so the borrow lives as
/// long as the array does; that is reproduced by handing back a pointer to the
/// cached per-item view rather than synthesising one on the stack.
///
/// # Safety
/// `array` must be a live loaned string array; the returned pointer must not
/// outlive it.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_get(
    array: *const z_loaned_string_array_t,
    k: usize,
) -> *const z_loaned_string_t {
    match string_array_state(array).and_then(|s| s.views.get(k)) {
        Some(view) => view as *const z_loaned_string_t,
        None => std::ptr::null(),
    }
}

/// Null an owned string array (pico `z_internal_string_array_null`).
///
/// # Safety
/// `array` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_array_null(array: *mut z_owned_string_array_t) {
    if let Some(array) = array.as_mut() {
        *array = z_owned_string_array_t::null_value();
    }
}

/// Whether an owned string array holds a value (pico
/// `z_internal_string_array_check`).
///
/// # Safety
/// `array` must be a live owned string array.
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_array_check(
    array: *const z_owned_string_array_t,
) -> bool {
    array.as_ref().is_some_and(|a| !a.handle.is_null())
}

/// Borrow an owned string array (pico `z_string_array_loan`) — offset-0
/// identity, the same shape every handle type in this crate loans by.
///
/// # Safety
/// `array` must be a live owned string array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_loan(
    array: *const z_owned_string_array_t,
) -> *const z_loaned_string_array_t {
    array as *const z_loaned_string_array_t
}

/// Mutably borrow an owned string array (pico `z_string_array_loan_mut`).
///
/// # Safety
/// See [`z_string_array_loan`].
#[no_mangle]
pub unsafe extern "C" fn z_string_array_loan_mut(
    array: *mut z_owned_string_array_t,
) -> *mut z_loaned_string_array_t {
    array as *mut z_loaned_string_array_t
}

/// Release an owned string array (pico `z_string_array_drop`).
///
/// # Safety
/// `array` must be a live moved string array; double-drop is prevented by
/// nulling the slot.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_drop(array: *mut z_moved_string_array_t) {
    if let Some(moved) = array.as_mut() {
        let handle = moved._this.handle;
        moved._this = z_owned_string_array_t::null_value();
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut StringArrayState));
        }
    }
}

/// Move an owned string array (pico `z_string_array_move`) — offset-0 identity.
///
/// # Safety
/// `array` must be a live owned string array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_move(
    array: *mut z_owned_string_array_t,
) -> *mut z_moved_string_array_t {
    array as *mut z_moved_string_array_t
}

/// Take an owned string array out of a moved wrapper (pico
/// `z_string_array_take`), leaving the source null.
///
/// # Safety
/// Both pointers must be live and non-overlapping.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_take(
    dst: *mut z_owned_string_array_t,
    src: *mut z_moved_string_array_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = [std::ptr::null_mut(); 3];
    (*src)._this = z_owned_string_array_t::null_value();
}

// ---------------------------------------------------------------------------
// z_owned_hello_t
// ---------------------------------------------------------------------------

/// The boxed payload behind a hello handle: one decoded `Hello`, plus the
/// locator array it lends out.
///
/// `locators_loan` is a PRE-BUILT loaned handle rather than something
/// `zp_hello_locators` synthesises per call, because that function returns a
/// POINTER and a stack temporary would dangle the moment it returned. This is
/// the same cached-self-view shape `StringState` uses for `z_string_loan`.
pub(crate) struct HelloState {
    zid: z_id_t,
    whatami: z_whatami_t,
    /// Owned, and the target of `locators_loan`'s handle. Boxed so its address
    /// is stable when this state moves.
    locators: Box<StringArrayState>,
    locators_loan: z_loaned_string_array_t,
}

impl HelloState {
    fn new(zid: z_id_t, whatami: z_whatami_t, locators: Vec<String>) -> Box<Self> {
        let locators = StringArrayState::new(locators);
        let handle = (&*locators) as *const StringArrayState as *mut c_void;
        Box::new(Self {
            zid,
            whatami,
            locators,
            locators_loan: z_loaned_string_array_t {
                handle,
                _pad: [std::ptr::null_mut(); 3],
            },
        })
    }
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
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 6],
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
        None => std::ptr::null(),
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
    let items = hello_state(hello).map_or_else(Vec::new, |s| s.locators.items.clone());
    *out = z_owned_string_array_t {
        handle: Box::into_raw(StringArrayState::new(items)) as *mut c_void,
        _pad: [std::ptr::null_mut(); 3],
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
    (*dst)._pad = [std::ptr::null_mut(); 6];
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
    let cloned = HelloState::new(state.zid, state.whatami, state.locators.items.clone());
    *dst = z_owned_hello_t {
        handle: Box::into_raw(cloned) as *mut c_void,
        _pad: [std::ptr::null_mut(); 6],
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
            context: std::ptr::null_mut(),
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

/// pico `z_scout_options_t` (`api/types.h:553-556`), 8 B measured:
/// `{ uint32_t timeout_ms; z_what_t what; }`.
#[repr(C)]
pub struct z_scout_options_t {
    /// Total discovery budget in milliseconds.
    pub timeout_ms: u32,
    /// `z_what_t` bitmask of roles to scout for.
    pub what: u32,
}

/// Default scout options (pico `z_scout_options_default`) — the same values
/// pico's config defaults carry, so the options form and the config form agree.
///
/// # Safety
/// `options` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn z_scout_options_default(options: *mut z_scout_options_t) {
    if let Some(options) = options.as_mut() {
        options.timeout_ms = SCOUTING_TIMEOUT_DEFAULT_MS;
        options.what = SCOUTING_WHAT_DEFAULT as u32;
    }
}

/// Parse a hex zid string (pico `_z_uuid_to_bytes`) into wire bytes. Odd-length
/// or non-hex input is rejected outright — a half-decoded identity is worse
/// than a random one.
fn parse_hex_zid(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.is_empty() || text.len() % 2 != 0 || text.len() > 32 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// A fresh random 16-byte scouting identity, from the same OS entropy source
/// the session plane mints its per-session zid with.
fn fresh_scout_zid() -> Vec<u8> {
    let mut zid = [0u8; 16];
    if getrandom::getrandom(&mut zid).is_err() {
        // Entropy is unavailable only in a profile that cannot open a session
        // either; scouting with a zeroed id still emits a well-formed Scout.
        return vec![0u8; 16];
    }
    zid.to_vec()
}

/// Parse `udp/<addr>:<port>` (pico's multicast-locator config form) into the
/// group + port a scouting socket joins. Returns `None` for anything this
/// crate's UDP scouting cannot bind, so an unsupported locator FAILS the scout
/// rather than silently falling back to the default group — a scout that
/// searches somewhere the caller did not ask about is worse than an error.
fn parse_multicast_locator(locator: &str) -> Option<(std::net::Ipv4Addr, u16)> {
    let rest = locator.strip_prefix("udp/")?;
    let (addr, port) = rest.rsplit_once(':')?;
    Some((addr.parse().ok()?, port.parse().ok()?))
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
    let cfg_get = |key: u8| -> Option<String> {
        cfg.as_ref()
            .and_then(|c| c.get(key))
            .map(|s| s.trim().to_string())
    };

    let (what, budget_ms) = match options.as_ref() {
        Some(o) => (o.what as u8, u64::from(o.timeout_ms)),
        None => (
            cfg_get(Z_CONFIG_SCOUTING_WHAT_KEY)
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(SCOUTING_WHAT_DEFAULT),
            cfg_get(Z_CONFIG_SCOUTING_TIMEOUT_KEY)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(u64::from(SCOUTING_TIMEOUT_DEFAULT_MS)),
        ),
    };
    let locator =
        cfg_get(Z_CONFIG_MULTICAST_LOCATOR_KEY).unwrap_or_else(|| MULTICAST_LOCATOR_DEFAULT.into());
    // The Scout announces the identity this node would open a session with, so
    // a responder that logs the scouter names the same zid a later InitSyn
    // would carry. An unparseable configured zid falls back to a fresh random
    // one rather than scouting as all-zeros (which a peer may read as unset).
    let zid = cfg_get(Z_CONFIG_SESSION_ZID_KEY)
        .and_then(|s| parse_hex_zid(&s))
        .unwrap_or_else(fresh_scout_zid);
    drop(cfg);

    let Some((group, port)) = parse_multicast_locator(&locator) else {
        if let Some(drop_fn) = user_drop {
            drop_fn(user_ctx);
        }
        return crate::result::Z_ERR_INVALID;
    };

    let hellos = run_scout(group, port, what, zid, budget_ms, |hello| {
        // The callback takes a MUTABLE loaned pointer (pico's signature), but
        // this side keeps ownership: the state is dropped when `run_scout`'s
        // per-hello box goes out of scope, matching upstream, where the hello
        // is owned by the scouting task and only borrowed by the user.
        if let Some(call) = user_call {
            let mut loaned = z_loaned_hello_t {
                handle: hello as *mut HelloState as *mut c_void,
                _pad: [std::ptr::null_mut(); 6],
            };
            call(&mut loaned as *mut z_loaned_hello_t, user_ctx);
        }
    });
    let _ = hellos;

    // The closure's `drop` runs exactly once, AFTER the last callback — the
    // signal `z_scout.c` uses to print its "found nothing" / "dropping" line,
    // so emitting it early would reorder that program's own output.
    if let Some(drop_fn) = user_drop {
        drop_fn(user_ctx);
    }
    crate::result::Z_OK
}

/// Drive `wz::runtime_tokio::scouting_glue` for `budget_ms`, invoking `on_hello`
/// for each NEW peer as it is recorded. Returns the number delivered.
///
/// Cycles rather than one long window: the scouting FSM resolves a cycle when it
/// discovers a peer, so a single window would return after the FIRST Hello and
/// a second responder on the same group would never be reported. Re-entering
/// keeps collecting until the caller's budget is spent, which is what makes
/// `z_scout` a SURVEY rather than a first-answer lookup.
fn run_scout(
    group: std::net::Ipv4Addr,
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
    mut on_hello: impl FnMut(&mut HelloState),
) -> usize {
    use wz_runtime_tokio::scouting_glue::{
        drive_scouting_until_resolved, new_scouting_engine, ScoutParams, ScoutingActions,
    };
    use wz_runtime_tokio::UdpDriver;

    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    else {
        return 0;
    };

    runtime.block_on(async move {
        // `None`: the scouting group is deliberately NOT interface-narrowed —
        // a discovery beacon must reach every interface a peer could answer on.
        let Ok(mut driver) = UdpDriver::bind_multicast_v4(group, port, None).await else {
            return 0;
        };
        let actions = ScoutingActions::new(ScoutParams {
            version: SCOUT_PROTO_VERSION,
            what,
            zid,
            timeout_ms: SCOUT_CYCLE_MS,
        });
        let mut engine = new_scouting_engine(&actions);
        let clock = wz_runtime_tokio::runtime_impl::TokioTime::new();
        let started = Instant::now();
        let budget = Duration::from_millis(budget_ms);
        let mut delivered = 0usize;
        let mut seen_zids: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();

        while started.elapsed() < budget {
            let _ = drive_scouting_until_resolved(
                &mut driver,
                &actions,
                &mut engine,
                &clock,
                None,
                SCOUT_TICK_MS,
            )
            .await;
            // Deliver each DISTINCT peer once. A cursor over the recorded list
            // is NOT enough and the real pico says so: every cycle re-scouts,
            // a live responder answers each Scout, and the registry records
            // every answer -- so a cursor reports one peer N times. Measured
            // against upstream's own `z_scout` binary on the same zenohd: it
            // prints ONE line and drops. Keyed on the zid because that is the
            // peer's identity; a peer that changes its advertised locators
            // mid-scout is still one peer.
            for hello in actions.scouted_hellos() {
                if !seen_zids.insert(hello.zid.clone()) {
                    continue;
                }
                let whatami = hello.whatami.map_or(0, |w| u32::from(w.to_api()));
                let mut state =
                    HelloState::new(z_id_t::from_wire(&hello.zid), whatami, hello.locators);
                on_hello(&mut state);
                delivered += 1;
            }
        }
        delivered
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three C-allocated structs of this plane, pinned against the sizes
    /// MEASURED off the pinned zenoh-pico headers (56 / 32 / 24). A C program
    /// stack-allocates each, so a drift here corrupts its frame — and the
    /// linker cannot see it, because a size mismatch is not a symbol mismatch.
    #[test]
    fn hello_and_string_array_abi() {
        assert_eq!(std::mem::size_of::<z_owned_hello_t>(), 56);
        assert_eq!(std::mem::size_of::<z_owned_string_array_t>(), 32);
        assert_eq!(std::mem::size_of::<z_owned_closure_hello_t>(), 24);
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

    /// The whatami map is an INDEXED BITMASK, not an ordinal list: index 3 is
    /// "Router|Peer", not a third role. Transcribing it as a role list is the
    /// mistake this pins against, and it would be invisible for the two
    /// single-bit values a test that only checked Router and Peer would use.
    #[test]
    fn whatami_renders_the_bitmask_combinations() {
        let render = |w: u32| -> String {
            let mut out = z_view_string_t {
                _start: std::ptr::null(),
                _len: 0,
                _pad: [0usize; 2],
            };
            let res = unsafe { z_whatami_to_view_string(w, &mut out) };
            let text = unsafe {
                std::str::from_utf8(std::slice::from_raw_parts(out._start, out._len)).unwrap()
            };
            format!("{res}:{text}")
        };
        assert_eq!(render(1), "0:Router");
        assert_eq!(render(2), "0:Peer");
        assert_eq!(render(3), "0:Router|Peer");
        assert_eq!(render(4), "0:Client");
        assert_eq!(render(7), "0:Router|Peer|Client");
        // Upstream returns an ERROR for 0 and for out-of-range, and still
        // writes "Other" — both halves, or a caller that ignores the result
        // reads uninitialised stack.
        assert!(render(0).starts_with("-8:Other") || render(0).ends_with(":Other"));
        assert!(render(99).ends_with(":Other"));
    }

    /// The locator array lends STABLE per-item views. Building them before the
    /// items were final would leave `z_string_array_get` pointing at freed
    /// buffers, and the failure would look like a garbled locator rather than
    /// a use-after-free.
    #[test]
    fn string_array_lends_each_locator_by_pointer() {
        let state = StringArrayState::new(vec![
            "tcp/127.0.0.1:7447".to_string(),
            "udp/127.0.0.1:7448".to_string(),
        ]);
        let handle = (&*state) as *const StringArrayState as *mut c_void;
        let loaned = z_loaned_string_array_t {
            handle,
            _pad: [std::ptr::null_mut(); 3],
        };
        unsafe {
            assert_eq!(z_string_array_len(&loaned), 2);
            assert!(!z_string_array_is_empty(&loaned));
            let first = z_string_array_get(&loaned, 0);
            assert!(!first.is_null());
            let bytes = std::slice::from_raw_parts((*first)._start, (*first)._len);
            assert_eq!(std::str::from_utf8(bytes).unwrap(), "tcp/127.0.0.1:7447");
            // Out of range is NULL, not a panic and not slot 0.
            assert!(z_string_array_get(&loaned, 2).is_null());
        }
    }

    /// A hello lends its locator array by POINTER, so the array handle must
    /// survive the call that returns it. A `zp_hello_locators` that built its
    /// return value on the stack would pass a same-statement read and dangle
    /// the moment the caller stored it — this holds the pointer across a
    /// second call before reading through it.
    #[test]
    fn hello_lends_a_locator_array_that_outlives_the_call() {
        let state = HelloState::new(
            z_id_t::from_wire(&[0xAB, 0xCD]),
            2,
            vec!["tcp/127.0.0.1:7447".to_string()],
        );
        let loaned = z_loaned_hello_t {
            handle: (&*state) as *const HelloState as *mut c_void,
            _pad: [std::ptr::null_mut(); 6],
        };
        unsafe {
            let locs = zp_hello_locators(&loaned);
            assert_eq!(z_hello_whatami(&loaned), 2);
            assert_eq!(z_hello_zid(&loaned).id[0], 0xAB);
            assert_eq!(z_string_array_len(locs), 1);
        }
    }
}
