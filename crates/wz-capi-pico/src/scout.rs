// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! deliberately in `wz-capi-core::scouting::deliver_in_upstream_order` rather
//! than firing per-Hello, which would have been a divergence in wz's favour.

use std::ffi::c_void;

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

// The Scout version byte and the drive-loop tick moved out with the copied
// drive loop: they are `wz_capi_core::scouting`'s now, so both C ABIs announce
// one protocol version and poll on one cadence by construction.

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

/// One string-array entry, BOXED so the address of its cached view survives a
/// push that reallocates the vector.
///
/// R311y570 — the previous shape kept `items: Vec<String>` beside a parallel
/// `views: Vec<z_loaned_string_t>`, and a push rebuilt BOTH into a fresh state
/// and freed the old one, so every pointer `z_string_array_get` had handed out
/// dangled from the next push onward. One indirection per entry replaces that:
/// a push moves the BOXES and never the bytes they describe.
///
/// # Every entry OWNS its bytes, in BOTH push spellings
///
/// That is not a shortcut — it is what the real library does, MEASURED at
/// R311y570 by `pico_string_array_alias_twice_and_diff`. Upstream's
/// `z_string_array_push_by_alias` builds an alias `_z_string_t` and then hands
/// it to `_z_string_svec_append(a, &str, true)`, which deep-copies; the probe
/// sees the array's entry pointing at storage that is NOT the caller's buffer,
/// on the real `libzenohpico.so`. So a wz that aliased here would be the one
/// diverging, and it would diverge in the dangerous direction — holding a
/// pointer into caller memory where upstream holds its own copy.
///
/// The SIBLING ABI genuinely differs: real `libzenohc.so` aliases in
/// `_by_alias` and copies in `_by_copy`, also measured, which is why
/// `wz-capi-c` implements the two spellings differently. A third dialect
/// split, alongside the keyexpr and encoding ones.
struct StringArrayEntry {
    value: String,
    view: z_loaned_string_t,
}

impl StringArrayEntry {
    /// An entry over a copy of `value`.
    ///
    /// The view is derived BEFORE the move, which is sound because moving a
    /// `String` moves the three-word header and never the heap buffer the view
    /// points at.
    fn new(value: String) -> Box<Self> {
        let view = z_loaned_string_t {
            _start: value.as_ptr(),
            _len: value.len(),
        };
        Box::new(Self { value, view })
    }
}

pub(crate) struct StringArrayState {
    // `clippy::vec_box` fires here and is WRONG for this type, exactly as it is
    // for the sibling zenoh-c state: the lint's premise is that the `Vec`
    // already heap-allocates, so the `Box` buys nothing. What it buys is the
    // whole point — an element address that survives a reallocation. Without
    // it, one `push` past capacity invalidates every pointer
    // `z_string_array_get` has handed out, which is the use-after-free
    // `an_element_pointer_survives_a_reallocating_push` pins.
    #[allow(clippy::vec_box)]
    entries: Vec<Box<StringArrayEntry>>,
}

impl StringArrayState {
    fn new(items: Vec<String>) -> Box<Self> {
        Box::new(Self {
            entries: items.into_iter().map(StringArrayEntry::new).collect(),
        })
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn view(&self, k: usize) -> Option<&z_loaned_string_t> {
        self.entries.get(k).map(|entry| &entry.view)
    }

    /// Every entry as an OWNED string.
    ///
    /// An alias is COPIED here on purpose: the callers are the deep-copy paths
    /// (`z_string_array_clone`, the hello clone), and a copy that kept
    /// borrowing would silently extend the caller's lifetime obligation to an
    /// array it never pushed to.
    fn to_strings(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.value.clone())
            .collect()
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

/// The MUTABLE half, for the two push exports.
///
/// Sound for the same reason every other handle deref in this crate is: the C
/// side owns the array and pico's contract makes it single-threaded for the
/// duration of a call.
unsafe fn string_array_state_mut<'a>(
    array: *mut z_loaned_string_array_t,
) -> Option<&'a mut StringArrayState> {
    let array = array.as_mut()?;
    (array.handle as *mut StringArrayState).as_mut()
}

/// Number of strings in the array (pico `z_string_array_len`).
///
/// # Safety
/// `array` must be a live loaned string array (or null, which reads 0).
#[no_mangle]
pub unsafe extern "C" fn z_string_array_len(array: *const z_loaned_string_array_t) -> usize {
    string_array_state(array).map_or(0, |s| s.len())
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
    match string_array_state(array).and_then(|s| s.view(k)) {
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

/// Build an EMPTY owned string array (pico `z_string_array_new`).
///
/// R311y559 — a symbol the census found missing. An owned array is a live
/// handle over zero items, not a null one: `z_internal_string_array_check`
/// reports it PRESENT, which is what makes the push family below usable on a
/// freshly constructed array.
///
/// # Safety
/// `array` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_new(array: *mut z_owned_string_array_t) {
    if array.is_null() {
        return;
    }
    *array = z_owned_string_array_t {
        handle: Box::into_raw(StringArrayState::new(Vec::new())) as *mut c_void,
        _pad: [std::ptr::null_mut(); 3],
    };
}

/// Append a COPY of `value` (pico `z_string_array_push_by_copy`), returning the
/// array's new length.
///
/// # Safety
/// `array` must be a live loaned string array; `value` must be null or a live
/// loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_push_by_copy(
    array: *mut z_loaned_string_array_t,
    value: *const z_loaned_string_t,
) -> usize {
    string_array_push(array, value)
}

/// Append `value` (pico `z_string_array_push_by_alias`), returning the array's
/// new length.
///
/// COPIES, and so does the real library — which is the opposite of what this
/// tree believed until R311y570. The doc here used to record a NAMED DIVERGENCE
/// ("upstream ALIASES the caller's storage here and wz copies in both"), and
/// the debt ledger carried it for rounds as a gap to close. It was read off the
/// function's NAME and never measured.
///
/// `pico_string_array_alias_twice_and_diff` measures it: on the real
/// `libzenohpico.so`, a view that provably aliases the caller's buffer
/// (`view.is_caller_buffer=1`) becomes an array entry that provably does not
/// (`alias.is_caller_buffer=0`). Upstream builds the alias and then hands it to
/// `_z_string_svec_append(a, &str, true)`, whose last argument deep-copies. So
/// the two spellings are the same operation on this ABI, and wz aliasing here
/// would be the divergence — in the dangerous direction.
///
/// The sibling zenoh-c ABI is genuinely different (its `_by_alias` really does
/// alias, also measured), which is why `wz-capi-c` implements the pair with two
/// bodies and this crate with one.
///
/// # Safety
/// As [`z_string_array_push_by_copy`].
#[no_mangle]
pub unsafe extern "C" fn z_string_array_push_by_alias(
    array: *mut z_loaned_string_array_t,
    value: *const z_loaned_string_t,
) -> usize {
    string_array_push(array, value)
}

/// The shared body of the two push exports — see
/// [`z_string_array_push_by_alias`] for why one body serves both.
///
/// Pushes IN PLACE. The earlier version rebuilt the whole state into a fresh
/// box and freed the old one, which invalidated every pointer
/// `z_string_array_get` had handed out; boxed entries make an in-place push the
/// safe operation instead of the dangerous one.
unsafe fn string_array_push(
    array: *mut z_loaned_string_array_t,
    value: *const z_loaned_string_t,
) -> usize {
    let Some(state) = string_array_state_mut(array) else {
        return 0;
    };
    let Some(view) = value.as_ref() else {
        return state.len();
    };
    let Some(bytes) = crate::abi::view_bytes(view._start, view._len) else {
        return state.len();
    };
    state.entries.push(StringArrayEntry::new(
        String::from_utf8_lossy(bytes).into_owned(),
    ));
    state.len()
}

/// Deep-copy a string array (pico `z_string_array_clone`).
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a live loaned array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_clone(
    dst: *mut z_owned_string_array_t,
    src: *const z_loaned_string_array_t,
) -> ZResult {
    if dst.is_null() {
        return crate::result::Z_ERR_NULL;
    }
    *dst = z_owned_string_array_t::null_value();
    let Some(state) = string_array_state(src) else {
        return crate::result::Z_ERR_NULL;
    };
    *dst = z_owned_string_array_t {
        handle: Box::into_raw(StringArrayState::new(state.to_strings())) as *mut c_void,
        _pad: [std::ptr::null_mut(); 3],
    };
    crate::result::Z_OK
}

/// Adopt a loaned string array into an owned one, emptying the source (pico
/// `z_string_array_take_from_loaned`).
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a live loaned array.
#[no_mangle]
pub unsafe extern "C" fn z_string_array_take_from_loaned(
    dst: *mut z_owned_string_array_t,
    src: *mut z_loaned_string_array_t,
) -> ZResult {
    if dst.is_null() || src.is_null() {
        return crate::result::Z_ERR_NULL;
    }
    let slot = src as *mut z_owned_string_array_t;
    *dst = z_owned_string_array_t {
        handle: (*slot).handle,
        _pad: [std::ptr::null_mut(); 3],
    };
    *slot = z_owned_string_array_t::null_value();
    crate::result::Z_OK
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
    let items = hello_state(hello).map_or_else(Vec::new, |s| s.locators.to_strings());
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
    let cloned = HelloState::new(state.zid, state.whatami, state.locators.to_strings());
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

/// Drive one scouting window for `budget_ms` and hand each peer that answered
/// to `on_hello`. Returns the number delivered.
///
/// DELEGATES to [`wz_capi_core::scouting::run_scout`], the drive both C ABIs
/// share. This function used to carry its own copy of that loop, and the copy
/// is what let the two ABIs disagree — the pico side re-entered whole scouting
/// CYCLES (because the statechart left `AwaitingHello` on the first Hello, so a
/// single window could report only one peer), which re-sent a Scout per cycle
/// and needed a zid set to suppress the duplicate answers its own re-scouting
/// provoked. The FSM carries pico's `exit_on_first == false` survey arm now, so
/// the shared drive is a single window, and the WHEN and the ORDER of the
/// callbacks — after the window, last responder first — are settled once in
/// `wz-capi-core` against upstream rather than twice here and there.
///
/// All this side keeps is the ABI mapping: a [`ScoutedHello`] becomes the
/// `HelloState` behind pico's `z_loaned_hello_t`.
fn run_scout(
    group: std::net::Ipv4Addr,
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
    mut on_hello: impl FnMut(&mut HelloState),
) -> usize {
    wz_capi_core::scouting::run_scout(group, port, what, zid, budget_ms, |hello| {
        let whatami = hello.whatami.map_or(0, |w| u32::from(w.to_api()));
        let mut state = HelloState::new(
            z_id_t::from_wire(&hello.zid),
            whatami,
            hello.locators.clone(),
        );
        on_hello(&mut state);
    })
}

/// Adopt a loaned hello into an owned one (pico `z_hello_take_from_loaned`).
///
/// R311y559 — a symbol the census found missing. A DEEP COPY that leaves the
/// source EMPTY, routed through the same [`HelloState::new`] `z_hello_clone`
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
            (*src).handle = std::ptr::null_mut();
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
    context: *mut std::ffi::c_void,
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

    /// R311y570 — an element pointer SURVIVES a reallocating push, on this ABI
    /// too.
    ///
    /// ## What this fixed, and why it is a wz-side test
    ///
    /// Until this round a push REPLACED the whole `StringArrayState` with a
    /// freshly built one and freed the old box, so every pointer
    /// `z_string_array_get` had handed out was dangling from the next push
    /// onward — a use-after-free reachable from ordinary C. Boxed entries make
    /// the push in-place and the pointers stable.
    ///
    /// It is asserted HERE rather than in a twice-and-diff leg because it is a
    /// wz SUPERSET: upstream's `_z_string_svec_t` stores entries inline, so the
    /// same program reads freed memory against the real library. A claim one
    /// side cannot make has no reference answer to agree with — the sibling
    /// zenoh-c ABI keeps its copy of this same claim in the same place, for the
    /// same reason.
    ///
    /// Meaningful only if the push actually REALLOCATES, which is why it grows
    /// well past any plausible initial capacity rather than pushing once.
    #[test]
    fn an_element_pointer_survives_a_reallocating_push() {
        // SAFETY: every pointer below is a live stack slot this test owns, and
        // the array is dropped exactly once at the end.
        unsafe {
            let mut arr = z_owned_string_array_t::null_value();
            z_string_array_new(&mut arr);
            let first = z_loaned_string_t {
                _start: b"first".as_ptr(),
                _len: 5,
            };
            let loaned = &mut arr as *mut z_owned_string_array_t as *mut z_loaned_string_array_t;
            assert_eq!(z_string_array_push_by_copy(loaned, &first), 1);

            // The pointer taken BEFORE the growth — the one the pre-y570 shape
            // freed out from under the caller.
            let e0 = z_string_array_get(loaned as *const z_loaned_string_array_t, 0);
            assert!(!e0.is_null());
            let before = std::slice::from_raw_parts((*e0)._start, (*e0)._len).to_vec();
            assert_eq!(before, b"first");

            let filler = z_loaned_string_t {
                _start: b"filler".as_ptr(),
                _len: 6,
            };
            for _ in 0..64 {
                z_string_array_push_by_copy(loaned, &filler);
            }
            assert_eq!(
                z_string_array_len(loaned as *const z_loaned_string_array_t),
                65
            );

            // Read through the PRE-GROWTH pointer, not a fresh `get`. A fresh
            // one would pass on either layout and would be testing nothing.
            let after = std::slice::from_raw_parts((*e0)._start, (*e0)._len).to_vec();
            assert_eq!(
                after, before,
                "the pointer handed out before the growth no longer reads its own \
                 string, so a reallocating push moved or freed the entry"
            );

            let mut moved = z_moved_string_array_t { _this: arr };
            z_string_array_drop(&mut moved);
        }
    }
}
