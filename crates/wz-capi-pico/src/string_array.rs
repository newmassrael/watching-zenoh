// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_owned_string_array_t`, the array of strings a hello lends its locators in and the
//! connectivity plane lends a transport's.
//!
//! Its own module, not part of [`crate::scout`], because the array is not scouting's alone: a
//! build without `z_scout` keeps the type the connectivity plane returns.
//!
//! A C program stack-allocates the owned form (32 B, measured against the pinned headers); the
//! contents are wz's — pico's header never dereferences the fields, every read goes through an
//! exported accessor, so a handle in slot 0 with zero padding to the pico size is faithful.

use std::ffi::c_void;

use crate::abi::z_loaned_string_t;
use crate::result::ZResult;

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
    pub(crate) fn new(items: Vec<String>) -> Box<Self> {
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
    pub(crate) fn to_strings(&self) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The owned string array is stack-allocated by a C program, so its size is
    /// pinned against the 32 B measured off the pinned zenoh-pico headers, and the
    /// loaned form must keep the owned form's layout for the offset-0 loan casts.
    #[test]
    fn string_array_abi() {
        assert_eq!(std::mem::size_of::<z_owned_string_array_t>(), 32);
        assert_eq!(
            std::mem::size_of::<z_loaned_string_array_t>(),
            std::mem::size_of::<z_owned_string_array_t>()
        );
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
