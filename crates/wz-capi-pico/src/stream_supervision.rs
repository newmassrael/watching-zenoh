// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_stream_supervisor_*`: reception supervision per stream, from C. A receiver gives each
//! periodic stream a deadline of its period times a factor, says when a stream is received, and
//! polls; a stream that stops arriving is told to the program's callback once per loss, with
//! saturating error counts per stream and per node.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h` (the
//! extension namespace, apart from the drop-in headers), and part of the unstable surface: the
//! `e2e-supervision` capability implies `unstable-api`.
//!
//! What the supervisor does is [`wz_session_core::stream_supervisor`]'s: the start delay from the
//! first poll that has a clock, the condition the program supplies, the re-basing of every stream
//! that can time out when the two gates open, and the senders the program marks absent. This file
//! is the pico ABI's names, result codes, clock and ownership around it.
//!
//! # Storage
//!
//! The table is the program's: an array of `wz_ext_stream_slot_t`, and under the build's
//! `e2e-supervision-notify = last-value` a byte area of one cell per slot for the last payload.
//! The supervisor writes both when it is made and owns them until it is dropped; the program
//! neither reads nor frees them in between.
//!
//! # Time
//!
//! Milliseconds in 32 bits that wrap: a clock the program gives at creation (for a device whose
//! tick is not yet running, which answers that it cannot say), or the library's monotonic clock
//! from the creation when it gives none.
//!
//! # The poll
//!
//! The program calls `wz_ext_stream_supervisor_poll` on its own cadence, which is how the
//! cooperative engine and a single-threaded program drive it. A build with tasks can instead have
//! the library poll on a task of its own (`wz_ext_stream_supervisor_start_task`).
//!
//! # Threads
//!
//! One supervisor may be called from several threads: each door runs under its lock. The clock and
//! the loss callback run inside that lock, on the thread that polls (the task's, when one runs), so
//! neither may call a door of its own supervisor; the payload a loss hands back is valid only
//! during the call.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::c_void;
// The lock, the clock and the polling task's wait: `std`'s where the library has `std`, and the
// host's own without it (`wz-host-sync`, which both libraries that compile the doors link).
#[cfg(all(feature = "std", feature = "multi-thread"))]
use std::sync::Condvar;
#[cfg(feature = "std")]
use std::sync::{Mutex, MutexGuard, PoisonError};
#[cfg(feature = "std")]
use std::time::Instant;
#[cfg(all(not(feature = "std"), feature = "multi-thread"))]
use wz_host_sync::Condvar;
#[cfg(not(feature = "std"))]
use wz_host_sync::{Instant, Mutex, MutexGuard};

use wz_session_core::policy::SessionPolicy;
use wz_session_core::stream_supervisor::{
    AddRefused, CreateRefused, Loss, Notify, Phase, ReceiveRefused, StreamSlot, StreamSupervisor,
    UnknownSender,
};

use crate::ffi::{guard_val, guarded, SendPtr};
#[cfg(feature = "multi-thread")]
use crate::result::Z_ERR_GENERIC;
use crate::result::{ZResult, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK};

/// One row of the program's stream table: five 32-bit words the supervisor owns.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct wz_ext_stream_slot_t {
    _opaque: [u32; 5],
}

// The C header sizes the table by this type, and the supervisor writes `StreamSlot` into it.
const _: () = assert!(
    core::mem::size_of::<wz_ext_stream_slot_t>() == core::mem::size_of::<StreamSlot>()
        && core::mem::align_of::<wz_ext_stream_slot_t>() == core::mem::align_of::<StreamSlot>()
);

/// The program's clock: writes the milliseconds of a monotonic source, in 32 bits that wrap, and
/// returns 0, or returns anything else when it cannot say what time it is.
pub type wz_ext_stream_clock_fn =
    unsafe extern "C" fn(context: *mut c_void, now_ms: *mut u32) -> i8;

/// One loss, as the callback reads it: 32 bytes on a 64-bit target, 24 on a 32-bit one.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_ext_stream_loss_t {
    /// The number `wz_ext_stream_supervisor_add` gave the stream.
    pub stream: u32,
    /// The sender the stream was added with.
    pub sender: u32,
    /// The stream's error count, this loss included; it stops at 255.
    pub errors: u8,
    /// The node's error count, this loss included; it stops at 255.
    pub node_errors: u8,
    pub reserved: u16,
    pub reserved2: u32,
    /// Under `last-value`, the payload the stream last carried, valid only during the call; null
    /// under `status-only` and when no payload was kept.
    pub value: *const u8,
    /// The length of `value`; 0 when it is null.
    pub value_len: usize,
}

impl wz_ext_stream_loss_t {
    fn of(loss: &Loss<'_>) -> Self {
        let (value, value_len) = match loss.value {
            Some(value) => (value.as_ptr(), value.len()),
            None => (core::ptr::null(), 0),
        };
        Self {
            // A stream's number is below the table's length, which `new` holds to 32 bits.
            stream: loss.stream as u32,
            sender: loss.sender,
            errors: loss.errors,
            node_errors: loss.node_errors,
            reserved: 0,
            reserved2: 0,
            value,
            value_len,
        }
    }
}

/// What the supervisor calls for each loss, with the program's context.
pub type wz_ext_stream_loss_fn =
    unsafe extern "C" fn(context: *mut c_void, loss: *const wz_ext_stream_loss_t);

/// No poll has had a clock yet.
pub const WZ_EXT_STREAM_UNCLOCKED: u8 = 0;
/// The start delay runs.
pub const WZ_EXT_STREAM_DELAYING: u8 = 1;
/// The delay has passed and the condition does not hold: nothing is judged.
pub const WZ_EXT_STREAM_INACTIVE: u8 = 2;
/// The delay has passed and the condition holds: every poll judges the streams.
pub const WZ_EXT_STREAM_ACTIVE: u8 = 3;
/// What `wz_ext_stream_supervisor_phase` answers for a null supervisor or the gravestone.
pub const WZ_EXT_STREAM_NO_SUPERVISOR: u8 = 255;

/// A loss tells the stream and its counts.
pub const WZ_EXT_STREAM_NOTIFY_STATUS_ONLY: u8 = 0;
/// A loss also hands back the stream's last payload.
pub const WZ_EXT_STREAM_NOTIFY_LAST_VALUE: u8 = 1;

/// An owned supervisor: the handle in its one word, null for the gravestone.
#[repr(C)]
pub struct wz_ext_owned_stream_supervisor_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned supervisor: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_stream_supervisor_t {
    pub(crate) handle: *mut c_void,
}

/// A moved supervisor (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_stream_supervisor_t {
    pub(crate) _this: wz_ext_owned_stream_supervisor_t,
}

impl wz_ext_owned_stream_supervisor_t {
    fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
        }
    }
}

struct Clock {
    read: Option<wz_ext_stream_clock_fn>,
    context: SendPtr,
    origin: Instant,
}

impl Clock {
    fn now(&self) -> Option<u32> {
        match self.read {
            // Milliseconds since the creation, in the 32 bits the supervisor compares: the
            // truncation is the wrap it is written to survive.
            None => Some(self.origin.elapsed().as_millis() as u32),
            Some(read) => {
                let mut now = 0u32;
                // SAFETY: the program gave this clock and its context for the supervisor's life.
                (unsafe { read(self.context.0, &mut now) } == 0).then_some(now)
            }
        }
    }
}

struct Callback {
    call: wz_ext_stream_loss_fn,
    context: SendPtr,
}

struct State {
    supervisor: StreamSupervisor<'static>,
    clock: Clock,
    callback: Option<Callback>,
}

/// The polling task's thread: `std`'s, or the host's own without it.
#[cfg(all(feature = "multi-thread", feature = "std"))]
type TaskThread = std::thread::JoinHandle<()>;
#[cfg(all(feature = "multi-thread", not(feature = "std")))]
type TaskThread = wz_host_sync::Thread;

#[cfg(feature = "multi-thread")]
struct Task {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: TaskThread,
}

/// Start the polling task's thread running `body`; `None` when the host gave none.
#[cfg(feature = "multi-thread")]
fn spawn_task(body: impl FnOnce() + Send + 'static) -> Option<TaskThread> {
    #[cfg(feature = "std")]
    {
        std::thread::Builder::new()
            .name("wz-stream-supervisor".into())
            .spawn(body)
            .ok()
    }
    #[cfg(not(feature = "std"))]
    {
        wz_host_sync::spawn_fn(body)
    }
}

/// Whether the calling thread is the task's own.
#[cfg(feature = "multi-thread")]
fn is_current(thread: &TaskThread) -> bool {
    #[cfg(feature = "std")]
    {
        thread.thread().id() == std::thread::current().id()
    }
    #[cfg(not(feature = "std"))]
    {
        thread.id() == wz_host_sync::current_thread()
    }
}

/// Wait for the task's thread to end.
#[cfg(feature = "multi-thread")]
fn join_task(thread: TaskThread) {
    #[cfg(feature = "std")]
    {
        let _ = thread.join();
    }
    #[cfg(not(feature = "std"))]
    {
        thread.join();
    }
}

/// Wait out one period, or less when told to stop: the stop flag after the wait.
#[cfg(feature = "multi-thread")]
fn wait_period(stopped: &Mutex<bool>, wake: &Condvar, period: core::time::Duration) -> bool {
    let guard = locked(stopped);
    #[cfg(feature = "std")]
    let (guard, _) = wake
        .wait_timeout_while(guard, period, |stop| !*stop)
        .unwrap_or_else(PoisonError::into_inner);
    #[cfg(not(feature = "std"))]
    let (guard, _) = wake.wait_timeout_while(guard, period, |stop| !*stop);
    *guard
}

struct Handle {
    state: Arc<Mutex<State>>,
    #[cfg(feature = "multi-thread")]
    task: Mutex<Option<Task>>,
}

/// The lock, past a poison: a panic inside a call was caught at the door, and the table is
/// written a row at a time.
fn locked<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    #[cfg(feature = "std")]
    {
        lock.lock().unwrap_or_else(PoisonError::into_inner)
    }
    #[cfg(not(feature = "std"))]
    {
        lock.lock()
    }
}

/// The policies a supervisor is made under: the one place its creator decides them. The build
/// defaults, until the process is handed a run-time document.
fn resolve_policy() -> SessionPolicy {
    SessionPolicy::defaults()
}

/// Poll the supervisor at its clock's time and tell the callback each loss. Returns how many.
fn poll_state(state: &Mutex<State>) -> usize {
    let mut state = locked(state);
    let now = state.clock.now();
    let State {
        supervisor,
        callback,
        ..
    } = &mut *state;
    supervisor.poll(now, |loss| {
        if let Some(callback) = callback.as_ref() {
            let told = wz_ext_stream_loss_t::of(&loss);
            // SAFETY: the program gave the callback and its context for as long as it is set.
            unsafe { (callback.call)(callback.context.0, &told) };
        }
    })
}

/// The supervisor behind a loaned handle; `None` for a null pointer or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned supervisor of this library.
unsafe fn handle_of<'a>(this_: *const wz_ext_loaned_stream_supervisor_t) -> Option<&'a Handle> {
    if this_.is_null() {
        return None;
    }
    let handle = (*this_).handle;
    if handle.is_null() {
        return None;
    }
    Some(&*handle.cast::<Handle>())
}

/// The code of a refusal to make a supervisor.
fn create_code(refusal: CreateRefused) -> ZResult {
    match refusal {
        CreateRefused::DelayOutOfRange
        | CreateRefused::NoValueCell
        | CreateRefused::ValueCellTooLarge
        | CreateRefused::ValueStorageShort => Z_ERR_INVALID,
    }
}

/// Make a supervisor of no stream yet over the program's storage: `slot_count` rows at `slots`,
/// and, under the build's `last-value` policy, `slot_count` cells of `value_cell` bytes at
/// `values` (under `status-only` `values` is not read and may be null). It judges nothing until
/// `start_delay_ms` after the first poll that has a clock, and the condition holds until the
/// program says otherwise. `clock` may be null for the library's monotonic clock.
///
/// `this_` holds the gravestone on every error. Returns `Z_ERR_NULL` for a null `this_` or
/// `slots`, or a null `values` under `last-value`; `Z_ERR_INVALID` for a `slot_count` of 0 or past
/// 2^32 - 1, a value area whose length overflows, a start delay past 2147483647, or under
/// `last-value` a `value_cell` of 0 or past 2^32 - 1; `Z_OK` otherwise.
///
/// # Safety
/// `this_` is writable; `slots` is writable for `slot_count` rows and `values`, under
/// `last-value`, for `slot_count * value_cell` bytes, both left to the supervisor until it is
/// dropped; `clock` is safe to call with `clock_context` from any thread that polls, for as long.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wz_ext_stream_supervisor_new(
    this_: *mut wz_ext_owned_stream_supervisor_t,
    slots: *mut wz_ext_stream_slot_t,
    slot_count: usize,
    values: *mut u8,
    value_cell: usize,
    start_delay_ms: u32,
    clock: Option<wz_ext_stream_clock_fn>,
    clock_context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        *this_ = wz_ext_owned_stream_supervisor_t::null_value();
        if slots.is_null() {
            return Z_ERR_NULL;
        }
        if slot_count == 0 || u32::try_from(slot_count).is_err() {
            return Z_ERR_INVALID;
        }
        let notify = resolve_policy().e2e_supervision_notify();
        let value_area: &'static mut [u8] = match notify {
            Notify::StatusOnly => &mut [],
            Notify::LastValue => {
                if values.is_null() {
                    return Z_ERR_NULL;
                }
                let Some(len) = slot_count.checked_mul(value_cell) else {
                    return Z_ERR_INVALID;
                };
                core::ptr::write_bytes(values, 0, len);
                core::slice::from_raw_parts_mut(values, len)
            }
        };
        let rows = slots.cast::<StreamSlot>();
        for row in 0..slot_count {
            rows.add(row).write(StreamSlot::EMPTY);
        }
        let table: &'static mut [StreamSlot] = core::slice::from_raw_parts_mut(rows, slot_count);
        let supervisor =
            match StreamSupervisor::new(table, value_area, value_cell, start_delay_ms, notify) {
                Ok(supervisor) => supervisor,
                Err(refusal) => return create_code(refusal),
            };
        let state = State {
            supervisor,
            clock: Clock {
                read: clock,
                context: SendPtr(clock_context),
                origin: Instant::now(),
            },
            callback: None,
        };
        let handle = Handle {
            state: Arc::new(Mutex::new(state)),
            #[cfg(feature = "multi-thread")]
            task: Mutex::new(None),
        };
        (*this_).handle = Box::into_raw(Box::new(handle)).cast::<c_void>();
        Z_OK
    })
}

/// Supervise a stream of `period_ms` that may miss `factor` periods, sent by `sender` (an opaque
/// number of the program's, which `wz_ext_stream_supervisor_set_sender_present` names), and write
/// its number to `out_stream` (which may be null). An `awaited` stream can time out before its
/// first reception; one that is not is supervised from its first. A stream of a sender marked
/// absent is absent with it.
///
/// Returns `Z_ERR_NULL` for a null supervisor or the gravestone; `Z_ERR_INVALID` for a period or a
/// factor of 0, or a deadline past 2147483646 ms; `Z_ERR_OVERFLOW` when the table holds as many
/// streams as its storage or the build's `E2E_SUPERVISED_STREAMS`; `Z_OK` otherwise.
///
/// # Safety
/// `this_` is null or a loaned supervisor; `out_stream` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_add(
    this_: *const wz_ext_loaned_stream_supervisor_t,
    period_ms: u32,
    factor: u16,
    sender: u32,
    awaited: bool,
    out_stream: *mut u32,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        let added = locked(&handle.state)
            .supervisor
            .add(period_ms, factor, sender, awaited);
        match added {
            Ok(stream) => {
                if !out_stream.is_null() {
                    // Below the table's length, which `new` holds to 32 bits.
                    *out_stream = stream as u32;
                }
                Z_OK
            }
            Err(AddRefused::DeadlineOutOfRange) => Z_ERR_INVALID,
            Err(AddRefused::Full) => Z_ERR_OVERFLOW,
        }
    })
}

/// Stream `stream` was received now, carrying `payload` (`len` bytes; null with 0 for none), which
/// is kept under `last-value` and not read otherwise. A loss the stream was in is over.
///
/// Returns `Z_ERR_NULL` for a null supervisor, the gravestone or a null payload with a length;
/// `Z_ERR_INVALID` for a stream there is none of; `Z_ERR_OVERFLOW` under `last-value` for a
/// payload longer than the value cell, the reception recorded and no value kept; `Z_OK` otherwise.
///
/// # Safety
/// `this_` is null or a loaned supervisor; `payload` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_received(
    this_: *const wz_ext_loaned_stream_supervisor_t,
    stream: u32,
    payload: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        if payload.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let payload: &[u8] = if len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(payload, len)
        };
        let mut state = locked(&handle.state);
        let now = state.clock.now();
        match state.supervisor.received(stream as usize, now, payload) {
            Ok(()) => Z_OK,
            Err(ReceiveRefused::NoSuchStream) => Z_ERR_INVALID,
            Err(ReceiveRefused::ValueTooLong) => Z_ERR_OVERFLOW,
        }
    })
}

/// Whether the program's condition holds (the supply is in range, the bus is up). Every poll reads
/// it; the streams are re-based each time it comes to hold after the start delay. It holds until
/// the program says otherwise. Returns `Z_ERR_NULL` for a null supervisor or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned supervisor.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_set_condition(
    this_: *const wz_ext_loaned_stream_supervisor_t,
    holds: bool,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        locked(&handle.state).supervisor.set_condition(holds);
        Z_OK
    })
}

/// Mark `sender` present or absent. Its streams are not judged while it is absent, and a loss one
/// of them was in is withdrawn without being told; once present again, their deadlines count from
/// now. The error counts are left as they are.
///
/// Returns `Z_ERR_NULL` for a null supervisor or the gravestone; `Z_ERR_INVALID` when no stream was
/// added with that sender; `Z_OK` otherwise, also when the sender already was what it is marked.
///
/// # Safety
/// `this_` is null or a loaned supervisor.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_set_sender_present(
    this_: *const wz_ext_loaned_stream_supervisor_t,
    sender: u32,
    present: bool,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        let mut state = locked(&handle.state);
        let now = state.clock.now();
        match state.supervisor.set_sender_present(sender, present, now) {
            Ok(()) => Z_OK,
            Err(UnknownSender) => Z_ERR_INVALID,
        }
    })
}

/// Set the callback each loss is told to, with `context`, or clear it with a null `call`. With
/// none set a loss is still counted. Returns `Z_ERR_NULL` for a null supervisor or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned supervisor; `call` is safe to call with `context` from any thread
/// that polls, for as long as it is set.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_set_callback(
    this_: *const wz_ext_loaned_stream_supervisor_t,
    call: Option<wz_ext_stream_loss_fn>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        locked(&handle.state).callback = call.map(|call| Callback {
            call,
            context: SendPtr(context),
        });
        Z_OK
    })
}

/// Look at every stream now and tell the callback once for each whose deadline has newly passed;
/// `out_told`, which may be null, receives how many. Returns `Z_ERR_NULL` for a null supervisor or
/// the gravestone, and `Z_OK` otherwise.
///
/// # Safety
/// `this_` is null or a loaned supervisor; `out_told` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_poll(
    this_: *const wz_ext_loaned_stream_supervisor_t,
    out_told: *mut usize,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        let told = poll_state(&handle.state);
        if !out_told.is_null() {
            *out_told = told;
        }
        Z_OK
    })
}

/// Write the error count of stream `stream` to `out`. Returns `Z_ERR_NULL` for a null supervisor,
/// the gravestone or a null `out`; `Z_ERR_INVALID` for a stream there is none of; `Z_OK`
/// otherwise.
///
/// # Safety
/// `this_` is null or a loaned supervisor; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_stream_errors(
    this_: *const wz_ext_loaned_stream_supervisor_t,
    stream: u32,
    out: *mut u8,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        if out.is_null() {
            return Z_ERR_NULL;
        }
        match locked(&handle.state)
            .supervisor
            .stream_errors(stream as usize)
        {
            Some(errors) => {
                *out = errors;
                Z_OK
            }
            None => Z_ERR_INVALID,
        }
    })
}

/// The node's error count: every loss told since the last activation, stopping at 255. 0 for a
/// null supervisor or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned supervisor.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_node_errors(
    this_: *const wz_ext_loaned_stream_supervisor_t,
) -> u8 {
    guard_val(0, || match handle_of(this_) {
        Some(handle) => locked(&handle.state).supervisor.node_errors(),
        None => 0,
    })
}

/// Where the two gates stand: `WZ_EXT_STREAM_UNCLOCKED`, `_DELAYING`, `_INACTIVE` or `_ACTIVE`, or
/// `WZ_EXT_STREAM_NO_SUPERVISOR`.
///
/// # Safety
/// `this_` is null or a loaned supervisor.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_phase(
    this_: *const wz_ext_loaned_stream_supervisor_t,
) -> u8 {
    guard_val(WZ_EXT_STREAM_NO_SUPERVISOR, || {
        let Some(handle) = handle_of(this_) else {
            return WZ_EXT_STREAM_NO_SUPERVISOR;
        };
        match locked(&handle.state).supervisor.phase() {
            Phase::Unclocked => WZ_EXT_STREAM_UNCLOCKED,
            Phase::Delaying => WZ_EXT_STREAM_DELAYING,
            Phase::Inactive => WZ_EXT_STREAM_INACTIVE,
            Phase::Active => WZ_EXT_STREAM_ACTIVE,
        }
    })
}

/// What a loss of this supervisor carries: `WZ_EXT_STREAM_NOTIFY_STATUS_ONLY` or
/// `_LAST_VALUE`, the build's `e2e-supervision-notify` policy when it was made, or
/// `WZ_EXT_STREAM_NO_SUPERVISOR`.
///
/// # Safety
/// `this_` is null or a loaned supervisor.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_notify(
    this_: *const wz_ext_loaned_stream_supervisor_t,
) -> u8 {
    guard_val(WZ_EXT_STREAM_NO_SUPERVISOR, || {
        let Some(handle) = handle_of(this_) else {
            return WZ_EXT_STREAM_NO_SUPERVISOR;
        };
        match locked(&handle.state).supervisor.notify() {
            Notify::StatusOnly => WZ_EXT_STREAM_NOTIFY_STATUS_ONLY,
            Notify::LastValue => WZ_EXT_STREAM_NOTIFY_LAST_VALUE,
        }
    })
}

/// Have the library poll every `period_ms` on a task of its own, for a program that does not poll
/// on its own cadence. The callback then runs on that task. It runs until
/// `wz_ext_stream_supervisor_stop_task` or the drop.
///
/// Returns `Z_ERR_NULL` for a null supervisor or the gravestone; `Z_ERR_INVALID` for a period of 0
/// or when a task already polls this supervisor; `Z_ERR_GENERIC` when the host gave no thread;
/// `Z_OK` otherwise.
///
/// # Safety
/// `this_` is null or a loaned supervisor.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_start_task(
    this_: *const wz_ext_loaned_stream_supervisor_t,
    period_ms: u32,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        if period_ms == 0 {
            return Z_ERR_INVALID;
        }
        let mut task = locked(&handle.task);
        if task.is_some() {
            return Z_ERR_INVALID;
        }
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_of_task = Arc::clone(&stop);
        let state = Arc::clone(&handle.state);
        let period = core::time::Duration::from_millis(u64::from(period_ms));
        let spawned = spawn_task(move || {
            let (stopped, wake) = &*stop_of_task;
            while !wait_period(stopped, wake, period) {
                poll_state(&state);
            }
        });
        match spawned {
            Some(thread) => {
                *task = Some(Task { stop, thread });
                Z_OK
            }
            None => Z_ERR_GENERIC,
        }
    })
}

/// Stop the task that polls, and wait for it: no poll of it runs after this returns. Returns
/// `Z_ERR_NULL` for a null supervisor or the gravestone; `Z_ERR_GENERIC` when called from the
/// task itself (the callback), which cannot wait for its own end; `Z_OK` otherwise, also when no
/// task runs.
///
/// # Safety
/// `this_` is null or a loaned supervisor.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_stop_task(
    this_: *const wz_ext_loaned_stream_supervisor_t,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        stop_task(handle)
    })
}

/// Stop and join the task of `handle`, when one runs.
#[cfg(feature = "multi-thread")]
fn stop_task(handle: &Handle) -> ZResult {
    let mut slot = locked(&handle.task);
    let Some(task) = slot.as_ref() else {
        return Z_OK;
    };
    if is_current(&task.thread) {
        return Z_ERR_GENERIC;
    }
    let Some(task) = slot.take() else {
        return Z_OK;
    };
    drop(slot);
    let (stopped, wake) = &*task.stop;
    *locked(stopped) = true;
    wake.notify_all();
    join_task(task.thread);
    Z_OK
}

/// Borrow a supervisor. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned supervisor.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_loan(
    this_: *const wz_ext_owned_stream_supervisor_t,
) -> *const wz_ext_loaned_stream_supervisor_t {
    this_.cast::<wz_ext_loaned_stream_supervisor_t>()
}

/// The moved form of a supervisor, for `wz_ext_stream_supervisor_drop`: a cast, which nulls
/// nothing.
///
/// # Safety
/// `this_` is null or an owned supervisor.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_move(
    this_: *mut wz_ext_owned_stream_supervisor_t,
) -> *mut wz_ext_moved_stream_supervisor_t {
    this_.cast::<wz_ext_moved_stream_supervisor_t>()
}

/// Release a supervisor and leave the gravestone: its task, when one runs, is stopped first, and
/// the program's storage is its own again once this returns. A second drop, and a drop of the
/// gravestone, do nothing. Not from the callback or the clock.
///
/// # Safety
/// `this_` is null or a moved supervisor.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_stream_supervisor_drop(
    this_: *mut wz_ext_moved_stream_supervisor_t,
) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        let handle = (*this_)._this.handle;
        (*this_)._this = wz_ext_owned_stream_supervisor_t::null_value();
        if handle.is_null() {
            return Z_OK;
        }
        let handle = Box::from_raw(handle.cast::<Handle>());
        #[cfg(feature = "multi-thread")]
        let _ = stop_task(&handle);
        drop(handle);
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_stream_supervisor_null(
    this_: *mut wz_ext_owned_stream_supervisor_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_owned_stream_supervisor_t::null_value();
    }
}

/// Whether the slot holds a supervisor.
///
/// # Safety
/// `this_` is null or an owned supervisor.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_stream_supervisor_check(
    this_: *const wz_ext_owned_stream_supervisor_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_has_the_layout_the_header_declares() {
        assert_eq!(core::mem::size_of::<wz_ext_stream_slot_t>(), 20);
        assert_eq!(core::mem::align_of::<wz_ext_stream_slot_t>(), 4);
        let pointer = core::mem::size_of::<usize>();
        assert_eq!(
            core::mem::size_of::<wz_ext_stream_loss_t>(),
            16 + 2 * pointer
        );
    }

    #[test]
    fn a_null_supervisor_and_null_storage_are_refused_by_name() {
        unsafe {
            let mut slots = [wz_ext_stream_slot_t { _opaque: [0; 5] }; 1];
            assert_eq!(
                wz_ext_stream_supervisor_new(
                    core::ptr::null_mut(),
                    slots.as_mut_ptr(),
                    1,
                    core::ptr::null_mut(),
                    0,
                    0,
                    None,
                    core::ptr::null_mut(),
                ),
                Z_ERR_NULL
            );
            let mut owned = wz_ext_owned_stream_supervisor_t::null_value();
            assert_eq!(
                wz_ext_stream_supervisor_new(
                    &mut owned,
                    core::ptr::null_mut(),
                    1,
                    core::ptr::null_mut(),
                    0,
                    0,
                    None,
                    core::ptr::null_mut(),
                ),
                Z_ERR_NULL
            );
            assert_eq!(
                wz_ext_stream_supervisor_new(
                    &mut owned,
                    slots.as_mut_ptr(),
                    0,
                    core::ptr::null_mut(),
                    0,
                    0,
                    None,
                    core::ptr::null_mut(),
                ),
                Z_ERR_INVALID
            );
            assert!(!wz_ext_internal_stream_supervisor_check(&owned));
            let loaned = wz_ext_stream_supervisor_loan(&owned);
            assert_eq!(
                wz_ext_stream_supervisor_poll(loaned, core::ptr::null_mut()),
                Z_ERR_NULL
            );
            assert_eq!(
                wz_ext_stream_supervisor_phase(core::ptr::null()),
                WZ_EXT_STREAM_NO_SUPERVISOR
            );
            assert_eq!(wz_ext_stream_supervisor_node_errors(loaned), 0);
            wz_ext_stream_supervisor_drop(wz_ext_stream_supervisor_move(&mut owned));
        }
    }
}
