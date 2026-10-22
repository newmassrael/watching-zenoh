// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The per-session slot (`session-slot`, fixed-memory step S5): storage of fixed
//! size that holds ONE session, from the link it sends through to the bundle that
//! drives it, and nothing about it is behind a pointer to the heap.
//!
//! ## What a session was made of, and what it is made of here
//!
//! A session on the MCU profile used to be four allocations before it sent a
//! byte: the bundle (`Rc<SessionLinkActions>`), the kernel and the link state it
//! holds (two more `Rc`), and the link's driver (`Rc<dyn BoxedLinkDriver>`, with
//! the socket behind another `Rc<RefCell<..>>`), and a boxed entropy source. All
//! of them are one slot now:
//!
//! - the driver, by value (`D`: the lwIP profile's `LwipUdpDriver`, which holds
//!   its socket by value too);
//! - the entropy source, by value (`E`: the board's TRNG type);
//! - the bundle, by value, which holds the kernel and the link state as its own
//!   fields (see `SessionLinkActions`'s `session-slot` form).
//!
//! (Full paths in the links below, and not `Self`-relative ones: `lib.rs` carries
//! an outer `///` on this module's `pub mod` line, rustdoc merges it with this
//! `//!` and resolves the merged text at the crate root.)
//!
//! The bundle reaches the driver through a [`SlotSink`](crate::session_slot::SlotSink) (the runtime's
//! `R::LinkSink`) and the entropy source through the `&'static mut` its
//! `CookieEntropy` is, both of them references into this same slot. They are
//! references and not owners, so the slot is the only thing that owns any of it
//! and the only thing that frees it.
//!
//! ## Where a slot lives, and who may free it
//!
//! A [`SessionSlots`](crate::session_slot::SessionSlots) is a `static`: a table of
//! `N` slots the image places, the way it places its other pools
//! (`wz-link-lwip`'s transmit pool is installed the same way).
//! [`claim`](crate::session_slot::SessionSlots::claim) takes a free slot and moves
//! the driver and the entropy source into it, or refuses and COUNTS it
//! ([`refused`](crate::session_slot::SessionSlots::refused)), giving the values
//! back so the caller can close what it opened: that is the acceptor's "no slot
//! free, answer nothing" and the dialer's "exhausted, retry later".
//! [`open`](crate::session_slot::SlotClaim::open) then builds the bundle in place
//! and hands out the first [`SlotRef`](crate::session_slot::SlotRef).
//!
//! A slot is freed when the LAST handle to it is dropped, never before: every
//! handle ([`SlotRef`](crate::session_slot::SlotRef),
//! [`SlotSink`](crate::session_slot::SlotSink) once it is cloned out of the bundle,
//! [`SlotDriver`](crate::session_slot::SlotDriver), an unopened
//! [`SlotClaim`](crate::session_slot::SlotClaim)) holds a count, and the body is
//! dropped in order (bundle, entropy source, driver) when the count reaches zero.
//! That is what makes a handle a safe thing to hold: it cannot outlive what it
//! points at. The bundle's own sink is the one reference that holds no count,
//! because it lives and dies inside the slot it names; a count there would be a
//! cycle that kept the slot for ever.
//!
//! ## The contract this makes with the profile, not with the type system
//!
//! The table is not `Sync` by any means a compiler can check: it is `Sync` by
//! the profile's own rule, stated on the impl, that a session is driven by ONE
//! cooperative task on one core. Claiming and releasing are plain loads and
//! stores, not critical sections. A caller that touches a slot from an interrupt
//! handler has left the profile.
//!
//! ## What this does NOT do
//!
//! It does not own the pump, the engine or the runtime (step S6), nor the
//! socket's own storage (step S7): the socket is bound before it reaches
//! [`claim`](crate::session_slot::SessionSlots::claim) and arrives by value. And the slot is as large as the
//! bundle it holds; the size is not capped here and is not measured on a board
//! (the stack the in-place build takes is the Q lane's to catch).

use core::cell::{Cell, RefCell, UnsafeCell};
use core::mem::MaybeUninit;
use core::ops::Deref;

use wz_runtime_core::TimeSource;

use crate::entropy::EntropySource;
use crate::link::{BoxedLinkDriver, SessionRuntime};
use crate::peer_tables::PeerTables;
use crate::session_actions::SessionLinkActions;
use crate::session_init_params::SessionInitParams;

/// What every handle to one slot shares: how many handles are out, and how to
/// free the slot when the last of them goes. The first field of its cell
/// (`repr(C)`), so a reference to it is a reference to the cell.
struct SlotHead {
    /// Handles out, counting the claim. Zero for a slot that is free and for one
    /// that is being freed.
    refs: Cell<usize>,
    /// Drop the body in place and mark the slot free. Called ONCE, when `refs`
    /// reaches zero, with the head of the slot the pointer was made for.
    ///
    /// `None` while the slot is free, and set by `claim`: a table is a `static`, and a
    /// function pointer in its initial value is a non-zero byte, which makes the linker
    /// place the WHOLE table in `.data` (flash and RAM) where an all-zero one is `.bss`
    /// (RAM only). On the T2G image that was 73 KB of flash for two slots.
    release: Cell<Option<unsafe fn(&'static SlotHead)>>,
}

impl SlotHead {
    /// Count one more handle.
    fn retain(&'static self) {
        self.refs.set(self.refs.get() + 1);
    }

    /// Count one handle fewer, freeing the slot when it was the last.
    fn drop_one(&'static self) {
        let left = self.refs.get() - 1;
        self.refs.set(left);
        if left == 0 {
            // `claim` set it before the first handle existed, so a handle that
            // reaches zero always finds it.
            if let Some(release) = self.release.get() {
                // SAFETY: `release` is the one `claim` set for this cell, called with
                // that cell's own head, and exactly once: the count has just reached
                // zero, no handle holds the slot, and the slot cannot be claimed
                // again until `release` marks it free.
                unsafe { release(self) }
            }
        }
    }
}

/// A count held on a slot, and nothing else. What the handles are made of.
struct SlotGuard {
    head: &'static SlotHead,
}

impl SlotGuard {
    /// Take a new count on `head`.
    fn retain(head: &'static SlotHead) -> Self {
        head.retain();
        Self { head }
    }
}

impl Clone for SlotGuard {
    fn clone(&self) -> Self {
        Self::retain(self.head)
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.head.drop_one();
    }
}

/// How far a slot has come: free; holding its driver and entropy source (claimed,
/// not yet opened); or holding the bundle too.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CellState {
    Free,
    Claimed,
    Open,
}

/// One slot.
#[repr(C)]
struct SlotCell<R: SessionRuntime, T: TimeSource, D, E> {
    head: SlotHead,
    state: Cell<CellState>,
    driver: UnsafeCell<MaybeUninit<D>>,
    entropy: UnsafeCell<MaybeUninit<E>>,
    actions: UnsafeCell<MaybeUninit<SessionLinkActions<R, T>>>,
    /// Every table the session's PEER writes, or that is owed to it: its keyexpr
    /// aliases, the declarations it made, its interests, the replies and `Final`s
    /// its queries owe (S9a, decision Q7). The slot's own, so a session's peer can
    /// fill nothing but its own, and so each session's memory is this slot's size.
    /// Empty whenever the slot is free: a release forgets it in place.
    peers: RefCell<PeerTables>,
}

impl<R: SessionRuntime, T: TimeSource, D, E> SlotCell<R, T, D, E> {
    const fn new() -> Self {
        Self {
            head: SlotHead {
                refs: Cell::new(0),
                release: Cell::new(None),
            },
            state: Cell::new(CellState::Free),
            driver: UnsafeCell::new(MaybeUninit::uninit()),
            entropy: UnsafeCell::new(MaybeUninit::uninit()),
            actions: UnsafeCell::new(MaybeUninit::uninit()),
            peers: RefCell::new(PeerTables::new()),
        }
    }
}

/// Free a slot whose last handle has gone: drop what it holds in the order that
/// keeps every reference valid while it is used (the bundle uses the driver and
/// the entropy source when it drops, so it goes first), then mark it free.
///
/// # Safety
///
/// `head` is the head of a `SlotCell<R, T, D, E>` whose `refs` has reached zero,
/// and which has not been released since it was last claimed.
unsafe fn release_cell<R: SessionRuntime, T: TimeSource, D, E>(head: &'static SlotHead) {
    // SAFETY: `head` is the first field of a `repr(C)` `SlotCell<R, T, D, E>`
    // (the contract above), so the cell starts where it does.
    let cell = unsafe { &*(head as *const SlotHead).cast::<SlotCell<R, T, D, E>>() };
    let state = cell.state.get();
    // SAFETY: the state says which parts were written, and each is written once
    // per claim; nothing else holds a reference into the slot any more.
    unsafe {
        if state == CellState::Open {
            (*cell.actions.get()).assume_init_drop();
        }
        if state != CellState::Free {
            (*cell.entropy.get()).assume_init_drop();
            (*cell.driver.get()).assume_init_drop();
        }
    }
    // What the departed peer said is nobody's now: the next session this slot
    // holds starts from empty tables, and a peer's aliases never leak into it.
    // Nothing holds a borrow of the tables once the last handle has gone.
    cell.peers.borrow_mut().forget_peer();
    cell.state.set(CellState::Free);
}

/// The table of slots an image places: `N` of them, each able to hold one session
/// whose link is a `D` and whose entropy source is an `E`.
///
/// Declare it as a `static`:
///
/// ```text
/// static SESSIONS: SessionSlots<CoopRuntime<Clock>, CoopTime<Clock>, LwipUdpDriver, Trng, 2> =
///     SessionSlots::new();
/// ```
pub struct SessionSlots<R: SessionRuntime, T: TimeSource, D, E, const N: usize> {
    cells: [SlotCell<R, T, D, E>; N],
    refused: Cell<u32>,
}

// SAFETY: see the module's last section. A slot table is touched by the one task
// that drives its sessions (the profile is single-task and its handles are
// `!Send`), so no two threads reach it; `Sync` is what a `static` needs of it.
unsafe impl<R: SessionRuntime, T: TimeSource, D, E, const N: usize> Sync
    for SessionSlots<R, T, D, E, N>
{
}

impl<R: SessionRuntime, T: TimeSource, D, E, const N: usize> Default
    for SessionSlots<R, T, D, E, N>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<R: SessionRuntime, T: TimeSource, D, E, const N: usize> SessionSlots<R, T, D, E, N> {
    /// An empty table, for a `static`.
    pub const fn new() -> Self {
        Self {
            cells: [const { SlotCell::new() }; N],
            refused: Cell::new(0),
        }
    }

    /// How many sessions the table holds at most.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The bytes ONE slot takes where the table is placed, for this driver and
    /// entropy source: the head and state, the driver, the entropy source and the
    /// bundle, as the compiler lays them out for the target the call is compiled
    /// for. The table is `N` of these and a counter, so an image's RAM for its
    /// sessions is this times `N`, read off the types and not measured on a board.
    pub const fn slot_bytes() -> usize {
        core::mem::size_of::<SlotCell<R, T, D, E>>()
    }

    /// How many slots are taken.
    pub fn in_use(&self) -> usize {
        self.cells
            .iter()
            .filter(|cell| cell.state.get() != CellState::Free)
            .count()
    }

    /// How many claims were refused because every slot was taken, since the
    /// table was placed: the counted half of "no slot free".
    pub fn refused(&self) -> u32 {
        self.refused.get()
    }
}

impl<R, T, D, E, const N: usize> SessionSlots<R, T, D, E, N>
where
    R: SessionRuntime<LinkSink = SlotSink> + 'static,
    T: TimeSource + 'static,
    D: BoxedLinkDriver + 'static,
    E: EntropySource + Send + 'static,
{
    /// Take a free slot for a session whose link is `driver` and whose entropy
    /// source is `entropy`, moving both into it.
    ///
    /// A table with no slot free refuses: it counts the refusal and hands both
    /// values back, so the caller can close the socket it opened and answer
    /// nothing, or retry later. Nothing is allocated either way.
    pub fn claim(
        &'static self,
        driver: D,
        entropy: E,
    ) -> Result<SlotClaim<R, T, D, E>, SlotsFull<D, E>> {
        let Some(cell) = self
            .cells
            .iter()
            .find(|cell| cell.state.get() == CellState::Free)
        else {
            self.refused.set(self.refused.get().saturating_add(1));
            return Err(SlotsFull { driver, entropy });
        };
        // SAFETY: the slot is free, so nothing refers into it, and each part is
        // written once; the state below says so to `release_cell`.
        unsafe {
            (*cell.driver.get()).write(driver);
            (*cell.entropy.get()).write(entropy);
        }
        cell.state.set(CellState::Claimed);
        cell.head.refs.set(1);
        cell.head.release.set(Some(release_cell::<R, T, D, E>));
        Ok(SlotClaim { cell })
    }
}

/// A claimed slot that holds a driver and an entropy source and not yet a
/// session. Dropping it gives the slot back.
pub struct SlotClaim<R: SessionRuntime + 'static, T: TimeSource + 'static, D: 'static, E: 'static> {
    cell: &'static SlotCell<R, T, D, E>,
}

impl<R, T, D, E> SlotClaim<R, T, D, E>
where
    R: SessionRuntime<LinkSink = SlotSink> + 'static,
    T: TimeSource + 'static,
    D: BoxedLinkDriver + 'static,
    E: EntropySource + Send + 'static,
{
    /// The link driver the slot holds.
    pub fn driver(&self) -> &D {
        // SAFETY: a claim holds the slot in the `Claimed` state, so the driver
        // is written, and it is not dropped before the claim's count is.
        unsafe { (*self.cell.driver.get()).assume_init_ref() }
    }

    /// A handle to the driver that holds the slot: what the drive loop's link
    /// keeps, so the driver is there for as long as the loop reads from it.
    pub fn driver_handle(&self) -> SlotDriver<D> {
        // SAFETY: as in `driver`, and the guard holds a count for the life of
        // the reference it hands out.
        let driver: &'static D = unsafe { (*self.cell.driver.get()).assume_init_ref() };
        SlotDriver {
            guard: SlotGuard::retain(&self.cell.head),
            driver,
        }
    }

    /// Build the session in this slot: the bundle, over this driver, with this
    /// entropy source installed. Everything the session holds is in the slot
    /// afterwards, and the returned handle is the first count on it (the claim's
    /// own count moves to it).
    ///
    /// The bundle is built by value and then moved into the slot, so it is on
    /// the stack once while it is built: the in-place build the Q lane's stack
    /// verdict is there to catch on a board.
    ///
    /// Never inlined, for the stack: the bundle (2 KB on the fixed client) is a temporary of
    /// this function and is gone when it returns. Inlined into the dial, it stayed in the
    /// dial's frame while the pump and the engine were built beneath it.
    #[inline(never)]
    pub fn open(self, params: SessionInitParams, clock: T) -> SlotRef<R, T> {
        let cell = self.cell;
        // SAFETY: the claim holds the slot `Claimed`, so the driver and the
        // entropy source are written. The references made here are `'static`
        // because the slot is, and are valid until the slot is released, which
        // happens only after the bundle that holds them has dropped.
        let (driver, entropy): (&'static D, &'static mut E) = unsafe {
            (
                (*cell.driver.get()).assume_init_ref(),
                (*cell.entropy.get()).assume_init_mut(),
            )
        };
        let sink = SlotSink {
            head: &cell.head,
            driver,
            counted: false,
        };
        let actions = SessionLinkActions::<R, T>::build(sink, params, clock);
        let placed: &'static SessionLinkActions<R, T> = {
            let at = cell.actions.get().cast::<SessionLinkActions<R, T>>();
            // SAFETY: the slot's bundle cell is unwritten (the state is
            // `Claimed`), and the pointer is valid for the slot's life.
            unsafe {
                at.write(actions);
                &*at
            }
        };
        cell.state.set(CellState::Open);
        placed.install_cookie_entropy(entropy);
        // The claim's count becomes the handle's; the claim must not give it back.
        core::mem::forget(self);
        SlotRef {
            guard: SlotGuard { head: &cell.head },
            actions: placed,
            peers: &cell.peers,
        }
    }
}

impl<R: SessionRuntime + 'static, T: TimeSource + 'static, D: 'static, E: 'static> Drop
    for SlotClaim<R, T, D, E>
{
    fn drop(&mut self) {
        self.cell.head.drop_one();
    }
}

/// What a claim on a full table gives back: the values it was handed, so the
/// caller can close what it opened.
pub struct SlotsFull<D, E> {
    /// The driver the caller offered.
    pub driver: D,
    /// The entropy source the caller offered.
    pub entropy: E,
}

/// A handle to the session in a slot: what the drive loop, the FSM's action
/// binding and the application layer each hold, and the runtime's
/// `ActionsHandle`. Cloning counts; the slot is freed when the last one drops.
pub struct SlotRef<R: SessionRuntime + 'static, T: TimeSource + 'static> {
    guard: SlotGuard,
    actions: &'static SessionLinkActions<R, T>,
    peers: &'static RefCell<PeerTables>,
}

impl<R: SessionRuntime + 'static, T: TimeSource + 'static> SlotRef<R, T> {
    /// Where the bundle lies, for a caller that compares two handles.
    pub fn as_ptr(&self) -> *const SessionLinkActions<R, T> {
        self.actions
    }

    /// The tables this session's PEER writes, or that are owed to it: its keyexpr
    /// aliases, the declarations it made, its interests, the replies and `Final`s
    /// its queries owe. The slot's own, never another session's, and bounded by
    /// the deploy `limits` ([`PeerTables`]).
    ///
    /// A `RefCell`: the profile drives a session from one cooperative task, so a
    /// borrow is held across no suspension and never contended; a borrow taken
    /// while another is live is the caller's bug and panics, as it would on any
    /// other `RefCell`.
    pub fn peers(&self) -> &RefCell<PeerTables> {
        self.peers
    }
}

impl<R: SessionRuntime + 'static, T: TimeSource + 'static> Clone for SlotRef<R, T> {
    fn clone(&self) -> Self {
        Self {
            guard: self.guard.clone(),
            actions: self.actions,
            peers: self.peers,
        }
    }
}

impl<R: SessionRuntime + 'static, T: TimeSource + 'static> Deref for SlotRef<R, T> {
    type Target = SessionLinkActions<R, T>;

    fn deref(&self) -> &SessionLinkActions<R, T> {
        self.actions
    }
}

/// The runtime's `R::LinkSink` under `session-slot`: the link driver, by
/// reference, where the slot holds it.
///
/// The bundle's own copy holds no count (it lives inside the slot it names), and
/// a clone does: `Clone` is what makes a copy that can leave the bundle, so it
/// is the one that keeps the slot alive for as long as the copy is, and a sink
/// is never a reference to a driver that has gone.
pub struct SlotSink {
    head: &'static SlotHead,
    driver: &'static dyn BoxedLinkDriver,
    counted: bool,
}

impl SlotSink {
    /// The driver, for as long as this sink is borrowed.
    pub fn driver(&self) -> &dyn BoxedLinkDriver {
        self.driver
    }
}

impl Clone for SlotSink {
    fn clone(&self) -> Self {
        self.head.retain();
        Self {
            head: self.head,
            driver: self.driver,
            counted: true,
        }
    }
}

impl Drop for SlotSink {
    fn drop(&mut self) {
        if self.counted {
            self.head.drop_one();
        }
    }
}

/// A handle to the driver a slot holds, which keeps the slot: what the drive
/// loop's link holds to read from the socket it shares with the session's send
/// seam.
pub struct SlotDriver<D: 'static> {
    guard: SlotGuard,
    driver: &'static D,
}

impl<D: 'static> Clone for SlotDriver<D> {
    fn clone(&self) -> Self {
        Self {
            guard: self.guard.clone(),
            driver: self.driver,
        }
    }
}

impl<D: 'static> Deref for SlotDriver<D> {
    type Target = D;

    fn deref(&self) -> &D {
        self.driver
    }
}
