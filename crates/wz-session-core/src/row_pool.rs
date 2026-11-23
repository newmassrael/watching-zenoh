// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rows the faces of a session keep what their peers write in: for a session of many faces one
//! pool of each kind of row that they share, and for a session of one face a span of that face's
//! own for each table (`docs/c-abi-no-heap-pools.md`, section 4.5).
//!
//! # Why
//!
//! A table a peer writes is bounded for each peer (`MAX_REMOTE_DECLS` and its kin), and a session
//! that holds many peers reserving that bound for each of them reserves its faces times the worst
//! one. zenoh-pico takes each such row from its heap as it comes, with no bound. A pool sized by
//! what the whole session may hold keeps the bound of each peer, reserves the session's sum once,
//! and a peer that declares little leaves its share to the others. A session of one face has no
//! one to share with: its tables take the rows of their bound in spans of their own, laid out as
//! an inline table lays them out, and carry no link and no pool state.
//!
//! # One untyped core, thin typed wrappers
//!
//! Everything a pool and a table do to their rows (taking a row off the free list, linking it into
//! a table, walking, unlinking and compacting, giving rows back, carving spans, counting) is done
//! once, by an untyped core that knows a kind of row only as values: the bytes and alignment of a
//! row in either layout, where a pool's row keeps its link, and how its item is dropped
//! ([`RowShape`]). The core is compiled once for every kind of row and every bound, and its entry
//! points are kept out of line so an optimizer does not copy them back into each caller. A table's
//! bound `N` reaches it as a value.
//!
//! What is typed is thin: a kind ([`Seq`], [`Keyed`]) writes its item into a row, reads it out
//! and lends it, and the wrappers ([`RowPool`], [`RowSpace`], [`PooledRows`]) hand the core its
//! shape and the kind its rows. Every `unsafe` is in this module, each with the invariant it rests on.
//!
//! # Two layouts of one kind of row
//!
//! In a table's own span a row is the item itself, packed as an inline table packs it. In a shared
//! pool a row also carries its link: the next row of the table that holds it and a generation, two
//! `u16`s past the item's fields, in what the item's alignment would leave as padding where there is
//! any. The item's fields lie at the same offsets in both layouts (both are `repr(C)` with the same
//! leading fields), so a kind reaches its item the same way in either.
//!
//! # Rows and handles of a shared pool
//!
//! A row is taken from the free list, or else from the rows no table has touched yet, and given
//! back to the free list. Its generation moves when it is taken and when it is given back, odd
//! while it is held: a [`RowHandle`] names a row and the generation it was taken at, so a handle
//! kept past the row's return names nothing rather than the row's next holder. A row handed out by
//! handle is marked as such, so no handle ever reaches a row a table holds. A pool names its rows
//! by `u16`, so it holds at most [`MAX_POOL_ROWS`], which a session's open holds its limits to.
//!
//! A [`PooledRows`] is one table: in a shared pool the rows it holds, in the order they were pushed,
//! linked through the rows; in a span of its own the rows from the span's start. Either way it is a
//! pointer and three counters wherever it lies. A lookup walks the table's own rows, as a scan of an
//! inline table does; clearing or dropping the table gives back exactly its rows, one step each.
//!
//! # Who holds which rows
//!
//! A pool is reached through [`RowPool`], a handle whose copies name the same rows, and any number of
//! tables take rows of it. A span of one table's own is a [`RowSpace`] that is not copied: it is moved
//! into the one table that keeps its rows there, so two tables never lay rows over each other. A
//! session hands its tables either through a [`RowSource`], which hands a pool to every table that
//! asks and an own span to the first.
//!
//! # Refusal
//!
//! A push past the table's own bound `N`, past its span's rows, or that its pool has no row for,
//! is refused as a full inline table refuses it, the value handed back and counted by the table
//! ([`PooledRows::refusals`]); a shared pool counts what it refused too ([`RowCounts::refused`]).
//!
//! # Memory, one thread, and the lifetime
//!
//! Every row lies in memory an [`Arena`] lent at a session's open; nothing is allocated after it. As
//! the key arena's ([`crate::key_arena`]): a pool's state is kept in cells, so a [`RowPool`] and every
//! table that holds rows of one are neither `Send` nor `Sync`, and every table that holds rows of an
//! arena is dropped before the memory the arena was made over is given back
//! ([`Arena::over`]'s contract, which every pointer here rests on).

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{align_of, needs_drop, offset_of, size_of};
use core::ptr::{self, addr_of, addr_of_mut, NonNull};

use crate::bounded::{Arena, BoundedVec, CapacityFull, LendRefused, Storage, ARENA_ALIGN};

/// No row: the end of a list and of the free list, and the first row of an empty shared table.
const NIL: u16 = u16::MAX;

/// The next row of a row of a shared pool handed out by handle ([`RowPool::take`]): no table links
/// it, and no index of a row is this.
const HANDED: u16 = u16::MAX - 1;

/// The mark of a table whose rows are a span of its own: its `first` is this and its rows.
const DENSE: u16 = 0x8000;

/// The most rows a pool, or a table's own span, holds: a row is named by a `u16` below
/// the bit that marks a span of one table's own, and the largest of those is no row.
pub const MAX_POOL_ROWS: usize = 0x7FFE;

/// What a row of a shared pool carries besides its item: the next row of the table, or of the free
/// list, that holds it, and its generation.
#[derive(Clone, Copy)]
struct Link {
    next: u16,
    generation: u16,
}

/// How a kind of row is laid out, as values: all the core knows of a kind ([`RowKind::SHAPE`]).
///
/// Made by this module's kinds alone, as a constant of each, whose fields are checked when it is
/// made: both layouts start on at most an arena's alignment, and the link lies inside a pool's
/// row, aligned for it, past the item's fields.
pub struct RowShape {
    /// The bytes of a row of a table's own span: the item alone.
    item_bytes: usize,
    /// The alignment of a row of a table's own span; a power of two, at most [`ARENA_ALIGN`].
    item_align: usize,
    /// The bytes of a row of a shared pool: the item's fields and the link, a multiple of the
    /// row's alignment, which is at most [`ARENA_ALIGN`].
    slot_bytes: usize,
    /// Where a pool's row keeps its link, past the item's fields.
    link_at: usize,
    /// Whether a row starts with its id, a `u64` ([`Keyed`]).
    keyed: bool,
    /// Drops the item at a row in place; `None` when the item needs no drop.
    drop: Option<unsafe fn(NonNull<u8>)>,
}

impl RowShape {
    /// The shape of rows that are a `Row` in a table's own span and a `Slot` in a pool, whose link
    /// lies at `link_at`; `same_fields` states that the item's fields lie at the same offsets in
    /// both, which the kind reads off their declarations.
    const fn of<Row, Slot>(
        link_at: usize,
        keyed: bool,
        drop: Option<unsafe fn(NonNull<u8>)>,
        same_fields: bool,
    ) -> Self {
        assert!(
            same_fields,
            "an item's fields lie where they lie in a pool's row"
        );
        assert!(
            align_of::<Row>() <= ARENA_ALIGN && align_of::<Slot>() <= ARENA_ALIGN,
            "a row asks for more alignment than an arena's spans start on"
        );
        assert!(
            link_at % align_of::<Link>() == 0 && link_at + size_of::<Link>() <= size_of::<Slot>(),
            "a pool's row keeps its link inside it, aligned for it"
        );
        Self {
            item_bytes: size_of::<Row>(),
            item_align: align_of::<Row>(),
            slot_bytes: size_of::<Slot>(),
            link_at,
            keyed,
            drop,
        }
    }

    /// The bytes a shared pool of `rows` rows takes in an arena: its state, one span, then its
    /// rows. `None` past [`MAX_POOL_ROWS`] or the address space.
    const fn pool_bytes(&self, rows: usize) -> Option<usize> {
        if rows > MAX_POOL_ROWS {
            return None;
        }
        match rows.checked_mul(self.slot_bytes) {
            Some(slots) => match Arena::span(slots) {
                Some(slots) => slots.checked_add(STATE_BYTES),
                None => None,
            },
            None => None,
        }
    }

    /// The bytes a table's own span of `rows` rows takes, not rounded to an arena's spans. `None`
    /// past [`MAX_POOL_ROWS`] or the address space.
    const fn own_bytes(&self, rows: usize) -> Option<usize> {
        if rows > MAX_POOL_ROWS {
            return None;
        }
        rows.checked_mul(self.item_bytes)
    }
}

/// Drop the item the row at `row` holds, where its kind's items need it.
///
/// # Safety
/// The row holds an item of the kind `shape` describes, which nothing reaches after: it is dropped
/// once, here.
unsafe fn drop_item(shape: &RowShape, row: NonNull<u8>) {
    if let Some(drop) = shape.drop {
        // SAFETY: the caller's contract; `drop` is the kind's, made for its rows.
        unsafe { drop(row) }
    }
}

/// The state of a shared pool, kept at the start of the span it was lent, its rows following it
/// at [`STATE_BYTES`]. Its counters are `u16`s, as the pool names its rows by them.
struct PoolState {
    /// How many rows there are.
    rows: u16,
    /// The rows below this have been written a link; none at or past it has.
    top: Cell<u16>,
    /// The first free row below `top`, or [`NIL`].
    free: Cell<u16>,
    /// The rows held.
    used: Cell<u16>,
    /// The most `used` has been.
    peak: Cell<u16>,
    /// The rows refused for want of one, saturating.
    refused: Cell<u16>,
}

/// The bytes a pool's state takes at the start of its span: a whole span of an arena, so its rows
/// start on an arena's alignment.
const STATE_BYTES: usize = match Arena::span(size_of::<PoolState>()) {
    Some(bytes) => bytes,
    None => panic!("a pool's state fits the address space"),
};

/// A shared pool, as the core reaches it: the start of the span it was lent (`RawSpace::lent_pool`).
///
/// Invariant: `base` is the start of a span an arena lent, aligned to [`ARENA_ALIGN`] and at least
/// the pool's bytes long ([`RowShape::pool_bytes`]), its state written at its start, valid for as
/// long as any handle or table that names it lives (`Arena::over`'s contract), and laid out for one
/// shape, the one every caller of a pool passes.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Pool {
    base: NonNull<u8>,
}

impl Pool {
    /// The pool's state.
    fn state(&self) -> &PoolState {
        // SAFETY: the invariant: the span starts with the state, written when it was lent, aligned
        // for it, and alive; it is reached through shared references alone, its counters cells.
        unsafe { self.base.cast::<PoolState>().as_ref() }
    }

    /// The row at `at`, one a link has been written to.
    fn slot(&self, shape: &RowShape, at: u16) -> NonNull<u8> {
        debug_assert!(at < self.state().top.get(), "a row past those written");
        // SAFETY: `at` is below `top`, at most the pool's rows, so the row lies inside the span:
        // its rows start one state's span from its start, each `slot_bytes` long.
        unsafe {
            self.base
                .add(STATE_BYTES + usize::from(at) * shape.slot_bytes)
        }
    }

    /// The link of the row at `at`.
    fn link(&self, shape: &RowShape, at: u16) -> Link {
        // SAFETY: the row lies inside the pool (`slot`) and starts on its alignment, which the
        // shape's link offset keeps for a link; the link was written when the row was first taken,
        // before any read, and only the core writes links, by value, apart from the item's fields.
        unsafe {
            self.slot(shape, at)
                .add(shape.link_at)
                .cast::<Link>()
                .read()
        }
    }

    /// Write the link of the row at `at`.
    fn set_link(&self, shape: &RowShape, at: u16, link: Link) {
        // SAFETY: as `link`: the link lies inside the row, apart from the item's fields.
        unsafe {
            self.slot(shape, at)
                .add(shape.link_at)
                .cast::<Link>()
                .write(link)
        }
    }

    /// The row after the one at `at`, in the list or the free list that holds it.
    fn next(&self, shape: &RowShape, at: u16) -> u16 {
        self.link(shape, at).next
    }

    /// Make `next` follow the row at `at`.
    fn set_next(&self, shape: &RowShape, at: u16, next: u16) {
        let mut link = self.link(shape, at);
        link.next = next;
        self.set_link(shape, at, link);
    }

    /// A row off the free list, or else one no table has touched, held from now on with `next` as
    /// what follows it, and the generation it is held at; `None`, counted, when every row is held.
    /// The row holds no item.
    #[inline(never)]
    fn take(&self, shape: &RowShape, next: u16) -> Option<(u16, u16)> {
        let state = self.state();
        let at = match state.free.get() {
            NIL => {
                let top = state.top.get();
                if top == state.rows {
                    state.refused.set(state.refused.get().saturating_add(1));
                    return None;
                }
                state.top.set(top + 1);
                self.set_link(
                    shape,
                    top,
                    Link {
                        next: NIL,
                        generation: 0,
                    },
                );
                top
            }
            at => {
                state.free.set(self.next(shape, at));
                at
            }
        };
        let mut link = self.link(shape, at);
        // From even to odd: the row is held. `u16::MAX` is odd, so the parity holds as it wraps.
        link.generation = link.generation.wrapping_add(1);
        link.next = next;
        self.set_link(shape, at, link);
        let used = state.used.get() + 1;
        state.used.set(used);
        state.peak.set(state.peak.get().max(used));
        Some((at, link.generation))
    }

    /// Put the held row at `at` on the free list.
    ///
    /// # Safety
    /// The row is held, it holds no item (it was moved out or dropped), and no table links to it.
    #[inline(never)]
    unsafe fn release(&self, shape: &RowShape, at: u16) {
        let state = self.state();
        let mut link = self.link(shape, at);
        debug_assert_eq!(link.generation & 1, 1, "a row given back twice");
        link.generation = link.generation.wrapping_add(1);
        link.next = state.free.get();
        self.set_link(shape, at, link);
        state.free.set(at);
        state.used.set(state.used.get() - 1);
    }

    /// Whether `handle` names a row handed out by handle and held since.
    fn holds(&self, shape: &RowShape, handle: RowHandle) -> bool {
        if handle.at >= self.state().top.get() {
            return false;
        }
        let link = self.link(shape, handle.at);
        link.next == HANDED && link.generation == handle.generation
    }

    /// What the pool holds now.
    fn counts(&self) -> RowCounts {
        let state = self.state();
        RowCounts {
            rows: usize::from(state.rows),
            used: usize::from(state.used.get()),
            peak: usize::from(state.peak.get()),
            untouched: usize::from(state.rows - state.top.get()),
            refused: u32::from(state.refused.get()),
        }
    }
}

/// Where the tables of one kind keep their rows, untyped: a shared pool's span, or a table's own.
///
/// Invariant: `at` is the start of memory an arena lent, alive as long as anything names it; for a
/// pool ([`NIL`]) it holds a pool as [`Pool`] states; for an own span ([`DENSE`] and its rows) it is
/// aligned for the rows of the shape it was made for and holds that many of them.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RawSpace {
    /// The pool's state, or the first row of a table's own span.
    at: NonNull<u8>,
    /// [`NIL`] for a shared pool; [`DENSE`] and the rows for a span of one table's own.
    form: u16,
}

impl RawSpace {
    /// A pool of `rows` rows of `shape`, lent from `arena`, none of them held. Refused, taking
    /// nothing, past what is left or past [`MAX_POOL_ROWS`].
    #[inline(never)]
    fn lent_pool(arena: &mut Arena, shape: &RowShape, rows: usize) -> Result<Self, LendRefused> {
        let at = arena.lend_span(shape.pool_bytes(rows))?;
        // SAFETY: the span is the arena's next, aligned to `ARENA_ALIGN` (at least the state's
        // alignment), `pool_bytes` long and lent to nothing before; `pool_bytes` answered, so `rows`
        // is at most `MAX_POOL_ROWS` and fits the state's counter.
        unsafe {
            at.cast::<PoolState>().as_ptr().write(PoolState {
                rows: rows as u16,
                top: Cell::new(0),
                free: Cell::new(NIL),
                used: Cell::new(0),
                peak: Cell::new(0),
                refused: Cell::new(0),
            });
        }
        Ok(Self { at, form: NIL })
    }

    /// A span of one table's own of `rows` rows of `shape`, lent from `arena`, none of them
    /// holding an item. Refused, taking nothing, past what is left or past [`MAX_POOL_ROWS`].
    #[inline(never)]
    fn lent_own(arena: &mut Arena, shape: &RowShape, rows: usize) -> Result<Self, LendRefused> {
        // The span starts on an arena's alignment, at least the rows' (`RowShape::of`).
        let at = arena.lend_span(shape.own_bytes(rows))?;
        Ok(Self {
            at,
            form: DENSE | rows as u16,
        })
    }

    /// The pool, if this is one.
    fn pool(&self) -> Option<Pool> {
        (self.form == NIL).then_some(Pool { base: self.at })
    }

    /// How many rows there are.
    fn rows(&self) -> usize {
        match self.pool() {
            Some(pool) => usize::from(pool.state().rows),
            None => usize::from(self.form & !DENSE),
        }
    }
}

/// Where a table's rows lie, as the core reaches them.
enum Lay {
    /// Nowhere: the table was handed no space.
    Bare,
    /// A span of its own, its rows from `base`, `rows` of them.
    Own { base: NonNull<u8>, rows: u16 },
    /// A pool it shares.
    Pool(Pool),
}

/// Where a walk over a table stands: the row, and in a shared pool the one before it.
#[derive(Clone, Copy)]
struct Place {
    at: u16,
    prev: u16,
}

/// One table's rows, untyped: the head every [`PooledRows`] is, a pointer and three counters.
///
/// Invariant: `at` is `None` and `len` zero, or `at` is a [`RawSpace`]'s and `first` its form; in a
/// pool `first` is then the first of `len` rows the table holds, linked in push order, or [`NIL`];
/// in an own span the first `len` rows hold items. Every row the table holds holds an item of the
/// kind of the shape every caller passes it.
struct RawRows {
    /// The pool's state, or the first row of the table's span.
    at: Option<NonNull<u8>>,
    /// In a shared pool the first row, or [`NIL`]; in a span of its own [`DENSE`] and its rows.
    first: u16,
    len: u16,
    refused: u32,
}

impl RawRows {
    /// A table of no rows and no space.
    const fn new() -> Self {
        Self {
            at: None,
            first: NIL,
            len: 0,
            refused: 0,
        }
    }

    /// Where the rows lie.
    fn lay(&self) -> Lay {
        match self.at {
            None => Lay::Bare,
            Some(base) if self.first != NIL && self.first & DENSE != 0 => Lay::Own {
                base,
                rows: self.first & !DENSE,
            },
            Some(base) => Lay::Pool(Pool { base }),
        }
    }

    fn len(&self) -> usize {
        usize::from(self.len)
    }

    fn count_refused(&mut self) {
        self.refused = self.refused.saturating_add(1);
    }

    /// Take the rows pushed from here on from `space`; what the table held in another space is
    /// given back first, dropped. A table handed the space it holds keeps its rows.
    #[inline(never)]
    fn keep_rows_in(&mut self, shape: &RowShape, space: RawSpace) {
        if self.at == Some(space.at) {
            return;
        }
        self.clear(shape);
        self.at = Some(space.at);
        self.first = space.form;
    }

    /// A row for one more item, held by the table from now on, or `None`, counted, when the table
    /// holds `bound`, its span has no row left, it has no space, or its pool has none, which the
    /// pool counts too.
    ///
    /// # Safety
    /// The caller writes an item of the kind `shape` describes into the row before anything else
    /// reaches the table.
    #[inline(never)]
    unsafe fn reserve(&mut self, shape: &RowShape, bound: usize) -> Option<NonNull<u8>> {
        let row = if self.len() >= bound {
            None
        } else {
            match self.lay() {
                // SAFETY: `len` is below the span's rows, so the row lies inside the span, past the
                // rows that hold items.
                Lay::Own { base, rows } if self.len < rows => {
                    Some(unsafe { base.add(self.len() * shape.item_bytes) })
                }
                Lay::Own { .. } | Lay::Bare => None,
                Lay::Pool(pool) => match pool.take(shape, NIL) {
                    Some((at, _)) => {
                        self.append(pool, shape, at);
                        Some(pool.slot(shape, at))
                    }
                    None => None,
                },
            }
        };
        match row {
            Some(row) => {
                self.len += 1;
                Some(row)
            }
            None => {
                self.count_refused();
                None
            }
        }
    }

    /// Link the row at `at`, just taken from `pool`, after the table's last.
    fn append(&mut self, pool: Pool, shape: &RowShape, at: u16) {
        if self.first == NIL {
            self.first = at;
            return;
        }
        // No tail is kept: the walk to the last row is over the table's own rows, at most its
        // bound, as a lookup is.
        let mut last = self.first;
        loop {
            let next = pool.next(shape, last);
            if next == NIL {
                break;
            }
            last = next;
        }
        pool.set_next(shape, last, at);
    }

    /// Where a walk over the rows starts.
    fn start(&self) -> Option<Place> {
        if self.len == 0 {
            return None;
        }
        let at = match self.lay() {
            Lay::Own { .. } => 0,
            _ => self.first,
        };
        Some(Place { at, prev: NIL })
    }

    /// Where a walk goes after `place`.
    fn advance(&self, shape: &RowShape, place: Place) -> Option<Place> {
        let next = match self.lay() {
            Lay::Own { .. } => {
                let next = place.at + 1;
                (next < self.len).then_some(next)
            }
            Lay::Pool(pool) => {
                let next = pool.next(shape, place.at);
                (next != NIL).then_some(next)
            }
            Lay::Bare => None,
        }?;
        Some(Place {
            at: next,
            prev: place.at,
        })
    }

    /// The row at `place`, a place of a walk: a row the table holds, holding an item.
    fn row(&self, shape: &RowShape, place: Place) -> NonNull<u8> {
        match self.lay() {
            // SAFETY: a place of a walk is below the table's length, inside its span.
            Lay::Own { base, .. } => unsafe { base.add(usize::from(place.at) * shape.item_bytes) },
            Lay::Pool(pool) => pool.slot(shape, place.at),
            Lay::Bare => unreachable!("a table of no space holds no row"),
        }
    }

    /// The first row `which` accepts, each row handed to it once, holding its item.
    #[inline(never)]
    fn find(&self, shape: &RowShape, which: &mut dyn FnMut(NonNull<u8>) -> bool) -> Option<Place> {
        let mut at = self.start();
        while let Some(place) = at {
            if which(self.row(shape, place)) {
                return Some(place);
            }
            at = self.advance(shape, place);
        }
        None
    }

    /// The row of `id`.
    ///
    /// # Safety
    /// `shape` is a keyed kind's: every row starts with its id, a `u64`.
    #[inline(never)]
    unsafe fn find_id(&self, shape: &RowShape, id: u64) -> Option<Place> {
        debug_assert!(shape.keyed, "an id is read off a keyed row alone");
        let mut at = self.start();
        while let Some(place) = at {
            // SAFETY: the caller's contract; the row holds an item and starts on its alignment, at
            // least an id's.
            if unsafe { self.row(shape, place).cast::<u64>().read() } == id {
                return Some(place);
            }
            at = self.advance(shape, place);
        }
        None
    }

    /// Take the row at `place` out of the table, the order of the rest kept, and where the walk
    /// goes next. With `drop` its item is dropped here; a drop that panics leaks the rows from it on
    /// rather than dropping one twice.
    ///
    /// # Safety
    /// `place` is a place of a walk. Without `drop` its item was moved out: the row holds none.
    #[inline(never)]
    unsafe fn detach(&mut self, shape: &RowShape, place: Place, drop: bool) -> Option<Place> {
        match self.lay() {
            Lay::Own { base, .. } => {
                let (at, len) = (usize::from(place.at), self.len());
                if drop {
                    self.len = place.at;
                    // SAFETY: the row holds an item, dropped once, and the table no longer counts it.
                    unsafe { drop_item(shape, own_row(base, shape, at)) };
                }
                // SAFETY: the rows past `at` up to the old length hold items, inside the span; they
                // move down by one row as bytes, over the row that now holds none.
                unsafe {
                    ptr::copy(
                        own_row(base, shape, at + 1).as_ptr(),
                        own_row(base, shape, at).as_ptr(),
                        (len - at - 1) * shape.item_bytes,
                    );
                }
                self.len = (len - 1) as u16;
                (place.at < self.len).then_some(place)
            }
            Lay::Pool(pool) => {
                let next = pool.next(shape, place.at);
                if place.prev == NIL {
                    self.first = next;
                } else {
                    pool.set_next(shape, place.prev, next);
                }
                self.len -= 1;
                if drop {
                    // SAFETY: the row holds an item, dropped once; no table links to it any more,
                    // and it goes back after, so a drop that panics leaks the row.
                    unsafe { drop_item(shape, pool.slot(shape, place.at)) };
                }
                // SAFETY: the row is held, holds no item now, and no table links to it.
                unsafe { pool.release(shape, place.at) };
                (next != NIL).then_some(Place {
                    at: next,
                    prev: place.prev,
                })
            }
            Lay::Bare => None,
        }
    }

    /// Keep only the rows `keep` accepts, in order, each row handed to it once holding its item;
    /// each other row's item is dropped and the row given back.
    #[inline(never)]
    fn retain(&mut self, shape: &RowShape, keep: &mut dyn FnMut(NonNull<u8>) -> bool) {
        let mut at = self.start();
        while let Some(place) = at {
            at = if keep(self.row(shape, place)) {
                self.advance(shape, place)
            } else {
                // SAFETY: the place is one of this walk, its row holding an item.
                unsafe { self.detach(shape, place, true) }
            };
        }
    }

    /// Give every row back, each item dropped: one step for each row the table holds. A drop that
    /// panics leaks the rows after it rather than dropping one twice.
    #[inline(never)]
    fn clear(&mut self, shape: &RowShape) {
        match self.lay() {
            Lay::Own { base, .. } => {
                let len = self.len();
                self.len = 0;
                for at in 0..len {
                    // SAFETY: the rows below the old length held items, each dropped once here; the
                    // length was set first.
                    unsafe { drop_item(shape, own_row(base, shape, at)) };
                }
            }
            Lay::Pool(pool) => {
                let mut at = self.first;
                self.first = NIL;
                self.len = 0;
                while at != NIL {
                    let next = pool.next(shape, at);
                    // SAFETY: the table held the row, holding an item, dropped once; the list it
                    // was linked in is gone, and the row goes back after its item.
                    unsafe {
                        drop_item(shape, pool.slot(shape, at));
                        pool.release(shape, at);
                    }
                    at = next;
                }
            }
            Lay::Bare => {}
        }
    }
}

/// Row `at` of an own span at `base`.
///
/// # Safety
/// `at` is at most the span's rows: the row lies inside the span or at its end.
unsafe fn own_row(base: NonNull<u8>, shape: &RowShape, at: usize) -> NonNull<u8> {
    // SAFETY: the caller's contract.
    unsafe { base.add(at * shape.item_bytes) }
}

/// The start and end of `rows` rows of `shape` laid after `from` bytes of a span, aligned for
/// them. `None` past [`MAX_POOL_ROWS`] or the address space.
const fn place(from: usize, shape: &RowShape, rows: usize) -> Option<(usize, usize)> {
    let start = match from.checked_add(shape.item_align - 1) {
        Some(up) => up & !(shape.item_align - 1),
        None => return None,
    };
    match shape.own_bytes(rows) {
        Some(bytes) => match start.checked_add(bytes) {
            Some(end) => Some((start, end)),
            None => None,
        },
        None => None,
    }
}

/// One span of an arena that several tables' own spans are carved from, each from where the one
/// before ends, aligned for its rows: the tables of one face that share a bound, in one span
/// rounded to an arena's once and not once for each.
pub struct OwnSpans {
    at: NonNull<u8>,
    bytes: usize,
    laid: usize,
}

impl OwnSpans {
    /// Where the rows of a table of `rows` rows of `K` end, laid after `from` bytes of a span: what
    /// a plan of the span adds up, in the order the span is carved. `None` when `from` is, past
    /// [`MAX_POOL_ROWS`], or past the address space.
    pub const fn after<K: RowKind>(from: Option<usize>, rows: usize) -> Option<usize> {
        match from {
            Some(from) => match place(from, K::SHAPE, rows) {
                Some((_, end)) => Some(end),
                None => None,
            },
            None => None,
        }
    }

    /// A span of `bytes` bytes lent from `arena` to carve own spans from. Refused, taking nothing,
    /// past what is left.
    pub fn lent(arena: &mut Arena, bytes: usize) -> Result<Self, LendRefused> {
        let at = arena.lend_span(Some(bytes))?;
        Ok(Self { at, bytes, laid: 0 })
    }

    /// The next table's own span, of `rows` rows of `K`. Refused, carving nothing, past the span
    /// or past [`MAX_POOL_ROWS`].
    #[inline]
    pub fn carve<K: RowKind>(&mut self, rows: usize) -> Result<RowSpace<K>, LendRefused> {
        self.carve_raw(K::SHAPE, rows).map(RowSpace::of)
    }

    #[inline(never)]
    fn carve_raw(&mut self, shape: &RowShape, rows: usize) -> Result<RawSpace, LendRefused> {
        let left = self.bytes - self.laid;
        match place(self.laid, shape, rows) {
            Some((start, end)) if end <= self.bytes => {
                self.laid = end;
                // SAFETY: `start` is at most `end`, at most the span's bytes, so the rows lie inside
                // the span the arena lent; `start` is aligned for them, the span's start on an
                // arena's alignment, at least theirs (`RowShape::of`).
                let at = unsafe { self.at.add(start) };
                Ok(RawSpace {
                    at,
                    form: DENSE | rows as u16,
                })
            }
            placed => Err(LendRefused::Exhausted {
                asked: placed.map(|(_, end)| end - self.laid),
                left,
            }),
        }
    }
}

/// A kind of row: the layout of its rows, which the core reaches as values ([`Self::SHAPE`]), and
/// how an item is written into a row, read out of it and lent from it, which the typed tables
/// reach through it.
///
/// # Safety
///
/// [`Self::SHAPE`] states the kind's rows as they are: a row of a table's own span is
/// `item_bytes` long and aligned to `item_align`; a pool's row is `slot_bytes` long, with its link
/// at `link_at`; a keyed kind's rows start with their id, a `u64`; and `drop` drops an item where
/// it lies. The item's fields lie at the same offsets in both layouts, below the link, and the
/// methods below touch those fields alone, so a pool may keep the link of a row whose item is not
/// there. A kind is made by this module alone: [`RowShape`] has no constructor outside it.
pub unsafe trait RowKind {
    /// What a table puts in and takes out.
    type Item;
    /// What reading a row hands out.
    type Ref<'a>
    where
        Self: 'a;
    /// What writing a row hands out.
    type Mut<'a>
    where
        Self: 'a;

    /// The kind's rows, as the core lays them out.
    const SHAPE: &'static RowShape;

    /// Write `item` into the row at `row`.
    ///
    /// # Safety
    /// `row` is a row of the kind, in either layout, that holds no item.
    unsafe fn put(row: NonNull<u8>, item: Self::Item);

    /// Read the item out of the row at `row`, which holds none after.
    ///
    /// # Safety
    /// `row` is a row of the kind that holds an item.
    unsafe fn take(row: NonNull<u8>) -> Self::Item;

    /// The item of the row at `row`, to read.
    ///
    /// # Safety
    /// `row` is a row of the kind that holds an item, which nothing writes for `'a`.
    unsafe fn get<'a>(row: NonNull<u8>) -> Self::Ref<'a>
    where
        Self: 'a;

    /// The item of the row at `row`, to write.
    ///
    /// # Safety
    /// `row` is a row of the kind that holds an item, which nothing else reaches for `'a`.
    unsafe fn get_mut<'a>(row: NonNull<u8>) -> Self::Mut<'a>
    where
        Self: 'a;
}

/// Drop the `T` at `row` in place.
///
/// # Safety
/// `row` points at a `T`, which nothing reaches after: it is dropped once, here.
unsafe fn drop_as<T>(row: NonNull<u8>) {
    // SAFETY: the caller's contract.
    unsafe { ptr::drop_in_place(row.cast::<T>().as_ptr()) }
}

/// The kind of row of a sequence of `T` (an interest, a repeat): the item is the value.
pub struct Seq<T> {
    _item: PhantomData<T>,
}

/// A row of a shared pool of [`Seq`]: the value, then its link.
#[repr(C)]
struct SeqSlot<T> {
    item: T,
    link: Link,
}

// SAFETY: a row is the value from its start in either layout (`SeqSlot` is `repr(C)` with the
// value first), the link past it; the methods reach the value alone.
unsafe impl<T> RowKind for Seq<T> {
    type Item = T;
    type Ref<'a>
        = &'a T
    where
        Self: 'a;
    type Mut<'a>
        = &'a mut T
    where
        Self: 'a;

    const SHAPE: &'static RowShape = &RowShape::of::<T, SeqSlot<T>>(
        offset_of!(SeqSlot<T>, link),
        false,
        if needs_drop::<T>() {
            Some(drop_as::<T> as unsafe fn(NonNull<u8>))
        } else {
            None
        },
        offset_of!(SeqSlot<T>, item) == 0,
    );

    #[inline]
    unsafe fn put(row: NonNull<u8>, item: T) {
        // SAFETY: the caller's contract: the row starts with room for a `T`, holding none.
        unsafe { row.cast::<T>().as_ptr().write(item) }
    }

    #[inline]
    unsafe fn take(row: NonNull<u8>) -> T {
        // SAFETY: the caller's contract: the row holds a `T`, read out once.
        unsafe { row.cast::<T>().as_ptr().read() }
    }

    #[inline]
    unsafe fn get<'a>(row: NonNull<u8>) -> &'a T
    where
        Self: 'a,
    {
        // SAFETY: the caller's contract: the value is there and not written for `'a`.
        unsafe { row.cast::<T>().as_ref() }
    }

    #[inline]
    unsafe fn get_mut<'a>(row: NonNull<u8>) -> &'a mut T
    where
        Self: 'a,
    {
        // SAFETY: the caller's contract: the value is there and reached by nothing else.
        unsafe { row.cast::<T>().as_mut() }
    }
}

/// The kind of row of a table keyed by a peer's ids: the item is `(id, value)`.
pub struct Keyed<V> {
    _value: PhantomData<V>,
}

/// A row of a table's own span of [`Keyed`], and the leading fields of a pool's row of it.
#[repr(C)]
struct KeyedRow<V> {
    id: u64,
    value: V,
}

/// A row of a shared pool of [`Keyed`]: [`KeyedRow`]'s fields, then the link, which takes the room
/// the id and the value leave where they leave any (a value of four-byte alignment after an
/// eight-byte id, on a 32-bit core).
#[repr(C)]
struct KeyedSlot<V> {
    id: u64,
    value: V,
    link: Link,
}

/// Drop the value of the keyed row at `row` in place.
///
/// # Safety
/// `row` is a keyed row that holds an item, whose value nothing reaches after.
unsafe fn drop_value<V>(row: NonNull<u8>) {
    // SAFETY: the caller's contract; the value lies where `KeyedRow` puts it in either layout.
    unsafe { ptr::drop_in_place(addr_of_mut!((*row.cast::<KeyedRow<V>>().as_ptr()).value)) }
}

// SAFETY: both layouts are `repr(C)` and start with the id and the value, so those lie at the same
// offsets in either, the id first; the link follows them in a pool's row. The methods reach the
// two fields alone, never a whole `KeyedRow`, whose padding a pool's link may lie in.
unsafe impl<V> RowKind for Keyed<V> {
    type Item = (u64, V);
    type Ref<'a>
        = (u64, &'a V)
    where
        Self: 'a;
    type Mut<'a>
        = (u64, &'a mut V)
    where
        Self: 'a;

    const SHAPE: &'static RowShape = &RowShape::of::<KeyedRow<V>, KeyedSlot<V>>(
        offset_of!(KeyedSlot<V>, link),
        true,
        if needs_drop::<V>() {
            Some(drop_value::<V> as unsafe fn(NonNull<u8>))
        } else {
            None
        },
        offset_of!(KeyedSlot<V>, id) == 0
            && offset_of!(KeyedRow<V>, id) == 0
            && offset_of!(KeyedSlot<V>, value) == offset_of!(KeyedRow<V>, value),
    );

    #[inline]
    unsafe fn put(row: NonNull<u8>, (id, value): (u64, V)) {
        let row = row.cast::<KeyedRow<V>>().as_ptr();
        // SAFETY: the caller's contract: the row holds no item; each field is written once.
        unsafe {
            addr_of_mut!((*row).id).write(id);
            addr_of_mut!((*row).value).write(value);
        }
    }

    #[inline]
    unsafe fn take(row: NonNull<u8>) -> (u64, V) {
        let row = row.cast::<KeyedRow<V>>().as_ptr();
        // SAFETY: the caller's contract: the row holds an item, read out once.
        unsafe { (addr_of!((*row).id).read(), addr_of!((*row).value).read()) }
    }

    #[inline]
    unsafe fn get<'a>(row: NonNull<u8>) -> (u64, &'a V)
    where
        Self: 'a,
    {
        let row = row.cast::<KeyedRow<V>>().as_ptr();
        // SAFETY: the caller's contract: the item is there and not written for `'a`.
        unsafe { (addr_of!((*row).id).read(), &*addr_of!((*row).value)) }
    }

    #[inline]
    unsafe fn get_mut<'a>(row: NonNull<u8>) -> (u64, &'a mut V)
    where
        Self: 'a,
    {
        let row = row.cast::<KeyedRow<V>>().as_ptr();
        // SAFETY: the caller's contract: the item is there and reached by nothing else.
        unsafe { (addr_of!((*row).id).read(), &mut *addr_of_mut!((*row).value)) }
    }
}

/// A row a shared pool handed out ([`RowPool::take`]): where it lies and the generation it was
/// taken at. Once the row is given back the handle names nothing, though another holder takes the
/// row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowHandle {
    at: u16,
    generation: u16,
}

/// What a shared pool holds, as [`RowPool::counts`] reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowCounts {
    /// The rows the pool was lent.
    pub rows: usize,
    /// The rows held now.
    pub used: usize,
    /// The most rows held at once.
    pub peak: usize,
    /// The rows no table has touched since the pool was lent.
    pub untouched: usize,
    /// The rows refused for want of one: the pool was full. Saturates at `u16::MAX`.
    pub refused: u32,
}

/// A pool of rows of one kind the tables of a session's faces share, lent from its arena
/// ([`Arena::lend_pool`]). A handle: copies name the same rows, and each table takes rows of it
/// through a space of its own ([`Self::space`]).
pub struct RowPool<K: RowKind> {
    pool: Pool,
    _kind: PhantomData<*const K>,
}

impl<K: RowKind> Clone for RowPool<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: RowKind> Copy for RowPool<K> {}

impl<K: RowKind> PartialEq for RowPool<K> {
    fn eq(&self, other: &Self) -> bool {
        self.pool == other.pool
    }
}

impl<K: RowKind> Eq for RowPool<K> {}

impl<K: RowKind> RowPool<K> {
    /// A pool of `rows` rows lent from `arena`. Refused, taking nothing, past what is left or past
    /// [`MAX_POOL_ROWS`].
    #[inline]
    pub(crate) fn lent(arena: &mut Arena, rows: usize) -> Result<Self, LendRefused> {
        let raw = RawSpace::lent_pool(arena, K::SHAPE, rows)?;
        Ok(Self {
            pool: Pool { base: raw.at },
            _kind: PhantomData,
        })
    }

    /// Where a table takes rows of this pool: any number of tables may.
    #[inline]
    pub fn space(&self) -> RowSpace<K> {
        RowSpace::of(RawSpace {
            at: self.pool.base,
            form: NIL,
        })
    }

    /// How many rows there are.
    pub fn rows(&self) -> usize {
        usize::from(self.pool.state().rows)
    }

    /// What the pool holds now.
    pub fn counts(&self) -> RowCounts {
        self.pool.counts()
    }

    /// A row holding `item`, or the item back when every row is held, which the pool counts.
    #[inline]
    pub fn take(&self, item: K::Item) -> Result<RowHandle, CapacityFull<K::Item>> {
        let Some((at, generation)) = self.pool.take(K::SHAPE, HANDED) else {
            return Err(CapacityFull(item));
        };
        // SAFETY: the row was just taken, so it is a row of the kind holding no item.
        unsafe { K::put(self.pool.slot(K::SHAPE, at), item) };
        Ok(RowHandle { at, generation })
    }

    /// The item of the row `handle` names, the row back on the free list; `None`, and nothing
    /// done, when the handle names no row held by handle since it was taken.
    #[inline]
    pub fn give_back(&self, handle: RowHandle) -> Option<K::Item> {
        if !self.holds(handle) {
            return None;
        }
        let row = self.pool.slot(K::SHAPE, handle.at);
        // SAFETY: the row is held at the handle's generation and marked as handed out, so it was
        // written an item by `take` and no table links to it; the item is read out once, then the
        // row, holding none, goes back.
        unsafe {
            let item = K::take(row);
            self.pool.release(K::SHAPE, handle.at);
            Some(item)
        }
    }

    /// Whether `handle` names a row held since it was taken.
    pub fn holds(&self, handle: RowHandle) -> bool {
        self.pool.holds(K::SHAPE, handle)
    }
}

impl<K: RowKind> fmt::Debug for RowPool<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RowPool")
            .field("counts", &self.counts())
            .finish()
    }
}

/// Where one table keeps its rows ([`PooledRows::keep_rows_in`]): rows of a pool it shares, or a
/// span of its own. Not copied: a span of one table's own is lent once ([`Arena::lend_own`]) and
/// moved into the table that keeps its rows there, so no other lays rows over them.
pub struct RowSpace<K: RowKind> {
    raw: RawSpace,
    _kind: PhantomData<*const K>,
}

impl<K: RowKind> RowSpace<K> {
    /// The space at `raw`, made for `K`'s shape.
    fn of(raw: RawSpace) -> Self {
        Self {
            raw,
            _kind: PhantomData,
        }
    }

    /// A span of one table's own of `rows` rows, lent from `arena`. Refused, taking nothing, past
    /// what is left or past [`MAX_POOL_ROWS`].
    #[inline]
    pub(crate) fn lent_own(arena: &mut Arena, rows: usize) -> Result<Self, LendRefused> {
        RawSpace::lent_own(arena, K::SHAPE, rows).map(Self::of)
    }

    /// The bytes one row of a shared pool takes: its item's fields and its link.
    pub const fn slot_bytes() -> usize {
        K::SHAPE.slot_bytes
    }

    /// The bytes one row of a table's own span takes: its item alone.
    pub const fn item_bytes() -> usize {
        K::SHAPE.item_bytes
    }

    /// The alignment a table's own span starts on: its item's.
    pub const fn item_align() -> usize {
        K::SHAPE.item_align
    }

    /// The bytes a shared pool of `rows` rows takes in an [`Arena`]: its state and its rows.
    /// `None` past [`MAX_POOL_ROWS`] or the address space.
    pub const fn pool_bytes(rows: usize) -> Option<usize> {
        K::SHAPE.pool_bytes(rows)
    }

    /// The bytes a table's own span of `rows` rows takes, not rounded to an arena's spans. `None`
    /// past [`MAX_POOL_ROWS`] or the address space.
    pub const fn own_bytes(rows: usize) -> Option<usize> {
        K::SHAPE.own_bytes(rows)
    }

    /// Whether these are rows of a pool the faces share, and not a span of one table's own.
    pub fn is_shared(&self) -> bool {
        self.raw.form == NIL
    }

    /// How many rows there are: the pool's, or the span's.
    pub fn rows(&self) -> usize {
        self.raw.rows()
    }
}

impl<K: RowKind> fmt::Debug for RowSpace<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RowSpace")
            .field("shared", &self.is_shared())
            .field("rows", &self.rows())
            .finish()
    }
}

/// Where the tables of one kind of row of a session take their rows: a pool every table that asks
/// takes rows of, or one table's own span, handed to the first table that asks and to no other.
pub enum RowSource<K: RowKind> {
    /// A pool the faces share.
    Pool(RowPool<K>),
    /// A span of one table's own, until it is handed out.
    Own(Option<RowSpace<K>>),
}

impl<K: RowKind> RowSource<K> {
    /// A space for one more table: of the pool, as often as asked; the own span, once.
    #[inline]
    pub fn hand_out(&mut self) -> Option<RowSpace<K>> {
        match self {
            Self::Pool(pool) => Some(pool.space()),
            Self::Own(own) => own.take(),
        }
    }

    /// Whether the tables share these rows.
    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Pool(_))
    }

    /// What a shared pool holds now; `None` for a span of one table's own, whose table says what it
    /// holds.
    pub fn counts(&self) -> Option<RowCounts> {
        match self {
            Self::Pool(pool) => Some(pool.counts()),
            Self::Own(_) => None,
        }
    }
}

impl<K: RowKind> fmt::Debug for RowSource<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pool(pool) => f.debug_tuple("Pool").field(pool).finish(),
            Self::Own(own) => f.debug_tuple("Own").field(own).finish(),
        }
    }
}

/// One table of a kind of row: at most `N` rows, in the order they were pushed, in a pool the
/// session's faces share or in a span of its own ([`Self::keep_rows_in`]). Made with neither
/// ([`Self::new`], `Default`), it refuses every item as a full table does until it is handed one.
/// Dropped or cleared, it gives back exactly the rows it holds. It is a pointer and three counters
/// wherever it lies, the refusals among them; what it does to its rows is the core's, once for
/// every kind and bound.
pub struct PooledRows<K: RowKind, const N: usize> {
    raw: RawRows,
    _items: PhantomData<(K, K::Item)>,
}

impl<K: RowKind, const N: usize> PooledRows<K, N> {
    /// A table of no rows and no space. `const`, as an inline table's constructor is.
    pub const fn new() -> Self {
        Self {
            raw: RawRows::new(),
            _items: PhantomData,
        }
    }

    /// Take the rows pushed from here on from `space`. A table keeps the space it holds rows of:
    /// one that holds rows of another is emptied first, as its rows belong to the space it held
    /// before.
    #[inline]
    pub fn keep_rows_in(&mut self, space: RowSpace<K>) {
        self.raw.keep_rows_in(K::SHAPE, space.raw);
    }

    /// The most rows the table holds: the bound of one table, whatever its space has left.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many rows the table holds.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Whether the table holds no row.
    pub fn is_empty(&self) -> bool {
        self.raw.len == 0
    }

    /// How many items the table refused since it was made: past its bound, past its span, for want
    /// of a pool's row or of any space, or as its owner counted ([`Self::count_refused`]).
    pub fn refusals(&self) -> u32 {
        self.raw.refused
    }

    /// Count an item refused before it reached the table, as one it had no room for is.
    pub fn count_refused(&mut self) {
        self.raw.count_refused();
    }

    /// Append `item`, or hand it back, counted: the table holds `N` rows, its span has no row
    /// left, it was handed no space, or its pool has no row left, which the pool counts too.
    #[inline]
    pub fn push(&mut self, item: K::Item) -> Result<(), CapacityFull<K::Item>> {
        // SAFETY: the row handed back is written at once, before anything else reaches the table.
        match unsafe { self.raw.reserve(K::SHAPE, N) } {
            Some(row) => {
                // SAFETY: a reserved row is a row of the kind holding no item.
                unsafe { K::put(row, item) };
                Ok(())
            }
            None => Err(CapacityFull(item)),
        }
    }

    /// The rows, in the order they were pushed.
    #[inline]
    pub fn iter(&self) -> Rows<'_, K> {
        Rows {
            raw: &self.raw,
            at: self.raw.start(),
            left: self.raw.len,
            _kind: PhantomData,
        }
    }

    /// The rows, to write, in the order they were pushed.
    #[inline]
    pub fn iter_mut(&mut self) -> RowsMut<'_, K> {
        let raw = &self.raw;
        RowsMut {
            at: raw.start(),
            left: raw.len,
            raw,
            _kind: PhantomData,
        }
    }

    /// Give every row back, each item dropped: one step for each row the table holds.
    #[inline]
    pub fn clear(&mut self) {
        self.raw.clear(K::SHAPE);
    }

    /// Take the item at `place` out of the table, its row given back.
    ///
    /// # Safety
    /// `place` is a place of a walk over this table, its row holding an item.
    #[inline]
    unsafe fn take_at(&mut self, place: Place) -> K::Item {
        // SAFETY: the caller's contract: the row holds an item, read out once; the row, holding
        // none, then leaves the table.
        unsafe {
            let item = K::take(self.raw.row(K::SHAPE, place));
            self.raw.detach(K::SHAPE, place, false);
            item
        }
    }
}

impl<T, const N: usize> PooledRows<Seq<T>, N> {
    /// Keep only the values `keep` accepts, in order; each other row is given back.
    #[inline]
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, mut keep: F) {
        self.raw
            .retain(<Seq<T> as RowKind>::SHAPE, &mut |row: NonNull<u8>| {
                // SAFETY: the core hands each row the table holds once, holding its value, which
                // nothing else reaches during the call.
                keep(unsafe { <Seq<T> as RowKind>::get(row) })
            });
    }

    /// Take the first value `which` accepts out of the table, its row given back.
    #[inline]
    pub fn remove_first<F: FnMut(&T) -> bool>(&mut self, mut which: F) -> Option<T> {
        let place = self
            .raw
            .find(<Seq<T> as RowKind>::SHAPE, &mut |row: NonNull<u8>| {
                // SAFETY: as `retain`'s.
                which(unsafe { <Seq<T> as RowKind>::get(row) })
            })?;
        // SAFETY: the place was found by a walk over this table.
        Some(unsafe { self.take_at(place) })
    }
}

impl<V, const N: usize> PooledRows<Keyed<V>, N> {
    /// The value of `id`.
    #[inline]
    pub fn get_id(&self, id: u64) -> Option<&V> {
        let shape = <Keyed<V> as RowKind>::SHAPE;
        // SAFETY: the shape is a keyed kind's.
        let place = unsafe { self.raw.find_id(shape, id) }?;
        // SAFETY: the place is a row the table holds, holding an item, and the table is borrowed
        // for as long as the reference lives.
        Some(unsafe { <Keyed<V> as RowKind>::get(self.raw.row(shape, place)) }.1)
    }

    /// The value of `id`, to write.
    #[inline]
    pub fn get_id_mut(&mut self, id: u64) -> Option<&mut V> {
        let shape = <Keyed<V> as RowKind>::SHAPE;
        // SAFETY: the shape is a keyed kind's.
        let place = unsafe { self.raw.find_id(shape, id) }?;
        // SAFETY: as `get_id`'s, the table borrowed mutably for as long.
        Some(unsafe { <Keyed<V> as RowKind>::get_mut(self.raw.row(shape, place)) }.1)
    }

    /// Take the row of `id` out of the table, its row given back, and hand back its value.
    #[inline]
    pub fn remove_id(&mut self, id: u64) -> Option<V> {
        // SAFETY: the shape is a keyed kind's.
        let place = unsafe { self.raw.find_id(<Keyed<V> as RowKind>::SHAPE, id) }?;
        // SAFETY: the place was found by a walk over this table.
        Some(unsafe { self.take_at(place) }.1)
    }
}

impl<K: RowKind, const N: usize> Default for PooledRows<K, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: RowKind, const N: usize> Drop for PooledRows<K, N> {
    fn drop(&mut self) {
        self.raw.clear(K::SHAPE);
    }
}

impl<K: RowKind, const N: usize> fmt::Debug for PooledRows<K, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let own = match self.raw.lay() {
            Lay::Own { rows, .. } => Some(rows),
            _ => None,
        };
        f.debug_struct("PooledRows")
            .field("len", &self.raw.len)
            .field("own", &own)
            .field("refused", &self.raw.refused)
            .finish()
    }
}

/// The rows of a [`PooledRows`], in the order they were pushed.
pub struct Rows<'a, K: RowKind> {
    raw: &'a RawRows,
    at: Option<Place>,
    left: u16,
    _kind: PhantomData<&'a K>,
}

impl<'a, K: RowKind> Iterator for Rows<'a, K> {
    type Item = K::Ref<'a>;

    #[inline]
    fn next(&mut self) -> Option<K::Ref<'a>> {
        let place = self.at?;
        self.at = self.raw.advance(K::SHAPE, place);
        self.left -= 1;
        // SAFETY: the place is a row the table holds, holding an item, and the table is borrowed
        // for `'a`, so the row is not written or given back meanwhile.
        Some(unsafe { K::get(self.raw.row(K::SHAPE, place)) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::from(self.left), Some(usize::from(self.left)))
    }
}

impl<K: RowKind> ExactSizeIterator for Rows<'_, K> {}

/// The rows of a [`PooledRows`], to write, in the order they were pushed.
pub struct RowsMut<'a, K: RowKind> {
    /// The table's head, read only: the walk holds the table's mutable borrow for `'a`, and the rows
    /// it hands out lie in the space, not in the head.
    raw: &'a RawRows,
    at: Option<Place>,
    left: u16,
    _kind: PhantomData<&'a mut K>,
}

impl<'a, K: RowKind> Iterator for RowsMut<'a, K> {
    type Item = K::Mut<'a>;

    #[inline]
    fn next(&mut self) -> Option<K::Mut<'a>> {
        let place = self.at?;
        self.at = self.raw.advance(K::SHAPE, place);
        self.left -= 1;
        // SAFETY: the table is borrowed mutably for `'a` by this walk alone, which visits each row
        // once, so no other reference to the row is handed out meanwhile.
        Some(unsafe { K::get_mut(self.raw.row(K::SHAPE, place)) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::from(self.left), Some(usize::from(self.left)))
    }
}

impl<K: RowKind> ExactSizeIterator for RowsMut<'_, K> {}

/// A table of rows a peer writes, as a storage policy keeps it ([`Storage::Pooled`]): an inline or
/// growable sequence on the policies that keep their own rows, and on the lent one a
/// [`PooledRows`] of [`Seq`]. The operations the tables above it need, written once for every
/// policy.
pub trait RowList<T>: Default {
    /// How many values the table holds.
    fn len(&self) -> usize;

    /// Whether the table holds no value.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append `value`, or hand it back when the table or its space has no room.
    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>>;

    /// The values, in order.
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a;

    /// The values, mutably, in order.
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a;

    /// Keep only the values `keep` accepts, in order.
    fn retain<F: FnMut(&T) -> bool>(&mut self, keep: F);

    /// Take the first value `which` accepts out of the table.
    fn remove_first<F: FnMut(&T) -> bool>(&mut self, which: F) -> Option<T>;

    /// Drop every value.
    fn clear(&mut self);
}

impl<T, const N: usize, P: Storage> RowList<T> for BoundedVec<T, N, P> {
    fn len(&self) -> usize {
        <[T]>::len(self)
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        BoundedVec::push(self, value)
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a,
    {
        <[T]>::iter(self)
    }

    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a,
    {
        <[T]>::iter_mut(self)
    }

    fn retain<F: FnMut(&T) -> bool>(&mut self, keep: F) {
        BoundedVec::retain(self, keep);
    }

    fn remove_first<F: FnMut(&T) -> bool>(&mut self, which: F) -> Option<T> {
        let at = <[T]>::iter(self).position(which)?;
        Some(BoundedVec::remove(self, at))
    }

    fn clear(&mut self) {
        BoundedVec::clear(self);
    }
}

impl<T, const N: usize> RowList<T> for PooledRows<Seq<T>, N> {
    fn len(&self) -> usize {
        PooledRows::len(self)
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        PooledRows::push(self, value)
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a,
    {
        PooledRows::iter(self)
    }

    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a,
    {
        PooledRows::iter_mut(self)
    }

    fn retain<F: FnMut(&T) -> bool>(&mut self, keep: F) {
        PooledRows::retain(self, keep);
    }

    fn remove_first<F: FnMut(&T) -> bool>(&mut self, which: F) -> Option<T> {
        PooledRows::remove_first(self, which)
    }

    fn clear(&mut self) {
        PooledRows::clear(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Static;
    use std::rc::Rc;
    use std::vec::Vec;

    /// One block of an arena's memory in a test, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block {
        _bytes: [u8; ARENA_ALIGN],
    }

    /// An arena over `bytes` bytes of memory the test process leaks, so it outlives every row.
    fn arena_of(bytes: usize) -> Arena {
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] =
            std::vec![Block { _bytes: [0; ARENA_ALIGN] }; blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `bytes` bytes, and is
        // leaked, so nothing else uses it and it outlives every row.
        unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) }
    }

    /// A shared pool of `rows` rows, lent from an arena of exactly its span.
    fn pool_of<K: RowKind>(rows: usize) -> RowPool<K> {
        let span = RowSpace::<K>::pool_bytes(rows).expect("a test pool fits");
        let mut arena = arena_of(span);
        let pool = arena.lend_pool(rows).expect("the arena is the pool's span");
        assert_eq!(arena.high_water(), span, "the span is what the pool takes");
        pool
    }

    /// A span of one table's own of `rows` rows.
    fn own_of<K: RowKind>(rows: usize) -> RowSpace<K> {
        let bytes = Arena::span(RowSpace::<K>::own_bytes(rows).expect("fits")).expect("fits");
        arena_of(bytes)
            .lend_own(rows)
            .expect("the arena is the span")
    }

    fn values<const N: usize>(table: &PooledRows<Seq<u32>, N>) -> Vec<u32> {
        table.iter().copied().collect()
    }

    /// The `u32`s a raw table of `Seq<u32>` holds, in its order, read off the rows the core walks.
    fn raw_values(raw: &RawRows) -> Vec<u32> {
        let shape = <Seq<u32> as RowKind>::SHAPE;
        let mut out = Vec::new();
        let mut at = raw.start();
        while let Some(place) = at {
            // SAFETY: a place of a walk is a row the table holds, holding a `u32`.
            out.push(unsafe { raw.row(shape, place).cast::<u32>().read() });
            at = raw.advance(shape, place);
        }
        out
    }

    /// Push `value` into a raw table of `Seq<u32>` under `bound`, as the typed table does.
    fn raw_push(raw: &mut RawRows, bound: usize, value: u32) -> bool {
        // SAFETY: the row is written at once.
        match unsafe { raw.reserve(<Seq<u32> as RowKind>::SHAPE, bound) } {
            Some(row) => {
                // SAFETY: a reserved row holds no item and has room for a `u32`.
                unsafe { row.cast::<u32>().as_ptr().write(value) };
                true
            }
            None => false,
        }
    }

    /// A kind reaches the core as values alone: its rows' bytes, their alignment, where a pool's row
    /// keeps its link, whether it is keyed and whether its item is dropped. A link is two `u16`s,
    /// and where the item's fields leave room a pool's row is no longer than a table's own row: an
    /// id and a value of four-byte alignment (a key's place on a 32-bit core) take the link into the
    /// padding the pair leaves. A pool's state is six `u16`s, one span of an arena.
    #[test]
    fn a_kind_reaches_the_core_as_its_shape_alone() {
        assert_eq!(size_of::<Link>(), 4);
        let seq = <Seq<u32> as RowKind>::SHAPE;
        assert_eq!(
            (seq.item_bytes, seq.item_align, seq.slot_bytes, seq.link_at),
            (4, 4, 8, 4),
            "a four-byte value, then its link"
        );
        assert!(!seq.keyed && seq.drop.is_none());
        assert!(
            <Seq<Rc<()>> as RowKind>::SHAPE.drop.is_some(),
            "an item that needs a drop"
        );
        let keyed = <Keyed<[u32; 3]> as RowKind>::SHAPE;
        assert_eq!(
            (keyed.item_bytes, keyed.slot_bytes),
            (size_of::<(u64, [u32; 3])>(), size_of::<(u64, [u32; 3])>()),
            "the link takes the padding of an id and a three-word value"
        );
        assert!(keyed.keyed && keyed.drop.is_none());
        assert!(
            <Keyed<crate::key_arena::KeyRef> as RowKind>::SHAPE.slot_bytes
                <= size_of::<(u64, crate::key_arena::KeyRef)>() + size_of::<Link>()
        );
        assert_eq!((size_of::<PoolState>(), STATE_BYTES), (12, ARENA_ALIGN));
        assert!(RowSpace::<Seq<u8>>::pool_bytes(MAX_POOL_ROWS).is_some());
        assert_eq!(RowSpace::<Seq<u8>>::pool_bytes(MAX_POOL_ROWS + 1), None);
        assert_eq!(RowSpace::<Seq<u8>>::own_bytes(MAX_POOL_ROWS + 1), None);
    }

    /// The core's free list hands back the row given back last, its generation moved on each take
    /// and each return, odd while held; a row no table touched is taken only once the free list is
    /// empty, and the pool counts what it refused.
    #[test]
    fn the_core_reuses_the_last_row_given_back_and_moves_its_generation() {
        let shape = <Seq<u32> as RowKind>::SHAPE;
        let pool = pool_of::<Seq<u32>>(3).pool;
        assert_eq!(pool.take(shape, NIL), Some((0, 1)));
        assert_eq!(pool.take(shape, NIL), Some((1, 1)));
        // SAFETY: row 0 is held, holds no item (none was written), and no table links it.
        unsafe { pool.release(shape, 0) };
        assert_eq!(pool.counts().untouched, 1);
        assert_eq!(
            pool.take(shape, NIL),
            Some((0, 3)),
            "the row given back, again"
        );
        assert_eq!(
            pool.take(shape, NIL),
            Some((2, 1)),
            "then the untouched one"
        );
        assert_eq!(pool.take(shape, NIL), None);
        let counts = pool.counts();
        assert_eq!(
            (counts.used, counts.peak, counts.untouched, counts.refused),
            (3, 3, 0, 1)
        );
    }

    /// The core walks, takes out and compacts a table by the shape alone, in either layout: a row
    /// taken out of the middle keeps the order of the rest, the bound and the span refuse past them
    /// and count it, and in a pool the row taken out is the next one a push takes.
    #[test]
    fn the_core_keeps_a_raw_tables_order_through_a_detach_in_either_layout() {
        let shape = <Seq<u32> as RowKind>::SHAPE;
        let pool = pool_of::<Seq<u32>>(4);
        for space in [pool.space().raw, own_of::<Seq<u32>>(3).raw] {
            let mut raw = RawRows::new();
            raw.keep_rows_in(shape, space);
            for v in [1, 2, 3] {
                assert!(raw_push(&mut raw, 3, v));
            }
            assert!(!raw_push(&mut raw, 3, 4), "the bound");
            assert_eq!(raw.refused, 1);
            let middle = raw
                .advance(shape, raw.start().expect("rows"))
                .expect("a second row");
            // SAFETY: the place is one of a walk; the `u32` needs no drop, so dropping is moving out.
            let next = unsafe { raw.detach(shape, middle, true) }.expect("a row after it");
            // SAFETY: as above.
            assert_eq!(unsafe { raw.row(shape, next).cast::<u32>().read() }, 3);
            assert_eq!(raw_values(&raw), [1, 3]);
            assert!(raw_push(&mut raw, 3, 5));
            assert_eq!(raw_values(&raw), [1, 3, 5]);
            raw.clear(shape);
            assert_eq!(raw.len(), 0);
        }
        assert_eq!(pool.counts().used, 0, "a clear gives every row back");
        let mut own = RawRows::new();
        own.keep_rows_in(shape, own_of::<Seq<u32>>(1).raw);
        assert!(raw_push(&mut own, 8, 1));
        assert!(
            !raw_push(&mut own, 8, 2),
            "the span's rows, under the bound"
        );
        assert_eq!(own.refused, 1);
    }

    /// A handle never reaches a row a table holds, even one at the generation the handle names: a
    /// row handed out by handle is marked so, and a table's row is not.
    #[test]
    fn a_stale_handle_never_reaches_a_row_a_table_holds() {
        let pool = pool_of::<Seq<u32>>(1);
        let handle = pool.take(7).expect("the row is free");
        assert_eq!(pool.give_back(handle), Some(7));
        let mut table = PooledRows::<Seq<u32>, 4>::new();
        table.keep_rows_in(pool.space());
        table.push(9).expect("the row given back");
        let forged = RowHandle {
            at: handle.at,
            generation: handle.generation + 2,
        };
        assert!(
            !pool.holds(forged),
            "the generation matches, the mark does not"
        );
        assert_eq!(pool.give_back(forged), None);
        assert_eq!(values(&table), [9]);
    }

    /// Spans carved from one span lie where their plan says, each aligned for its rows; one past the
    /// span is refused, carving nothing, and the tables over the spans keep their rows apart.
    #[test]
    fn own_spans_lie_where_their_plan_lays_them() {
        let word = 3usize.next_multiple_of(align_of::<u64>());
        let bytes = OwnSpans::after::<Seq<u64>>(OwnSpans::after::<Seq<u8>>(Some(0), 3), 2);
        assert_eq!(
            bytes,
            Some(word + 2 * size_of::<u64>()),
            "three bytes, then two words from the next word"
        );
        let bytes = bytes.expect("fits");
        let mut span = OwnSpans::lent(&mut arena_of(Arena::span(bytes).expect("fits")), bytes)
            .expect("the arena is the span");
        let small = span.carve::<Seq<u8>>(3).expect("the first table's rows");
        let words = span.carve::<Seq<u64>>(2).expect("the second's");
        assert_eq!(
            words.raw.at.as_ptr() as usize - small.raw.at.as_ptr() as usize,
            word,
            "aligned for a word"
        );
        assert!(matches!(
            span.carve::<Seq<u8>>(1),
            Err(LendRefused::Exhausted {
                asked: Some(1),
                left: 0
            })
        ));
        let (mut a, mut b) = (
            PooledRows::<Seq<u8>, 3>::new(),
            PooledRows::<Seq<u64>, 2>::new(),
        );
        a.keep_rows_in(small);
        b.keep_rows_in(words);
        for v in [1, 2, 3] {
            a.push(v).expect("room");
        }
        b.push(u64::MAX).expect("room");
        assert_eq!(a.iter().copied().collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(b.iter().copied().collect::<Vec<_>>(), [u64::MAX]);
    }

    /// A source hands a pool to every table that asks and an own span to the first alone.
    #[test]
    fn a_source_hands_a_pool_to_every_table_and_an_own_span_once() {
        let mut shared = RowSource::Pool(pool_of::<Seq<u32>>(2));
        assert!(shared.hand_out().is_some() && shared.hand_out().is_some());
        assert!(shared.is_shared());
        let mut own = RowSource::Own(Some(own_of::<Seq<u32>>(2)));
        assert!(own.hand_out().is_some_and(|space| !space.is_shared()));
        assert!(own.hand_out().is_none(), "the span went to the first");
        assert_eq!((own.is_shared(), own.counts()), (false, None));
    }

    /// A shared pool lends its rows by handle until every one is held, refuses the next and counts
    /// it, and a row given back is taken again. A handle names its row only until the row goes back.
    #[test]
    fn a_handle_names_its_row_until_the_row_goes_back() {
        let pool = pool_of::<Seq<u32>>(2);
        let first = pool.take(10).expect("a row is free");
        let second = pool.take(20).expect("the last row is free");
        assert_eq!(pool.take(30).err().map(|full| full.0), Some(30));
        let counts = pool.counts();
        assert_eq!((counts.used, counts.refused), (2, 1));
        assert_eq!(pool.give_back(first), Some(10));
        assert_eq!(
            pool.give_back(first),
            None,
            "a handle given back names nothing"
        );
        let again = pool.take(40).expect("the row given back is free");
        assert!(
            !pool.holds(first),
            "the old handle does not name the row's new holder"
        );
        assert!(pool.holds(again) && pool.holds(second));
        assert_eq!(pool.give_back(again), Some(40));
        assert_eq!(pool.counts().peak, 2);
    }

    /// Many tables, each bounded at sixteen rows, each holding three, fit a pool of the rows they
    /// hold together; the next push of any of them is refused and counted by the pool and by the
    /// table, and every table keeps what it held.
    #[test]
    fn many_tables_holding_a_few_rows_fit_a_pool_far_smaller_than_their_bounds() {
        const TABLES: usize = 8;
        let pool = pool_of::<Seq<u32>>(TABLES * 3);
        let mut tables: Vec<PooledRows<Seq<u32>, 16>> =
            (0..TABLES).map(|_| PooledRows::new()).collect();
        for (n, table) in tables.iter_mut().enumerate() {
            table.keep_rows_in(pool.space());
            for k in 0..3 {
                assert!(table.push((n * 10 + k) as u32).is_ok(), "table {n} row {k}");
            }
        }
        assert_eq!(pool.counts().used, TABLES * 3);
        assert_eq!(tables[5].push(99).err().map(|full| full.0), Some(99));
        assert_eq!(
            (tables[5].len(), tables[5].refusals(), pool.counts().refused),
            (3, 1, 1),
            "the refusal takes nothing and is counted by the table and the pool"
        );
        for (n, table) in tables.iter().enumerate() {
            let n = n as u32;
            assert_eq!(values(table), [n * 10, n * 10 + 1, n * 10 + 2]);
        }
    }

    /// Clearing a table gives back exactly its rows: the pool holds the other tables' rows still,
    /// their values intact, and the rows given back hold the next table's values.
    #[test]
    fn clearing_a_table_gives_back_exactly_its_rows() {
        let pool = pool_of::<Seq<u32>>(5);
        let (mut a, mut b) = (
            PooledRows::<Seq<u32>, 4>::new(),
            PooledRows::<Seq<u32>, 4>::new(),
        );
        a.keep_rows_in(pool.space());
        b.keep_rows_in(pool.space());
        for v in [1, 2, 3] {
            a.push(v).expect("room");
        }
        for v in [7, 8] {
            b.push(v).expect("room");
        }
        a.clear();
        assert_eq!(pool.counts().used, 2, "a's three rows went back");
        assert_eq!(values(&b), [7, 8], "b's rows are untouched");
        let mut c = PooledRows::<Seq<u32>, 4>::new();
        c.keep_rows_in(pool.space());
        for v in [4, 5, 6] {
            c.push(v).expect("the rows a gave back");
        }
        assert_eq!(pool.counts().untouched, 0);
        assert!(c.push(9).is_err(), "the pool is full again");
        assert_eq!(
            (values(&b), values(&c)),
            (std::vec![7, 8], std::vec![4, 5, 6])
        );
    }

    /// A table keeps the order of its pushes through removals in either layout: in a shared pool
    /// and in a span of its own, the head, the middle and the last row each removed, a push after
    /// them landing last.
    #[test]
    fn a_table_keeps_its_push_order_through_removals_in_either_layout() {
        for space in [pool_of::<Seq<u32>>(8).space(), own_of::<Seq<u32>>(8)] {
            let mut table = PooledRows::<Seq<u32>, 8>::new();
            table.keep_rows_in(space);
            for v in 1..=5 {
                table.push(v).expect("room");
            }
            assert_eq!(table.remove_first(|v| *v == 3), Some(3));
            table.retain(|v| *v != 2);
            assert_eq!(values(&table), [1, 4, 5]);
            assert_eq!(table.remove_first(|v| *v == 5), Some(5), "the last");
            table.push(6).expect("room");
            assert_eq!(values(&table), [1, 4, 6]);
            assert_eq!(table.remove_first(|v| *v == 1), Some(1), "the head");
            for v in table.iter_mut() {
                *v += 10;
            }
            assert_eq!(values(&table), [14, 16]);
            table.retain(|_| false);
            assert!(table.is_empty());
        }
    }

    /// A table of its own span holds as many rows as the span and no pool state: its rows lie from
    /// the span's start as an inline table's do, a push past them is refused and counted, and a row
    /// taken out makes room.
    #[test]
    fn a_table_of_its_own_span_holds_its_rows_in_place_and_refuses_past_them() {
        let own = own_of::<Seq<u64>>(2);
        assert!(!own.is_shared());
        assert_eq!(own.rows(), 2);
        let start = own.raw.at;
        let mut table = PooledRows::<Seq<u64>, 4>::new();
        table.keep_rows_in(own);
        table.push(1).expect("room");
        table.push(2).expect("room");
        let first = table.iter().next().expect("a row") as *const u64;
        assert_eq!(
            first as usize,
            start.as_ptr() as usize,
            "the first row lies at the span's start"
        );
        assert_eq!(table.push(3).err().map(|full| full.0), Some(3));
        assert_eq!(table.refusals(), 1);
        assert_eq!(table.remove_first(|v| *v == 1), Some(1));
        table.push(3).expect("the row taken out");
        assert_eq!(table.iter().copied().collect::<Vec<_>>(), [2, 3]);
    }

    /// A table refuses past its own bound though its space has rows left, as an inline table of
    /// that bound refuses, and the pool counts no refusal of its own for it.
    #[test]
    fn a_table_refuses_past_its_own_bound_with_rows_left_in_the_space() {
        let pool = pool_of::<Seq<u32>>(8);
        let mut table = PooledRows::<Seq<u32>, 2>::new();
        table.keep_rows_in(pool.space());
        table.push(1).expect("room");
        table.push(2).expect("room");
        assert_eq!(table.push(3).err().map(|full| full.0), Some(3));
        let counts = pool.counts();
        assert_eq!((counts.used, counts.refused, table.refusals()), (2, 0, 1));
    }

    /// A table handed no space refuses every item, and so does one whose pool lends no row.
    #[test]
    fn a_table_with_no_space_or_an_empty_one_refuses() {
        let mut table = PooledRows::<Seq<u32>, 4>::default();
        assert_eq!(table.push(1).err().map(|full| full.0), Some(1));
        let empty = pool_of::<Seq<u32>>(0);
        table.keep_rows_in(empty.space());
        assert!(table.push(1).is_err());
        assert_eq!(empty.counts().refused, 1);
        assert_eq!(table.refusals(), 2);
    }

    /// A dropped table gives its rows back and drops each item once, in either layout; so does one
    /// handed another space, whose rows belong to the first; and so does a retain, for each row it
    /// lets go.
    #[test]
    fn a_dropped_table_drops_its_items_and_gives_its_rows_back() {
        let value = Rc::new(());
        for space in [pool_of::<Seq<Rc<()>>>(4).space(), own_of::<Seq<Rc<()>>>(4)] {
            let mut table = PooledRows::<Seq<Rc<()>>, 4>::new();
            table.keep_rows_in(space);
            for _ in 0..3 {
                table.push(Rc::clone(&value)).expect("room");
            }
            assert_eq!(Rc::strong_count(&value), 4);
            let mut kept = 0;
            table.retain(|_| {
                kept += 1;
                kept != 2
            });
            assert_eq!(Rc::strong_count(&value), 3, "the row let go dropped once");
            drop(table);
            assert_eq!(Rc::strong_count(&value), 1, "each item dropped once");
        }
        let (pool, other) = (pool_of::<Seq<Rc<()>>>(4), pool_of::<Seq<Rc<()>>>(4));
        let mut moved = PooledRows::<Seq<Rc<()>>, 4>::new();
        moved.keep_rows_in(pool.space());
        moved.push(Rc::clone(&value)).expect("room");
        moved.keep_rows_in(other.space());
        assert_eq!((pool.counts().used, Rc::strong_count(&value)), (0, 1));
        moved.push(Rc::clone(&value)).expect("the other pool's row");
        assert_eq!(other.counts().used, 1);
    }

    /// A keyed table finds, rewrites and takes out a row by its id in either layout, the value of
    /// the rest untouched.
    #[test]
    fn a_keyed_table_finds_and_takes_out_a_row_by_its_id_in_either_layout() {
        for space in [pool_of::<Keyed<u32>>(4).space(), own_of::<Keyed<u32>>(4)] {
            let mut table = PooledRows::<Keyed<u32>, 4>::new();
            table.keep_rows_in(space);
            for id in 1..=3u64 {
                table.push((id, id as u32 * 10)).expect("room");
            }
            if let Some(value) = table.get_id_mut(2) {
                *value = 21;
            }
            assert_eq!((table.get_id(2), table.get_id(9)), (Some(&21), None));
            assert_eq!(table.remove_id(1), Some(10));
            assert_eq!(table.remove_id(1), None);
            assert_eq!(
                table.iter().map(|(id, v)| (id, *v)).collect::<Vec<_>>(),
                [(2, 21), (3, 30)]
            );
        }
    }

    /// An arena one byte short of a pool's span refuses it, taking nothing.
    #[test]
    fn an_arena_refuses_a_pool_past_what_is_left() {
        let span = RowSpace::<Seq<u64>>::pool_bytes(4).expect("fits");
        let mut arena = arena_of(span - 1);
        assert!(matches!(
            arena.lend_pool::<Seq<u64>>(4),
            Err(LendRefused::Exhausted { .. })
        ));
        assert_eq!(arena.high_water(), 0);
    }

    /// The tables of every policy answer the same: an inline sequence is a `RowList` as a pooled one
    /// and one of its own span are, in push order.
    #[test]
    fn an_inline_sequence_and_a_pooled_one_answer_alike() {
        fn exercise<L: RowList<u32>>(table: &mut L) -> Vec<u32> {
            for v in 1..=4 {
                table.push(v).expect("room");
            }
            assert_eq!(table.remove_first(|v| *v == 2), Some(2));
            table.retain(|v| *v != 4);
            for v in table.iter_mut() {
                *v *= 10;
            }
            table.iter().copied().collect()
        }
        let mut inline = BoundedVec::<u32, 8, Static>::new_static();
        let mut pooled = PooledRows::<Seq<u32>, 8>::new();
        pooled.keep_rows_in(pool_of::<Seq<u32>>(8).space());
        let mut own = PooledRows::<Seq<u32>, 8>::new();
        own.keep_rows_in(own_of::<Seq<u32>>(8));
        let expected = exercise(&mut inline);
        assert_eq!(expected, [10, 30]);
        assert_eq!(exercise(&mut pooled), expected);
        assert_eq!(exercise(&mut own), expected);
    }
}
