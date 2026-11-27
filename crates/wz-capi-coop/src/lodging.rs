// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The places a session's arena lends for values lodged by counts ([`wz_capi_port::lodge`]):
//! values the ABI and the engine make for the session and share past it, a listener's hub or a
//! watcher of the faces, which lie in the session's memory and take none of the heap.
//!
//! The places are one table of cells laid out at the open by the largest layout asked
//! ([`crate::arena::HeldPlaces::with_lodgings`]), each cell a head and a place. A place is lent
//! from any thread and given back by the last count of what lies there, from any thread and with
//! no lock of the session held, so the head's mark is atomic. A value lodged may outlive the
//! session, so each place lent holds a count of the memory the arena lies in, given back after
//! the mark is cleared: the memory goes with the last of the session and the values lodged in it.
//!
//! Where the session's tables take their memory on use no table is laid out: each place is an
//! allocation of its own, taken as it is lent and given back by the last count of what lies there,
//! its head the cell's layout, so it is given back from any thread with nothing of the session
//! read. A value lodged then keeps no memory of the session's.

use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::NonNull;
#[cfg(not(wz_on_use))]
use core::sync::atomic::{AtomicBool, Ordering};

use wz_capi_port::lodge::LentBytes;
#[cfg(not(wz_on_use))]
use wz_runtime_coop::kept::Kept;
#[cfg(not(wz_on_use))]
use wz_session_core::bounded::TableLender;
use wz_session_core::bounded::ARENA_ALIGN;

/// What lies before each place: whether it is lent, and the count of the memory the place lies
/// in, one of which each place lent holds.
#[cfg(not(wz_on_use))]
#[repr(C)]
struct PlaceHead {
    held: AtomicBool,
    keeper: NonNull<Kept>,
}

/// What lies before each place where the tables take their memory on use: the layout of the
/// allocation the place lies in, which its give-back hands the allocator.
#[cfg(wz_on_use)]
#[repr(C)]
struct OwnHead {
    cell: Layout,
}

/// The head before each place, as the session's form keeps its places.
#[cfg(not(wz_on_use))]
type Head = PlaceHead;
#[cfg(wz_on_use)]
type Head = OwnHead;

/// `bytes` rounded up to `align`, a power of two; `None` past the address space.
const fn round_up(bytes: usize, align: usize) -> Option<usize> {
    let mask = align.wrapping_sub(1);
    match bytes.checked_add(mask) {
        Some(up) => Some(up & !mask),
        None => None,
    }
}

/// The table of lodging places a plan lays out: how many cells, and how each is laid out. Worked
/// out in a `const` context where the places are known when the ABI is built
/// ([`crate::arena::HeldPlaces::with_lodgings`]), so an open only counts the cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LodgingRows {
    /// The layout of each place, which a lend hands out as it is.
    place: Layout,
    /// Where a place starts in its cell, past the head.
    offset: usize,
    /// The bytes of one cell, a multiple of the alignment of its head and of its place.
    stride: usize,
    /// How many cells.
    count: usize,
}

impl Default for LodgingRows {
    /// No table.
    fn default() -> Self {
        Self::NONE
    }
}

impl LodgingRows {
    /// No table.
    pub(crate) const NONE: Self = Self {
        place: Layout::new::<()>(),
        offset: 0,
        stride: 0,
        count: 0,
    };

    /// A table of `count` places of `place`. `None` when a cell asks for more alignment than a
    /// span of the arena starts on, or the table is past the address space.
    pub(crate) const fn of(place: Layout, count: usize) -> Option<Self> {
        let head_align = core::mem::align_of::<Head>();
        let cell_align = if place.align() > head_align {
            place.align()
        } else {
            head_align
        };
        if cell_align > ARENA_ALIGN {
            return None;
        }
        let offset = match round_up(core::mem::size_of::<Head>(), place.align()) {
            Some(offset) => offset,
            None => return None,
        };
        let stride = match offset.checked_add(place.size()) {
            Some(end) => round_up(end, cell_align),
            None => None,
        };
        match stride {
            Some(stride) if stride.checked_mul(count).is_some() => Some(Self {
                place,
                offset,
                stride,
                count,
            }),
            _ => None,
        }
    }

    /// This table with `count` more places, every place as large and as aligned as the largest
    /// of its own and `layout`; `None` as for [`Self::of`].
    pub(crate) const fn with(self, layout: Layout, count: usize) -> Option<Self> {
        let size = if layout.size() > self.place.size() {
            layout.size()
        } else {
            self.place.size()
        };
        let align = if layout.align() > self.place.align() {
            layout.align()
        } else {
            self.place.align()
        };
        let place = match Layout::from_size_align(size, align) {
            Ok(place) => place,
            Err(_) => return None,
        };
        match self.count.checked_add(count) {
            Some(count) => Self::of(place, count),
            None => None,
        }
    }

    /// This table with `count` more places of its own layout; `None` past the address space.
    #[cfg(feature = "connectivity")]
    pub(crate) const fn more(self, count: usize) -> Option<Self> {
        match self.count.checked_add(count) {
            Some(count) if self.stride.checked_mul(count).is_some() => Some(Self { count, ..self }),
            _ => None,
        }
    }

    /// How many places the table holds.
    pub(crate) const fn count(&self) -> usize {
        self.count
    }

    /// The bytes of one cell, a head and its place.
    pub(crate) const fn stride(&self) -> usize {
        self.stride
    }

    /// The span of the table, lent by `lend` ([`LodgingSpan::kept_by`] makes the table over
    /// it); a span of no place for a table of none, which lends nothing from the arena.
    #[cfg(not(wz_on_use))]
    pub(crate) fn lent_from(&self, lend: &mut TableLender<'_>) -> LodgingSpan {
        if self.count == 0 {
            return LodgingSpan::default();
        }
        let rows = *self;
        lend.lend_with(|arena| {
            Ok(LodgingSpan {
                first: arena.lend_span(rows.stride.checked_mul(rows.count))?,
                rows,
            })
        })
    }
}

/// The span of an arena a table of lodging places lies in, its heads not written yet.
#[cfg(not(wz_on_use))]
pub(crate) struct LodgingSpan {
    first: NonNull<u8>,
    rows: LodgingRows,
}

#[cfg(not(wz_on_use))]
impl Default for LodgingSpan {
    /// A span of no place.
    fn default() -> Self {
        Self {
            first: NonNull::dangling(),
            rows: LodgingRows::NONE,
        }
    }
}

#[cfg(not(wz_on_use))]
impl LodgingSpan {
    /// The table over this span, every place free, each place lent holding a count of
    /// `keeper`, the count of the memory the span lies in.
    ///
    /// # Safety
    /// The span is an arena's, lent to this table alone, aligned to [`ARENA_ALIGN`] and
    /// `stride * count` bytes long; `keeper` is a live count of the memory it lies in, which
    /// stands while a count of it is held; and the table is lent from only while the caller holds
    /// such a count.
    pub(crate) unsafe fn kept_by(self, keeper: NonNull<Kept>) -> LodgingPlaces {
        let places = LodgingPlaces {
            first: self.first,
            rows: self.rows,
        };
        for at in 0..places.rows.count {
            // SAFETY: the caller's: the cell is inside the span, its head aligned as the cell is,
            // and written once here, before the table lends it.
            unsafe {
                places.head(at).as_ptr().write(PlaceHead {
                    held: AtomicBool::new(false),
                    keeper,
                });
            }
        }
        places
    }
}

/// The places an arena lent for lodged values ([`LodgingSpan::kept_by`]): a handle, copied into
/// the engine that lends from it.
#[cfg(not(wz_on_use))]
#[derive(Clone, Copy)]
pub(crate) struct LodgingPlaces {
    first: NonNull<u8>,
    rows: LodgingRows,
}

// SAFETY: the table is an address in a session's memory and its shape; a place is taken and given
// back through its head's atomic mark alone, so handing the table to another thread shares nothing
// unsynchronised.
#[cfg(not(wz_on_use))]
unsafe impl Send for LodgingPlaces {}
// SAFETY: as for `Send`.
#[cfg(not(wz_on_use))]
unsafe impl Sync for LodgingPlaces {}

#[cfg(not(wz_on_use))]
impl LodgingPlaces {
    /// The head of cell `at`, below the table's count.
    fn head(&self, at: usize) -> NonNull<PlaceHead> {
        // SAFETY: `at` is below the count, so the cell lies inside the table's span
        // (`LodgingSpan::kept_by`).
        unsafe {
            NonNull::new_unchecked(self.first.as_ptr().add(at.wrapping_mul(self.rows.stride)))
        }
        .cast()
    }

    /// A free place of at least `layout`, lent until the last count of what is lodged there
    /// lets it go, or at once when the place is dropped unused; `None` when every place is lent or
    /// the table's places are smaller or less aligned than `layout`.
    pub(crate) fn lend(&self, layout: Layout) -> Option<LentBytes> {
        let place = self.rows.place;
        if layout.size() > place.size() || layout.align() > place.align() {
            return None;
        }
        (0..self.rows.count).find_map(|at| {
            let head = self.head(at);
            // SAFETY: the head was written when the table was made and stands while the session
            // holds its count of the memory, which it does while it lends (`LodgingSpan::kept_by`).
            let marked = unsafe { head.as_ref() };
            // Acquire, to see the drop of the value the place held last before it is written again.
            marked
                .held
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .ok()?;
            // SAFETY: the count is live, held by the session that lends.
            unsafe { marked.keeper.as_ref() }.retain();
            // SAFETY: the place follows its head in the cell, laid out as `place`
            // (`LodgingRows::of`), and holds no value now that its mark is this lend's; the
            // memory stands until `give_back` releases the count taken above, after the mark.
            Some(unsafe {
                LentBytes::new(
                    NonNull::new_unchecked(head.as_ptr().cast::<u8>().add(self.rows.offset)),
                    place,
                    give_back,
                    head.as_ptr().cast::<c_void>(),
                )
            })
        })
    }

    /// How many places are lent. For tests.
    #[cfg(test)]
    pub(crate) fn lent(&self) -> usize {
        (0..self.rows.count)
            .filter(|&at| {
                // SAFETY: as `lend`'s.
                unsafe { self.head(at).as_ref() }
                    .held
                    .load(Ordering::Relaxed)
            })
            .count()
    }
}

/// Give back the place whose head is at `context`: its mark cleared, then the count of the memory
/// it held let go of, which gives the memory back when it was the last.
///
/// # Safety
/// `context` is the head of a place [`LodgingPlaces::lend`] lent, given back once, with nothing
/// left in the place.
#[cfg(not(wz_on_use))]
unsafe fn give_back(context: *mut c_void) {
    let head = context.cast::<PlaceHead>();
    // Read before the mark is cleared: a lend after it owns the head, and the release after it may
    // give back the memory the head lies in.
    // SAFETY: the caller's: the head stands while the place's count of the memory is held.
    let keeper = unsafe { (*head).keeper };
    // SAFETY: as above. Release, so the next lend of the place sees what was dropped in it.
    unsafe { (*head).held.store(false, Ordering::Release) };
    // SAFETY: the count the lend took for this place, let go of once, here.
    unsafe { Kept::release(keeper) };
}

/// The places for lodged values where the tables take their memory on use: the table's shape, by
/// which each place is an allocation of its own of a cell, taken as it is lent.
#[cfg(wz_on_use)]
#[derive(Clone, Copy)]
pub(crate) struct LodgingPlaces {
    rows: LodgingRows,
}

#[cfg(wz_on_use)]
impl LodgingPlaces {
    /// The places `rows` lays out, none taken.
    pub(crate) const fn own(rows: LodgingRows) -> Self {
        Self { rows }
    }

    /// A place of at least `layout`, an allocation of its own of one cell, given back by the last
    /// count of what is lodged there, or at once when it is dropped unused; `None` when the plan
    /// names no place, the places are smaller or less aligned than `layout`, or the allocator
    /// refuses the cell. The places the ABI lodges are its session's own, one of each value, so
    /// no count bounds them beyond the plan's layout.
    pub(crate) fn lend(&self, layout: Layout) -> Option<LentBytes> {
        let place = self.rows.place;
        if self.rows.count == 0 || layout.size() > place.size() || layout.align() > place.align() {
            return None;
        }
        let align = place.align().max(core::mem::align_of::<OwnHead>());
        let cell = Layout::from_size_align(self.rows.stride(), align).ok()?;
        // SAFETY: the cell holds a head, so its size is not zero.
        let head = NonNull::new(unsafe { alloc::alloc::alloc(cell) })?.cast::<OwnHead>();
        // SAFETY: the cell is aligned for its head and its place (`LodgingRows::of`), the head at
        // its start and the place `offset` bytes in, inside the cell; the head is written once,
        // here, and the place holds no value.
        Some(unsafe {
            head.as_ptr().write(OwnHead { cell });
            LentBytes::new(
                NonNull::new_unchecked(head.as_ptr().cast::<u8>().add(self.rows.offset)),
                place,
                give_back_own,
                head.as_ptr().cast::<c_void>(),
            )
        })
    }
}

/// Give back the cell whose head is at `context` to the allocator.
///
/// # Safety
/// `context` is the head of a place [`LodgingPlaces::lend`] lent, given back once, with nothing
/// left in the place.
#[cfg(wz_on_use)]
unsafe fn give_back_own(context: *mut c_void) {
    // SAFETY: the caller's: the head was written by the lend and stands until this gives it back.
    let cell = unsafe { context.cast::<OwnHead>().read() }.cell;
    // SAFETY: the cell was taken by the lend for this layout, given back once, here.
    unsafe { alloc::alloc::dealloc(context.cast::<u8>(), cell) };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(wz_on_use))]
    use core::sync::atomic::AtomicUsize;
    use wz_capi_port::lodge::{Lent, Strong};
    #[cfg(not(wz_on_use))]
    use wz_session_core::bounded::Arena;

    /// How many times a test's memory was given back by its last count.
    #[cfg(not(wz_on_use))]
    static GIVEN: AtomicUsize = AtomicUsize::new(0);

    /// The last count of a test's memory let go: counted, as there is nothing to give back.
    #[cfg(not(wz_on_use))]
    unsafe fn count_given(_kept: NonNull<Kept>) {
        GIVEN.fetch_add(1, Ordering::Relaxed);
    }

    /// A buffer of the test's, aligned as an arena's spans start.
    #[cfg(not(wz_on_use))]
    #[repr(C, align(16))]
    struct Buffer([u8; 512]);

    #[cfg(not(wz_on_use))]
    const _: () = assert!(core::mem::align_of::<Buffer>() == ARENA_ALIGN);

    /// Where the tables take their memory on use each place lent is a cell of its own, so two
    /// lends of a table of one place both answer, a place past the plan's layout is refused, a
    /// place is handed at the plan's layout, and one lodged goes back with its last count; a plan
    /// of no place lends none. Turned red by a lend that shares one cell, takes a layout past the
    /// plan's, or by a give-back that hands the allocator another layout than the cell's (an
    /// allocator that checks it, or the interpreter, then fails).
    #[cfg(wz_on_use)]
    #[test]
    fn an_on_use_lodging_place_is_a_cell_of_its_own_given_back_by_its_last_count() {
        let layout = Lent::<u64>::LAYOUT;
        let places = LodgingPlaces::own(LodgingRows::of(layout, 1).expect("a table of one place"));
        let past = Layout::from_size_align(layout.size() + 1, 1).expect("a layout");
        assert!(
            places.lend(past).is_none(),
            "a place past the plan's is refused"
        );
        let first = places.lend(layout).expect("a place");
        assert_eq!(first.layout(), layout, "lent at the plan's layout");
        let second = places
            .lend(Layout::new::<u8>())
            .expect("another place: each is a cell of its own");
        drop(first);
        let count = Strong::new_at(Lent::<u64>::of_bytes(second).expect("a lodging fits"), 7);
        assert_eq!(Strong::strong_count(&count), 1);
        drop(count);
        assert!(
            LodgingPlaces::own(LodgingRows::NONE)
                .lend(Layout::new::<u8>())
                .is_none(),
            "a plan of no place lends none"
        );
    }

    /// Each place of a table is lent once until it is given back, every place lent refuses the
    /// next lend, a layout past the places is refused, and the memory's count is held by each
    /// place lent and let go of after its mark: the memory goes with the last of the session and
    /// the values lodged in it. Turned red by a mark that is not cleared, a lend that takes no
    /// count of the memory, or a give-back that releases no count.
    #[cfg(not(wz_on_use))]
    #[test]
    fn a_lodging_place_is_lent_once_and_keeps_the_memory_it_lies_in() {
        let layout = Lent::<u64>::LAYOUT;
        let rows = LodgingRows::of(layout, 2).expect("a table of two places");
        assert_eq!(rows.count(), 2);
        assert_eq!(
            rows.stride() % layout.align(),
            0,
            "each cell starts aligned for its place"
        );
        let mut buffer = Buffer([0; 512]);
        // SAFETY: the buffer is the test's, aligned to `ARENA_ALIGN` and used by this arena alone
        // for as long as the table is.
        let mut arena =
            unsafe { Arena::over(NonNull::from(&mut buffer.0).cast::<u8>(), buffer.0.len()) };
        let mut lend = TableLender::new(&mut arena);
        let span = rows.lent_from(&mut lend);
        lend.finish().expect("the buffer holds the table");
        let kept = Kept::new(count_given);
        let keeper = NonNull::from(&kept);
        // SAFETY: the span is the arena's, lent to the table alone, and `kept` stands past every
        // count of it taken here.
        let places = unsafe { span.kept_by(keeper) };
        let before = GIVEN.load(Ordering::Relaxed);

        let past = Layout::from_size_align(layout.size() + 1, 1).expect("a layout");
        assert!(
            places.lend(past).is_none(),
            "a place past the table's is refused"
        );
        let first = places.lend(layout).expect("a free place");
        let second = places
            .lend(Layout::new::<u8>())
            .expect("the other free place");
        assert_eq!(
            second.layout(),
            layout,
            "a place is lent at the table's layout"
        );
        assert_eq!(places.lent(), 2);
        assert!(
            places.lend(Layout::new::<u8>()).is_none(),
            "every place is lent"
        );
        drop(first);
        assert_eq!(places.lent(), 1, "a place dropped unused goes back");
        let again = places
            .lend(layout)
            .expect("the place given back is lent again");
        let count = Strong::new_at(Lent::<u64>::of_bytes(again).expect("a lodging fits"), 7);
        drop(second);
        assert_eq!(places.lent(), 1, "the lodged value holds its place");

        // SAFETY: the session's count, given back once.
        unsafe { Kept::release(keeper) };
        assert_eq!(
            GIVEN.load(Ordering::Relaxed),
            before,
            "the value lodged keeps the memory past the session"
        );
        drop(count);
        assert_eq!(places.lent(), 0, "the last count gave the place back");
        assert_eq!(
            GIVEN.load(Ordering::Relaxed),
            before + 1,
            "and the memory with it"
        );
    }

    /// A table of no place asks the arena for nothing and lends nothing; one whose cell asks for
    /// more alignment than an arena's spans start on is no table. Turned red by a table of none
    /// that takes a span or lends, or an alignment let through.
    #[cfg(not(wz_on_use))]
    #[test]
    fn a_table_of_no_place_lends_nothing_and_a_misaligned_one_is_refused() {
        let past = Layout::from_size_align(8, ARENA_ALIGN * 2).expect("a layout");
        assert_eq!(LodgingRows::of(past, 1), None);
        assert_eq!(
            LodgingRows::NONE.with(past, 0),
            None,
            "nor is a table grown to it"
        );
        let mut arena = Arena::empty();
        let mut lend = TableLender::new(&mut arena);
        let span = LodgingRows::NONE.lent_from(&mut lend);
        lend.finish().expect("a table of no place takes nothing");
        let kept = Kept::new(count_given);
        // SAFETY: a span of no cell writes no head and lends nothing.
        let places = unsafe { span.kept_by(NonNull::from(&kept)) };
        assert!(places.lend(Layout::new::<u8>()).is_none());
        assert_eq!(places.lent(), 0);
    }

    /// A table grown by a layout lays every place out as the largest and most aligned asked and
    /// counts the places of both, as one made of that layout and that count; a count past the
    /// address space is no table. Turned red by a merge that keeps the smaller size or alignment,
    /// or drops either count.
    #[test]
    fn a_table_grown_by_a_layout_holds_the_largest_place_and_every_count() {
        let small = Layout::from_size_align(24, 4).expect("a layout");
        let aligned = Layout::from_size_align(8, 8).expect("a layout");
        let grown = LodgingRows::of(small, 1)
            .and_then(|rows| rows.with(aligned, 2))
            .expect("a table");
        let made = LodgingRows::of(Layout::from_size_align(24, 8).expect("a layout"), 3);
        assert_eq!(Some(grown), made);
        assert_eq!(grown.count(), 3);
        assert_eq!(
            grown.with(small, usize::MAX),
            None,
            "a count past the space"
        );
    }

    /// A table counted once more keeps its layout and adds the count; one past the address space
    /// is no table. Turned red by a count that is not added, or a product left unchecked.
    #[cfg(feature = "connectivity")]
    #[test]
    fn a_table_counted_once_more_keeps_its_layout() {
        let rows = LodgingRows::of(Layout::new::<u64>(), 1).expect("a table");
        let more = rows.more(2).expect("a table of three");
        assert_eq!(more.count(), 3);
        assert_eq!(more.stride(), rows.stride());
        assert_eq!(rows.more(usize::MAX), None);
    }
}
