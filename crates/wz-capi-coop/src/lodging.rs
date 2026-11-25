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

use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use wz_capi_port::lodge::LentBytes;
use wz_runtime_coop::kept::Kept;
use wz_session_core::bounded::{TableLender, ARENA_ALIGN};

/// What lies before each place: whether it is lent, and the count of the memory the place lies
/// in, one of which each place lent holds.
#[repr(C)]
struct PlaceHead {
    held: AtomicBool,
    keeper: NonNull<Kept>,
}

/// `bytes` rounded up to `align`, a power of two; `None` past the address space.
const fn round_up(bytes: usize, align: usize) -> Option<usize> {
    let mask = align.wrapping_sub(1);
    match bytes.checked_add(mask) {
        Some(up) => Some(up & !mask),
        None => None,
    }
}

/// The table of lodging places a plan lays out: how many cells, and how each is laid out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LodgingRows {
    /// The bytes of each place.
    size: usize,
    /// The alignment of each place.
    align: usize,
    /// Where a place starts in its cell, past the head.
    offset: usize,
    /// The bytes of one cell, a multiple of the alignment of its head and of its place.
    stride: usize,
    /// How many cells.
    count: usize,
}

impl LodgingRows {
    /// No table.
    pub(crate) const NONE: Self = Self {
        size: 0,
        align: 0,
        offset: 0,
        stride: 0,
        count: 0,
    };

    /// A table of `count` places of `size` bytes aligned to `align`, a power of two. `None`
    /// when a cell asks for more alignment than a span of the arena starts on, or the table is
    /// past the address space.
    pub(crate) const fn of(size: usize, align: usize, count: usize) -> Option<Self> {
        let head_align = core::mem::align_of::<PlaceHead>();
        let cell_align = if align > head_align {
            align
        } else {
            head_align
        };
        if !align.is_power_of_two() || cell_align > ARENA_ALIGN {
            return None;
        }
        let offset = match round_up(core::mem::size_of::<PlaceHead>(), align) {
            Some(offset) => offset,
            None => return None,
        };
        let stride = match offset.checked_add(size) {
            Some(end) => round_up(end, cell_align),
            None => None,
        };
        match stride {
            Some(stride) if stride.checked_mul(count).is_some() => Some(Self {
                size,
                align,
                offset,
                stride,
                count,
            }),
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
pub(crate) struct LodgingSpan {
    first: NonNull<u8>,
    rows: LodgingRows,
}

impl Default for LodgingSpan {
    /// A span of no place.
    fn default() -> Self {
        Self {
            first: NonNull::dangling(),
            rows: LodgingRows::NONE,
        }
    }
}

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
#[derive(Clone, Copy)]
pub(crate) struct LodgingPlaces {
    first: NonNull<u8>,
    rows: LodgingRows,
}

// SAFETY: the table is an address in a session's memory and its shape; a place is taken and given
// back through its head's atomic mark alone, so handing the table to another thread shares nothing
// unsynchronised.
unsafe impl Send for LodgingPlaces {}
// SAFETY: as for `Send`.
unsafe impl Sync for LodgingPlaces {}

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
        if layout.size() > self.rows.size || layout.align() > self.rows.align {
            return None;
        }
        let place = Layout::from_size_align(self.rows.size, self.rows.align).ok()?;
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
            // SAFETY: the place follows its head in the cell, `size` bytes aligned to `align`
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;
    use wz_capi_port::lodge::{Lent, Strong};
    use wz_session_core::bounded::Arena;

    /// How many times a test's memory was given back by its last count.
    static GIVEN: AtomicUsize = AtomicUsize::new(0);

    /// The last count of a test's memory let go: counted, as there is nothing to give back.
    unsafe fn count_given(_kept: NonNull<Kept>) {
        GIVEN.fetch_add(1, Ordering::Relaxed);
    }

    /// A buffer of the test's, aligned as an arena's spans start.
    #[repr(C, align(16))]
    struct Buffer([u8; 512]);

    const _: () = assert!(core::mem::align_of::<Buffer>() == ARENA_ALIGN);

    /// Each place of a table is lent once until it is given back, every place lent refuses the
    /// next lend, a layout past the places is refused, and the memory's count is held by each
    /// place lent and let go of after its mark: the memory goes with the last of the session and
    /// the values lodged in it. Turned red by a mark that is not cleared, a lend that takes no
    /// count of the memory, or a give-back that releases no count.
    #[test]
    fn a_lodging_place_is_lent_once_and_keeps_the_memory_it_lies_in() {
        let layout = Lent::<u64>::LAYOUT;
        let rows =
            LodgingRows::of(layout.size(), layout.align(), 2).expect("a table of two places");
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
    /// more alignment than an arena's spans start on, or whose alignment is no power of two, is no
    /// table. Turned red by a table of none that takes a span or lends, or an alignment let through.
    #[test]
    fn a_table_of_no_place_lends_nothing_and_a_misaligned_one_is_refused() {
        assert_eq!(LodgingRows::of(8, ARENA_ALIGN * 2, 1), None);
        assert_eq!(LodgingRows::of(8, 3, 1), None);
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
}
