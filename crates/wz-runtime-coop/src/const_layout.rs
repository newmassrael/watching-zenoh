// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The reckoning of a [`Layout`] a `const fn` makes: a size rounded up to an alignment, an array,
//! one layout after another and a layout padded to its own alignment, each the answer of the
//! method of `Layout` it is named for. Those methods are `const` only from Rust 1.85, past the
//! workspace's `rust-version`, while `Layout::from_size_align` is `const` on it; so a layout a
//! build reckons when it is compiled (the span a runtime is placed in, a session's region) is
//! reckoned here, made by `layout` alone, and refused where the method would refuse it.

use core::alloc::Layout;
use core::mem::{align_of, size_of};

/// A layout of `size` bytes aligned to `align`, `None` where `Layout::from_size_align` refuses
/// it: an alignment that is not a power of two, or a size that, rounded up to it, passes
/// `isize::MAX`. Every layout of this module is made here.
pub(crate) const fn layout(size: usize, align: usize) -> Option<Layout> {
    match Layout::from_size_align(size, align) {
        Ok(layout) => Some(layout),
        Err(_) => None,
    }
}

/// `size` rounded up to a multiple of `align`; `None` past `usize::MAX` and for an alignment of
/// `0`.
pub(crate) const fn round_up(size: usize, align: usize) -> Option<usize> {
    size.checked_next_multiple_of(align)
}

/// The layout of `count` values of `T` one after another, `Layout::array::<T>(count)`: each a
/// stride of `size_of::<T>()`, already a multiple of its alignment. `None` past the address space.
pub(crate) const fn array<T>(count: usize) -> Option<Layout> {
    match size_of::<T>().checked_mul(count) {
        Some(bytes) => layout(bytes, align_of::<T>()),
        None => None,
    }
}

/// `head` and after it `tail`, `head.extend(tail)`: the layout of both, aligned to the larger of
/// their alignments, and where `tail` starts in it, `head`'s size rounded up to `tail`'s
/// alignment. `None` past the address space.
pub(crate) const fn extend(head: Layout, tail: Layout) -> Option<(Layout, usize)> {
    let Some(offset) = round_up(head.size(), tail.align()) else {
        return None;
    };
    let Some(size) = offset.checked_add(tail.size()) else {
        return None;
    };
    let align = if head.align() > tail.align() {
        head.align()
    } else {
        tail.align()
    };
    match layout(size, align) {
        Some(both) => Some((both, offset)),
        None => None,
    }
}

/// `layout` with its size rounded up to its own alignment, `layout.pad_to_align()`. A layout's
/// size rounded up so is what `Layout::from_size_align` checked when the layout was made, so
/// neither refusal below is reached; each answers the layout as it is rather than end the build.
pub(crate) const fn pad_to_align(layout: Layout) -> Layout {
    match round_up(layout.size(), layout.align()) {
        Some(size) => match self::layout(size, layout.align()) {
            Some(padded) => padded,
            None => layout,
        },
        None => layout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sizes and alignments across the space, the largest valid for their alignment among them.
    const PAIRS: [(usize, usize); 14] = [
        (0, 1),
        (1, 1),
        (3, 2),
        (9, 8),
        (24, 16),
        (1, 4096),
        (isize::MAX as usize - 15, 16),
        (isize::MAX as usize, 1),
        (isize::MAX as usize / 2 + 1, 1),
        (isize::MAX as usize, 2),
        (usize::MAX, 1),
        (8, 3),
        (8, 0),
        (0, 0),
    ];

    /// Every layout of `PAIRS` that `Layout::from_size_align` makes.
    fn layouts() -> impl Iterator<Item = Layout> {
        PAIRS
            .into_iter()
            .filter_map(|(size, align)| Layout::from_size_align(size, align).ok())
    }

    /// The one maker answers what `Layout::from_size_align` answers, its refusals included.
    /// Turned red by a maker that admits an alignment that is not a power of two or a size past
    /// `isize::MAX` rounded up.
    #[test]
    fn a_layout_is_made_as_from_size_align_makes_it() {
        for (size, align) in PAIRS {
            assert_eq!(
                layout(size, align),
                Layout::from_size_align(size, align).ok(),
                "{size} bytes aligned to {align}"
            );
        }
        assert_eq!(
            layout(8, 3),
            None,
            "CONTROL: an alignment of three is refused"
        );
    }

    /// A size is rounded up to the next multiple of the alignment, and one past `usize::MAX` is
    /// refused. Turned red by rounding that wraps or rounds a multiple up again.
    #[test]
    fn a_size_rounds_up_as_a_padded_layout_does() {
        for layout in layouts() {
            assert_eq!(
                round_up(layout.size(), layout.align()),
                Some(layout.pad_to_align().size()),
                "{layout:?}"
            );
        }
        assert_eq!(round_up(17, 16), Some(32));
        assert_eq!(round_up(32, 16), Some(32));
        assert_eq!(round_up(usize::MAX, 2), None);
        assert_eq!(round_up(usize::MAX, 1), Some(usize::MAX));
        assert_eq!(round_up(5, 0), None);
    }

    /// An array of each type and count is the layout `Layout::array` answers, `None` where it
    /// refuses. Turned red by a stride other than the type's size, or a product let past the
    /// address space.
    #[test]
    fn an_array_is_the_layout_layout_array_answers() {
        fn same<T>() {
            let stride = size_of::<T>().max(1);
            let counts = [
                0,
                1,
                3,
                isize::MAX as usize / stride,
                isize::MAX as usize / stride + 1,
                usize::MAX / 2,
                usize::MAX,
            ];
            for count in counts {
                assert_eq!(
                    array::<T>(count),
                    Layout::array::<T>(count).ok(),
                    "{count} of {} bytes",
                    size_of::<T>()
                );
            }
        }
        same::<u8>();
        same::<u64>();
        same::<[u16; 3]>();
        same::<()>();
        same::<u128>();
        same::<[u64; 5]>();
        assert_eq!(array::<[u64; 5]>(2).map(|both| both.size()), Some(80));
    }

    /// Every layout after every other is the layout and offset `Layout::extend` answers, `None`
    /// where it refuses. Turned red by an offset not rounded up to the tail's alignment, an
    /// alignment other than the larger, or a sum let past the address space.
    #[test]
    fn a_layout_after_another_is_what_extend_answers() {
        for head in layouts() {
            for tail in layouts() {
                assert_eq!(
                    extend(head, tail),
                    head.extend(tail).ok(),
                    "{head:?} then {tail:?}"
                );
            }
        }
        let head = Layout::from_size_align(9, 8).expect("a layout");
        let tail = Layout::from_size_align(24, 16).expect("a layout");
        assert_eq!(
            extend(head, tail),
            Some((Layout::from_size_align(40, 16).expect("a layout"), 16)),
            "CONTROL: the tail starts on its own alignment"
        );
    }

    /// Every layout padded to its own alignment is what `Layout::pad_to_align` answers. Turned red
    /// by padding to another alignment, or a size left unpadded.
    #[test]
    fn a_padded_layout_is_what_pad_to_align_answers() {
        for layout in layouts() {
            assert_eq!(pad_to_align(layout), layout.pad_to_align(), "{layout:?}");
        }
    }

    /// The reckoning runs where a constant is evaluated, as a layout reckoned when the build is
    /// compiled is, and answers there what the methods answer at run time.
    #[test]
    fn the_reckoning_answers_the_same_when_the_build_is_compiled() {
        const PLACED: Option<(Layout, usize)> = match (array::<u64>(3), layout(1, 32)) {
            (Some(head), Some(tail)) => extend(head, tail),
            _ => None,
        };
        let head = Layout::array::<u64>(3).expect("a layout");
        let tail = Layout::from_size_align(1, 32).expect("a layout");
        assert_eq!(PLACED, head.extend(tail).ok());
        const PADDED: Option<Layout> = match PLACED {
            Some((placed, _)) => Some(pad_to_align(placed)),
            None => None,
        };
        assert_eq!(
            PADDED,
            head.extend(tail)
                .ok()
                .map(|(placed, _)| placed.pad_to_align())
        );
    }
}
