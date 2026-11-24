// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A value a view builds the first time a reader asks for it, read through a shared borrow.

use core::cell::OnceCell;

/// The value `cell` holds, built by `build` the first time it is asked for. A build that asks the
/// same cell again before it returns leaves the value that inner ask stored, and its own is
/// dropped: `OnceCell::get_or_init` panics there, so the answer is read back from the cell instead
/// of taken from the store.
pub(crate) fn get_or_build<T>(cell: &OnceCell<T>, build: impl FnOnce() -> T) -> Option<&T> {
    if cell.get().is_none() {
        let _ = cell.set(build());
    }
    cell.get()
}

#[cfg(test)]
mod tests {
    use super::get_or_build;
    use core::cell::{Cell, OnceCell};

    #[test]
    fn a_value_is_built_once_and_read_back_after() {
        let cell = OnceCell::new();
        let builds = Cell::new(0u32);
        let build = || {
            builds.set(builds.get() + 1);
            7u32
        };
        assert_eq!(get_or_build(&cell, build), Some(&7));
        assert_eq!(get_or_build(&cell, build), Some(&7));
        assert_eq!(builds.get(), 1);
    }

    /// Turned red by a body that stores with `OnceCell::get_or_init`, which panics when the build
    /// asks the cell it is building.
    #[test]
    fn a_build_that_asks_its_own_cell_keeps_the_inner_value() {
        let cell = OnceCell::new();
        let outer = get_or_build(&cell, || {
            assert_eq!(get_or_build(&cell, || 1u32), Some(&1));
            2u32
        });
        assert_eq!(outer, Some(&1));
    }
}
