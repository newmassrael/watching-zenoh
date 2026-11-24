// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A place a value the session owns is lent in for the length of a step, to the tasks the step
//! polls.
//!
//! A task cannot be handed a borrow (an executor polls it with nothing but its context), so the
//! lend is a place the task looks in: the owner lends the value for the length of a step
//! ([`StepLend::lend_for`]), and each call of a task takes it out for its own length and puts it
//! back ([`StepLend::with`]). No task holds the value past a step, and none holds it beside
//! another; the owner reads and writes it by `&mut` between steps, with nothing counted.

use alloc::rc::Rc;
use core::cell::Cell;
use core::ptr::NonNull;

/// The place a value of type `D` is lent in for the length of a step; each task that looks in it
/// holds a handle on the same place.
pub struct StepLend<D>(Rc<Cell<Option<NonNull<D>>>>);

impl<D> StepLend<D> {
    /// A place nothing is lent in yet.
    pub fn new() -> Self {
        Self(Rc::new(Cell::new(None)))
    }

    /// Lend `value` to every holder of this place for the length of `f`, and take it back when
    /// `f` returns or unwinds. The owner holds `value` borrowed for as long, so it neither reads
    /// nor moves it meanwhile.
    pub fn lend_for<T>(&self, value: &mut D, f: impl FnOnce() -> T) -> T {
        /// Puts back what the place held before, however `f` ends.
        struct Restore<'a, D> {
            place: &'a Cell<Option<NonNull<D>>>,
            was: Option<NonNull<D>>,
        }
        impl<D> Drop for Restore<'_, D> {
            fn drop(&mut self) {
                self.place.set(self.was);
            }
        }
        let _restore = Restore {
            place: &self.0,
            was: self.0.replace(Some(NonNull::from(value))),
        };
        f()
    }

    /// Whether the value is lent here now, and not taken out by a call.
    pub fn is_lent(&self) -> bool {
        self.0.get().is_some()
    }

    /// Run `f` on the value while it is lent here, taking it out for the length of `f`; `None`,
    /// with `f` not run, while it is not.
    pub fn with<T>(&self, f: impl FnOnce(&mut D) -> T) -> Option<T> {
        let mut taken = self.0.take()?;
        /// Puts the value back in its place, however `f` ends.
        struct PutBack<'a, D> {
            place: &'a Cell<Option<NonNull<D>>>,
            value: NonNull<D>,
        }
        impl<D> Drop for PutBack<'_, D> {
            fn drop(&mut self) {
                self.place.set(Some(self.value));
            }
        }
        let _back = PutBack {
            place: &self.0,
            value: taken,
        };
        // SAFETY: the pointer was set by `lend_for` from a `&mut D` its caller holds borrowed for
        // the whole of the lend, which has not ended, since `lend_for` takes it back only after
        // its `f` returns, and this call runs inside it. It was taken out of the place, so no
        // other call reaches it until `PutBack` returns it: this is the one reference to the
        // value while `f` runs.
        Some(f(unsafe { taken.as_mut() }))
    }
}

impl<D> Default for StepLend<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D> Clone for StepLend<D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value is reached only while it is lent, by one call at a time, and what a call wrote is
    /// the owner's once the lend ends. Turned red by a place that stays lent past its step or that
    /// hands a second call the value the first holds.
    #[test]
    fn a_value_is_reached_only_inside_its_lend_and_by_one_call_at_a_time() {
        let place = StepLend::<u32>::new();
        let holder = place.clone();
        assert_eq!(holder.with(|value| *value), None, "nothing lent yet");
        let mut owned = 1;
        let seen = place.lend_for(&mut owned, || {
            assert!(holder.is_lent());
            holder.with(|value| {
                *value += 1;
                assert_eq!(holder.with(|_| ()), None, "taken out by the running call");
                *value
            })
        });
        assert_eq!(seen, Some(2));
        assert!(!holder.is_lent(), "taken back when the step ends");
        assert_eq!(holder.with(|value| *value), None);
        assert_eq!(owned, 2, "the owner reads what the call wrote");
    }
}
