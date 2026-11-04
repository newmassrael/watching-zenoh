// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE DECLARED SHAPE, built once and indexed.
//!
//! Every path a selector or a sentence names is held to the shape the
//! dissector declares, and every such check asks one question: which declared
//! paths END with these segments. The shape is a pure function of static data,
//! so it is built once per process, and the question is answered from an index
//! by last segment, which every tail the question asks ends with.
//!
//! Built per call instead, a check paid for the whole shape each time (every
//! path, and every closed label's word list): about 14 ms in a test build,
//! several times over for each node a sentence is written for.
//!
//! A target with no pointer-wide atomics has no lock-free way to publish a
//! value once, and builds the shape per call there; the answers are the same.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::Declared;

/// The declared paths in the order the shape lists them, and by last segment.
pub(crate) struct Shape {
    paths: Vec<Declared>,
    /// For each last segment, the indices of the paths ending in it, ascending,
    /// so a lookup keeps the shape's order.
    by_last: BTreeMap<&'static str, Vec<usize>>,
}

impl Shape {
    fn build() -> Self {
        let paths = super::read_declared();
        let mut by_last: BTreeMap<&'static str, Vec<usize>> = BTreeMap::new();
        for (i, d) in paths.iter().enumerate() {
            if let Some(last) = d.segments.last() {
                by_last.entry(last).or_default().push(i);
            }
        }
        Self { paths, by_last }
    }

    /// Every declared path, in the order the shape lists them.
    pub(crate) fn paths(&self) -> &[Declared] {
        &self.paths
    }

    /// The declared paths that end with `tail`, in the order the shape lists
    /// them. An empty tail ends every path.
    pub(crate) fn ending_with<'s: 't, 't>(
        &'s self,
        tail: &'t [&'t str],
    ) -> impl Iterator<Item = &'s Declared> + 't {
        let (bucket, every): (&[usize], bool) = match tail.last() {
            Some(last) => (self.by_last.get(last).map_or(&[], Vec::as_slice), false),
            None => (&[], true),
        };
        self.paths
            .iter()
            .filter(move |_| every)
            .chain(bucket.iter().map(|&i| &self.paths[i]))
            .filter(move |d| d.segments.ends_with(tail))
    }

    /// Whether `segments` is itself a declared path.
    pub(crate) fn holds(&self, segments: &[&str]) -> bool {
        self.ending_with(segments).any(|d| d.segments == segments)
    }
}

/// `f` over the declared shape.
pub(crate) fn with_shape<R>(f: impl FnOnce(&Shape) -> R) -> R {
    #[cfg(target_has_atomic = "ptr")]
    {
        f(once())
    }
    #[cfg(not(target_has_atomic = "ptr"))]
    {
        f(&Shape::build())
    }
}

/// The shape, built by the first caller and kept for the process. Two callers
/// that race both build it; the first to publish wins and the other's copy is
/// dropped, so every caller reads the one published value.
#[cfg(target_has_atomic = "ptr")]
fn once() -> &'static Shape {
    use alloc::boxed::Box;
    use core::ptr;
    use core::sync::atomic::{AtomicPtr, Ordering};

    static SHAPE: AtomicPtr<Shape> = AtomicPtr::new(ptr::null_mut());

    let published = SHAPE.load(Ordering::Acquire);
    if !published.is_null() {
        // SAFETY: a non-null value was published below from `Box::into_raw`,
        // is never freed and never written through, and the acquire load
        // orders this read after the build that published it.
        return unsafe { &*published };
    }
    let built = Box::into_raw(Box::new(Shape::build()));
    match SHAPE.compare_exchange(ptr::null_mut(), built, Ordering::AcqRel, Ordering::Acquire) {
        // SAFETY: `built` is now the published value, which lives for the
        // process and is never written through.
        Ok(_) => unsafe { &*built },
        Err(first) => {
            // SAFETY: `built` came from `Box::into_raw` above and was never
            // published, so this is its only owner.
            drop(unsafe { Box::from_raw(built) });
            // SAFETY: as for `published` above.
            unsafe { &*first }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_answers_as_a_scan_of_every_path_does() {
        with_shape(|shape| {
            let scan = |tail: &[&str]| -> Vec<*const Declared> {
                shape
                    .paths()
                    .iter()
                    .filter(|d| d.segments.ends_with(tail))
                    .map(|d| d as *const Declared)
                    .collect()
            };
            let indexed = |tail: &[&str]| -> Vec<*const Declared> {
                shape
                    .ending_with(tail)
                    .map(|d| d as *const Declared)
                    .collect()
            };
            assert_eq!(indexed(&[]), scan(&[]));
            for d in shape.paths() {
                for width in 1..=d.segments.len() {
                    let tail = &d.segments[d.segments.len() - width..];
                    assert_eq!(indexed(tail), scan(tail), "{tail:?}");
                }
                assert!(shape.holds(&d.segments));
            }
            assert!(indexed(&["no_such_segment"]).is_empty());
            assert!(!shape.holds(&["no_such_segment"]));
        });
    }

    #[cfg(target_has_atomic = "ptr")]
    #[test]
    fn every_caller_reads_the_one_published_shape() {
        assert!(core::ptr::eq(once(), once()));
    }
}
