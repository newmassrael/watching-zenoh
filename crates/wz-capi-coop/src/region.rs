// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The state of a session whose shape the build fixes, as one struct: the session's registry (the
//! application's tables and its one face's), the rows each lays out beside it and the key arena
//! their keys lie in. Its
//! size is its `size_of` and its layout its fields' offsets; the allocator hands it zeroed, every
//! table of it empty (`ZeroEmpty`), and [`StateRegion::open`] joins each table to its rows and its
//! keys by one walk of the description the type states, so nothing is planned or lent at the open.
//!
//! A region is reached through a pointer to it, never by a reference to the whole: the tables'
//! rows and the key arena lie in it beside the tables, reached through the tables, and a unique
//! reference to the whole would cover them too. Each field is projected from the pointer alone.

use core::alloc::Layout;
use core::ops::{Deref, DerefMut};
use core::ptr::{addr_of_mut, NonNull};

use wz_session_core::bounded::{RegionLines, ZeroEmpty};
use wz_session_core::caps;
use wz_session_core::key_arena::{place_region, KeyArena, KeySpace};
use wz_session_core::limits::SessionLimits;

use crate::arena::{ArenaMemory, ArenaRefused, ArenaRegion};
use crate::engine::{RegistryRegion, StatePlaces, REGISTRY_REGION_LINES};
use crate::open_source::EndpointList;
use crate::CoopConfig;

/// A `T` reserved with every byte zero, so every field of it is empty (`ZeroEmpty`) until its
/// owner binds it, and dropped in place when the block is let go: a reservation of its own from an
/// [`ArenaMemory`] ([`Self::reserve`]), given back then too, or the head of the one block an
/// open reserves for its arena as well ([`Self::within`]), which the arena gives back. The block
/// holds the pointer and never a reference to the whole `T`: what lies in it is reached by fields
/// projected from [`Self::as_ptr`].
pub struct RegionBlock<T: ZeroEmpty> {
    at: NonNull<T>,
    /// The memory the block gives itself back to: `None` for a block another owner gives back.
    memory: Option<&'static dyn ArenaMemory>,
}

impl<T: ZeroEmpty> RegionBlock<T> {
    /// A zeroed `T` reserved from `memory`, refused as [`ArenaRefused::NoMemory`], having taken
    /// nothing, when the memory has none to give.
    pub fn reserve(memory: &'static dyn ArenaMemory) -> Result<Self, ArenaRefused> {
        const {
            assert!(
                core::mem::size_of::<T>() != 0,
                "a memory is never asked for nothing"
            )
        };
        let layout = Layout::new::<T>();
        let base = memory
            .reserve_zeroed(layout)
            .ok_or(ArenaRefused::NoMemory {
                bytes: layout.size(),
            })?;
        Ok(Self {
            at: base.cast::<T>(),
            memory: Some(memory),
        })
    }

    /// The zeroed `T` at `at`, the head of a block another owner reserved and gives back
    /// (`SessionArena::reserve_after`): the block drops the `T` in place and gives back nothing.
    ///
    /// # Safety
    /// `at` is an aligned `T` of all zero bytes that nothing else reaches, and its memory stays,
    /// unmoved, until after the block is dropped.
    pub(crate) unsafe fn within(at: NonNull<T>) -> Self {
        Self { at, memory: None }
    }

    /// Where the `T` lies, aligned and of all zero bytes until its owner writes it.
    pub fn as_ptr(&self) -> NonNull<T> {
        self.at
    }
}

// SAFETY: the block owns the `T` it reserved, which nothing else reaches, as a `Box` owns its
// value; the memory it gives it back to is `Sync` (`ArenaMemory`).
unsafe impl<T: ZeroEmpty + Send> Send for RegionBlock<T> {}
// SAFETY: a shared block hands out nothing but its pointer, as above.
unsafe impl<T: ZeroEmpty + Sync> Sync for RegionBlock<T> {}

impl<T: ZeroEmpty> Drop for RegionBlock<T> {
    fn drop(&mut self) {
        // SAFETY: the block holds a `T` (zero bytes are one, and every write since kept one),
        // dropped once, here, in place; then a block reserved alone goes back with the layout it
        // was reserved by, once, and nothing reaches it after. A block within another's
        // reservation leaves it to that owner, which outlives it (`Self::within`).
        unsafe {
            core::ptr::drop_in_place(self.at.as_ptr());
            if let Some(memory) = self.memory {
                memory.release(self.at.cast::<u8>(), Layout::new::<T>());
            }
        }
    }
}

/// A value that lies in a field of a region and that this handle owns: reached through the
/// pointer to the field, never through a reference to the whole region, and dropped in place by
/// the handle's drop, which the region's own drop leaves to it (the field is a `MaybeUninit`). So
/// the order a value is let go in is its handle's, wherever the handle is held, while its memory
/// is the region's.
pub struct RegionField<T> {
    at: NonNull<T>,
}

impl<T> RegionField<T> {
    /// The handle of the value at `at`.
    ///
    /// # Safety
    /// `at` holds a value of `T` that nothing else drops or reaches but through this handle, and
    /// its memory stays, unmoved, until after the handle is dropped.
    pub unsafe fn new(at: NonNull<T>) -> Self {
        Self { at }
    }
}

impl<T> Deref for RegionField<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the value is the handle's alone (`Self::new`), so a shared borrow of the handle
        // is one of the value.
        unsafe { self.at.as_ref() }
    }
}

impl<T> DerefMut for RegionField<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`; a unique borrow of the handle is the only one of the value.
        unsafe { self.at.as_mut() }
    }
}

impl<T> Drop for RegionField<T> {
    fn drop(&mut self) {
        // SAFETY: the value is the handle's alone and still in place (`Self::new`); it is dropped
        // once, here, and not reached after.
        unsafe { core::ptr::drop_in_place(self.at.as_ptr()) }
    }
}

// SAFETY: the handle owns its value as a `Box` does: it moves to another thread when the value may.
unsafe impl<T: Send> Send for RegionField<T> {}
// SAFETY: a shared handle hands out shared references to its value only.
unsafe impl<T: Sync> Sync for RegionField<T> {}

/// The lines of a [`StateRegion`]'s description, at most: its registry's.
pub const STATE_REGION_LINES: usize = REGISTRY_REGION_LINES;

/// The state of a session of the build's shape: see the module documentation. The key arena is the
/// last field, so a region dropped in place lets go of its keys after the registry, whose handle
/// drops it first.
pub struct StateRegion {
    registry: RegistryRegion,
    /// The values the state owns and its tasks reach by handles: its round, its planes and its
    /// step places, written by the open (`StatePlaces`), none of them laid out over rows here.
    places: StatePlaces,
    keys: KeyArena<{ caps::KEY_ARENA_BYTES }>,
}

// SAFETY: the registry's region, the places and the key arena are `ZeroEmpty`.
unsafe impl ZeroEmpty for StateRegion {}

impl StateRegion {
    /// The region's description: the lines that place each table of the registry over its rows
    /// and hand each the key arena, read as the region is placed.
    pub const DESCRIPTION: RegionLines<STATE_REGION_LINES> =
        RegistryRegion::places(core::mem::offset_of!(Self, registry));

    /// The state of a session of `config` in `build`, the region the build lays out: refused as
    /// [`ArenaRegion::admit`] refuses the config, having reserved nothing, or as
    /// [`RegionBlock::reserve`] refuses the memory; else reserved once, zeroed, from `memory`
    /// and placed over its rows. Nothing is planned or lent: the type is the layout.
    pub fn open<E: EndpointList>(
        build: &ArenaRegion,
        config: &CoopConfig<E>,
        memory: &'static dyn ArenaMemory,
    ) -> Result<RegionBlock<Self>, ArenaRefused> {
        build.admit(config)?;
        let block = RegionBlock::<Self>::reserve(memory)?;
        // SAFETY: the block is a zeroed `StateRegion` it alone reaches; it neither moves nor goes
        // back before its drop.
        unsafe { Self::place(block.as_ptr(), build.limits()) };
        Ok(block)
    }

    /// Place each table of the zeroed region at `region` over its rows and hand it the key arena,
    /// its keys at most `limits` long and together at most the bytes `limits` state (a lowered
    /// `KEY_ARENA_BYTES` holds the arena as an arena it lends from is held), and hand back the key arena: the parts of the registry whose
    /// empty value is not zero bytes written first, each bound one of nothing until the registry
    /// is bound (`RegistryRegion::bind`).
    ///
    /// # Safety
    /// `region` points at a `StateRegion` of all zero bytes, aligned, that nothing else reaches,
    /// and which neither moves nor is given back while a table or a key of it lives.
    pub(crate) unsafe fn place(region: NonNull<Self>, limits: &SessionLimits) -> KeySpace {
        // SAFETY: the caller's contract; the registry's field of it is zeroed and reached by this
        // call alone.
        unsafe { RegistryRegion::write_parts(Self::registry_at(region), limits) };
        let at = region.as_ptr();
        // SAFETY: the key arena field alone, reached by this one reference before any key exists
        // and not after `space`; it stays in the region for as long as the tables do.
        let keys = unsafe {
            (*addr_of_mut!((*at).keys))
                .space_of(limits.key_arena_bytes(), limits.max_keyexpr_bytes_held())
        };
        // SAFETY: the description is this type's own: its lines name the tables' sequences and key
        // handles in the region, each holding no value, and the rows beside them, which only those
        // tables reach; the caller's contract keeps the region in place.
        unsafe { place_region(region.cast::<u8>(), keys, &Self::DESCRIPTION) };
        keys
    }

    /// Where the registry of the region at `region` lies.
    ///
    /// # Safety
    /// `region` points at a `StateRegion`.
    pub(crate) unsafe fn registry_at(region: NonNull<Self>) -> NonNull<RegistryRegion> {
        // SAFETY: the caller's contract: a field of a region that lies at a pointer that is not
        // null is not null either.
        unsafe { NonNull::new_unchecked(addr_of_mut!((*region.as_ptr()).registry)) }
    }

    /// Where the places of the state's own values in the region at `region` lie.
    ///
    /// # Safety
    /// `region` points at a `StateRegion`.
    pub(crate) unsafe fn places_at(region: NonNull<Self>) -> NonNull<StatePlaces> {
        // SAFETY: as `registry_at`.
        unsafe { NonNull::new_unchecked(addr_of_mut!((*region.as_ptr()).places)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every line of the region's description lies inside the region, no two place the same
    /// sequence or the same rows, and no two hand the key arena to the same handle. Turned red by
    /// an offset of a part of the registry that is not the field it names, or by a set's lines
    /// that reuse another's rows.
    #[test]
    fn a_state_regions_lines_lie_inside_it_and_name_nothing_twice() {
        let size = core::mem::size_of::<StateRegion>();
        let seqs = StateRegion::DESCRIPTION.seq_lines();
        assert!(!seqs.is_empty());
        for (at, line) in seqs.iter().enumerate() {
            assert!(line.seq < size, "a sequence lies in the region");
            assert!(
                line.room == 0 || line.rows < size,
                "its rows lie in the region"
            );
            for other in seqs.iter().skip(at + 1) {
                assert_ne!(line.seq, other.seq, "a sequence is placed once");
                if line.room != 0 && other.room != 0 {
                    assert_ne!(line.rows, other.rows, "rows are one table's");
                }
            }
        }
        let keys = StateRegion::DESCRIPTION.key_lines();
        for (at, key) in keys.iter().enumerate() {
            assert!(*key < size, "a handle lies in the region");
            assert!(!keys.iter().skip(at + 1).any(|other| other == key));
        }
    }
}
