// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Room in a `static` for the parts of a node's loop that live as long as it runs, on the slot
//! profile. It was `slot_node`'s, and is no client's: the admin node over Zephyr's sockets keeps its
//! host, its factory and its node in one as well, and `slot_node` (which only a client-core build has)
//! is not a module that node should need to name it.

use core::cell::{Cell, UnsafeCell};
use core::mem::MaybeUninit;

/// Room in a `static` for the parts of the loop that live as long as it runs, built in place and
/// never moved or dropped: a bump allocator of `BYTES` bytes that is filled once and not reused.
///
/// It exists for the frame of the loop. The node, its factory and its host are locals of the
/// loop's function, about 550 bytes on the Zephyr client, and a local of that function is
/// under every call the loop makes, so the worst chain of the whole node carries them. Built in
/// this arena they are in `.bss`, as the peers' machines are, and the loop holds three references.
/// The same reason made `PeerStore` (of `connect_manager`, a module of the builds that dial) and
/// the observer cell.
///
/// Like every table of the profile it is `Sync` by the profile's rule: the one cooperative loop
/// reaches it.
#[repr(C, align(8))]
pub struct RunArena<const BYTES: usize> {
    // First, so that the arena's own alignment (eight) is the alignment of the bytes.
    bytes: UnsafeCell<[MaybeUninit<u8>; BYTES]>,
    used: Cell<usize>,
}

// SAFETY: the profile's rule, stated on the type: one cooperative loop on one thread reaches the
// arena, once, at start.
unsafe impl<const BYTES: usize> Sync for RunArena<BYTES> {}

impl<const BYTES: usize> RunArena<BYTES> {
    /// An empty arena, for a `static`; all zero bytes.
    pub const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([MaybeUninit::uninit(); BYTES]),
            used: Cell::new(0),
        }
    }

    /// Whether anything was built in the arena: it is filled once, by one run.
    pub fn is_used(&self) -> bool {
        self.used.get() != 0
    }

    /// Build the value `make` returns in the arena, where it stays, and lend it for as long as the
    /// arena lives. `None` when it does not fit in what is left.
    ///
    /// `make`'s value is the call's own result, written where it is kept. A caller that keeps its
    /// own frame short does the building in a function of its own (`assemble`).
    // A shared reference lends a unique one, which is what a bump arena is: `used` only grows, so no
    // byte is lent twice (the safety argument is in the body).
    #[allow(clippy::mut_from_ref)]
    pub fn put<V>(&'static self, make: impl FnOnce() -> V) -> Option<&'static mut V> {
        const {
            assert!(
                core::mem::align_of::<V>() <= 8,
                "the arena is aligned to eight"
            )
        };
        let align = core::mem::align_of::<V>();
        let start = self.used.get().checked_add(align - 1)? & !(align - 1);
        let end = start.checked_add(core::mem::size_of::<V>())?;
        if end > BYTES {
            return None;
        }
        self.used.set(end);
        // SAFETY: `[start, end)` is inside the arena, aligned for `V` (the arena is aligned to eight
        // and `start` to `V`), and was handed to nobody: `used` only grows, so this range is
        // this call's alone, and the reference lent is the only one to it.
        unsafe {
            let at = self.bytes.get().cast::<u8>().add(start).cast::<V>();
            at.write(make());
            Some(&mut *at)
        }
    }
}

impl<const BYTES: usize> Default for RunArena<BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

/// The bytes of a [`RunArena`] that hold `parts` (size and alignment of each, in the order they
/// are built), for a `const` that holds an image's number to what its loop builds.
pub const fn run_bytes_needed(parts: &[(usize, usize)]) -> usize {
    let mut used = 0;
    let mut at = 0;
    while at < parts.len() {
        let (size, align) = parts[at];
        used = (used + align - 1) & !(align - 1);
        used += size;
        at += 1;
    }
    used
}
