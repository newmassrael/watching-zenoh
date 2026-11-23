// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A key an object of a C ABI keeps in its session's key arena ([`HeldKey`]), and what an engine
//! that keeps one offers for it ([`SessionKeys`]).
//!
//! An engine whose session keeps its keys in a key arena (`wz_session_core::key_arena`) holds
//! each key once, as a block every holder counts, instead of a copy of the key in each object that
//! names it. The objects of a C ABI (a declared key expression, a write filter, an entity's own key)
//! live outside the session's lock and are dropped from any thread, while the arena's counts are
//! the session's state, touched only under that lock. So such an object holds its key as a
//! [`HeldKey`], whose text it reads with no lock (the bytes of a held block are written once,
//! before its first holder, and never again while it is held), and asks the engine to share or let
//! go of it, which the engine does under the lock ([`SessionKeys`]).

use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use wz_session_core::key_arena::KeyRef;

/// Why an engine kept no key for an object of the C ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyNotHeld {
    /// The key is longer than the session's `MAX_KEYEXPR_BYTES`.
    TooLong,
    /// The session's key arena has no room for it; the arena counts the refusal.
    NoRoom,
    /// The session is closed and makes no key.
    Closed,
}

/// A key held in a session's key arena by an object outside the session's lock.
///
/// It is not shared or given back by itself: [`SessionKeys::share_key`] and
/// [`SessionKeys::release_key`] do that, under the session's lock. One dropped without being
/// released leaves its block taken until the session's arena is given back, which is a block of the
/// arena and never memory read after it is freed.
pub struct HeldKey {
    key: ManuallyDrop<KeyRef>,
    /// The first byte of the key's text in its block, read with no lock.
    text: NonNull<u8>,
    len: usize,
    /// Whether this holder is one of the block's count. A key shared after its session closed is
    /// not: a closed session makes no key and gives no block back, so the block outlives it.
    counted: bool,
}

// SAFETY: the key's count and its arena's state are touched only through `share` and `release`,
// whose callers hold the lock of the session the arena belongs to; what any thread reads with no
// lock is the text, which no one writes while a holder of its block lives.
unsafe impl Send for HeldKey {}
// SAFETY: as `Send`: a shared reference reads the text alone.
unsafe impl Sync for HeldKey {}

impl HeldKey {
    /// `key`, held by an object outside the session's lock.
    ///
    /// # Safety
    /// The lock of the session whose key arena made `key` is held, and the arena outlives every
    /// copy of the key this one is shared into.
    pub unsafe fn new(key: KeyRef) -> Self {
        let text = NonNull::from(key.as_str().as_bytes()).cast::<u8>();
        let len = key.len();
        Self {
            key: ManuallyDrop::new(key),
            text,
            len,
            counted: true,
        }
    }

    /// The key's text.
    pub fn as_str(&self) -> &str {
        // SAFETY: `text` and `len` are the bytes of the `str` the key was made from, in a block
        // this holder keeps taken, which nothing writes while it is held (`Self::new`).
        unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                self.text.as_ptr(),
                self.len,
            ))
        }
    }

    /// Another holder of this key's block, counted.
    ///
    /// # Safety
    /// As [`Self::new`]: the session's lock is held.
    pub unsafe fn share(&self) -> Self {
        // SAFETY: the caller's contract.
        unsafe { Self::new(KeyRef::clone(&*self.key)) }
    }

    /// Another holder of this key's block that is not one of its count, for a session that will
    /// neither make a key nor give a block back again.
    ///
    /// # Safety
    /// The session's arena makes no key and gives no block back for as long as the copy lives.
    pub unsafe fn uncounted(&self) -> Self {
        Self {
            // SAFETY: a copy of the handle that is never dropped (`counted` is `false`), so the
            // count it does not hold is never given back.
            key: ManuallyDrop::new(unsafe { core::ptr::read(&*self.key) }),
            text: self.text,
            len: self.len,
            counted: false,
        }
    }

    /// Let go of this holder: the block is given back when it was the last one counted.
    ///
    /// # Safety
    /// As [`Self::new`]: the session's lock is held.
    pub unsafe fn release(self) {
        let mut this = ManuallyDrop::new(self);
        if this.counted {
            // SAFETY: the caller holds the session's lock, and `this` is never used again.
            unsafe { ManuallyDrop::drop(&mut this.key) }
        }
    }
}

impl core::fmt::Debug for HeldKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

/// What an engine whose session keeps a key arena offers the objects of a C ABI for their keys
/// ([`crate::SessionEngine::key_arena`]). A key equal to one the session's own record keeps is
/// shared with it rather than copied, so a key every object of a declaration names takes one
/// block.
pub trait SessionKeys {
    /// `text` held in the session's key arena, or why not.
    fn hold_key(&self, text: &str) -> Result<HeldKey, KeyNotHeld>;

    /// Another holder of `key`'s block.
    fn share_key(&self, key: &HeldKey) -> HeldKey;

    /// Let go of `key`; its block is given back with its last holder.
    fn release_key(&self, key: HeldKey);
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::bounded::{Arena, ARENA_ALIGN};
    use wz_session_core::key_arena::{block_bytes, KeySpace};

    /// One block of an arena's memory in a test, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block {
        _bytes: [u8; ARENA_ALIGN],
    }

    /// A key arena of `bytes` bytes of blocks over memory the test process leaks, so it outlives
    /// every key.
    fn keys_of(bytes: usize) -> KeySpace {
        let span = KeySpace::span_bytes(bytes).expect("a test arena fits");
        let blocks = span.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] = alloc::vec![
            Block {
                _bytes: [0; ARENA_ALIGN]
            };
            blocks
        ]
        .leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `span` bytes, and is
        // leaked, so nothing else uses it and it outlives every key.
        let mut arena = unsafe { Arena::over(NonNull::from(region).cast::<u8>(), span) };
        arena
            .lend_keys(
                bytes,
                wz_session_core::limits::SessionLimits::defaults().max_keyexpr_bytes_held(),
            )
            .expect("the arena is the key arena's span")
    }

    /// A held key reads back as its text; a share counts one holder more, and the block is given
    /// back with the last counted holder released.
    #[test]
    fn a_held_key_reads_back_and_its_block_goes_with_its_last_holder() {
        let keys = keys_of(128);
        let key = keys.key("demo/held/key").expect("room");
        // SAFETY: the test is the session's one thread, and the arena is leaked.
        let held = unsafe { HeldKey::new(key) };
        assert_eq!(held.as_str(), "demo/held/key");
        let block = block_bytes("demo/held/key".len()).expect("short");
        assert_eq!(keys.counts().used, block);
        // SAFETY: as above.
        let shared = unsafe { held.share() };
        assert_eq!(keys.counts().used, block, "a share takes no block");
        // SAFETY: as above.
        unsafe { held.release() };
        assert_eq!(shared.as_str(), "demo/held/key", "the share still reads it");
        assert_eq!(keys.counts().used, block);
        // SAFETY: as above.
        unsafe { shared.release() };
        assert_eq!(keys.counts().used, 0, "the last holder gave the block back");
    }

    /// An uncounted copy reads the key and its release gives nothing back; the counted holder's
    /// does.
    #[test]
    fn an_uncounted_copy_gives_nothing_back() {
        let keys = keys_of(128);
        // SAFETY: the test is the session's one thread, and the arena is leaked.
        let held = unsafe { HeldKey::new(keys.key("demo/uncounted").expect("room")) };
        let used = keys.counts().used;
        // SAFETY: the test makes no key and gives no block back while the copy lives.
        let copy = unsafe { held.uncounted() };
        assert_eq!(copy.as_str(), "demo/uncounted");
        // SAFETY: as above.
        unsafe { copy.release() };
        assert_eq!(keys.counts().used, used, "the copy was no holder");
        // SAFETY: as above.
        unsafe { held.release() };
        assert_eq!(keys.counts().used, 0);
    }

    /// A key dropped without being released keeps its block, and reads nothing freed.
    #[test]
    fn a_key_dropped_unreleased_keeps_its_block() {
        let keys = keys_of(128);
        let used = {
            // SAFETY: the test is the session's one thread, and the arena is leaked.
            let _unreleased = unsafe { HeldKey::new(keys.key("demo/kept").expect("room")) };
            keys.counts().used
        };
        assert!(used > 0);
        assert_eq!(keys.counts().used, used, "the block stays taken");
    }
}
