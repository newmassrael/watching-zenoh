// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The key an object of a C ABI keeps ([`HeldKey`]): a block of its session's key arena, or a copy
//! of its own, and the one door an engine that keeps a key arena offers for it ([`SessionKeys`]).
//!
//! An engine whose session keeps its keys in a key arena (`wz_session_core::key_arena`) holds
//! each text once, as a block every holder counts, instead of a copy of the key in each object
//! that names it. The objects of a C ABI (a declared key expression, a write filter, an entity's
//! own key) live outside the session's lock and are dropped from any thread, while the arena's
//! counts are the session's state, touched only under that lock. So such an object holds its key
//! as a [`HeldKey`], whose text it reads with no lock and no branch (the bytes of a held block are
//! written once, before its first holder, and never again while it is held), and asks the engine
//! to hold, share or let go of a block through one call ([`SessionKeys::key`]), which the engine
//! answers under the lock in one body.

use alloc::boxed::Box;
use core::ptr::NonNull;

use wz_session_core::key_arena::{KeyRef, KeySpace};

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

/// The place of a key that is a copy of its own. No block of an arena lies there: blocks lie
/// below `MAX_KEY_ARENA_BYTES`, and an arena's empty key has the place `u32::MAX`.
const OWN: u32 = u32::MAX - 1;

/// A key an object outside its session's lock keeps: where its text lies and the block that holds
/// it, one of the block's holders; or a copy of its own ([`Self::own`]).
///
/// A key of an arena is not shared or given back by itself: [`SessionKeys::key`] does that, under
/// the session's lock. One dropped without being let go of leaves its block taken until the
/// session's arena is given back, which is a block of the arena and never memory read after it is
/// freed; a copy of its own is freed by [`Self::free_own`].
pub struct HeldKey {
    /// The first byte of the key's text, read with no lock.
    text: NonNull<u8>,
    len: usize,
    /// The block in the arena, or [`OWN`].
    at: u32,
}

// SAFETY: a key's count and its arena's state are touched only through `share` and `release`,
// whose callers hold the lock of the session the arena belongs to, and a copy of its own is
// touched only by its one owner's `free_own`; what any thread reads with no lock is the text,
// which no one writes while a holder of it lives.
unsafe impl Send for HeldKey {}
// SAFETY: as `Send`: a shared reference reads the text alone.
unsafe impl Sync for HeldKey {}

impl HeldKey {
    /// `key`, held apart from its arena: this is its holder from now on. Nothing is counted, so
    /// no lock is needed.
    pub fn of(key: KeyRef) -> Self {
        let text = NonNull::from(key.as_str().as_bytes()).cast::<u8>();
        let (at, len) = key.into_raw();
        Self {
            text,
            len: len as usize,
            at,
        }
    }

    /// A copy of `text` of its own, on the heap: for a key no session's arena keeps, made with no
    /// session, for an engine that keeps no key arena or for a closed session.
    pub fn own(text: &str) -> Self {
        let own: Box<str> = text.into();
        let len = own.len();
        Self {
            text: NonNull::from(Box::leak(own).as_bytes()).cast::<u8>(),
            len,
            at: OWN,
        }
    }

    /// Whether this is a copy of its own ([`Self::own`]).
    pub fn is_own(&self) -> bool {
        self.at == OWN
    }

    /// The key's text.
    pub fn as_str(&self) -> &str {
        // SAFETY: `text` and `len` are the bytes of the `str` the key was made from, in a block
        // this holder keeps taken or in its own copy, which nothing writes while it is held.
        unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                self.text.as_ptr(),
                self.len,
            ))
        }
    }

    /// Free a copy of its own.
    ///
    /// # Safety
    /// `self` is a copy of its own ([`Self::is_own`]), freed once.
    pub unsafe fn free_own(self) {
        // SAFETY: the caller's contract: `text` and `len` are the `Box<str>` `own` leaked.
        drop(unsafe {
            Box::from_raw(
                core::ptr::slice_from_raw_parts_mut(self.text.as_ptr(), self.len) as *mut str,
            )
        });
    }

    /// Another holder of this key's block, counted.
    ///
    /// # Safety
    /// The lock of the session whose key arena `keys` is, which made this key, is held.
    pub unsafe fn share(&self, keys: &KeySpace) -> Self {
        // SAFETY: the caller's contract; the key adopted is this holder, kept apart again below.
        let key = unsafe { keys.adopt(self.at, self.len as u32) };
        let shared = Self::of(key.clone());
        let _ = key.into_raw();
        shared
    }

    /// Let go of this holder: the block goes back with its last.
    ///
    /// # Safety
    /// As [`Self::share`].
    pub unsafe fn release(self, keys: &KeySpace) {
        // SAFETY: the caller's contract; the key adopted is this holder, which ends here.
        drop(unsafe { keys.adopt(self.at, self.len as u32) });
    }

    /// Another holder of this key's block that is not one of its count, for a session that will
    /// neither make a key nor give a block back again.
    ///
    /// # Safety
    /// The session's arena makes no key and gives no block back for as long as the copy lives, and
    /// the copy is never shared or let go of through the arena.
    pub unsafe fn uncounted(&self) -> Self {
        Self {
            text: self.text,
            len: self.len,
            at: self.at,
        }
    }
}

impl core::fmt::Debug for HeldKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

/// What an object of a C ABI asks of its session's key arena ([`SessionKeys::key`]).
pub enum KeyAsk<'a> {
    /// Hold `text`: the block a key of the same text has already, whoever holds it, or one of its
    /// own.
    Hold(&'a str),
    /// One more holder of a held key's block.
    Share(&'a HeldKey),
    /// Let go of a held key; its block goes back with its last holder.
    Release(HeldKey),
}

/// What an engine whose session keeps a key arena offers the objects of a C ABI for their keys
/// ([`crate::SessionEngine::key_arena`]): one call, which the engine answers under the session's
/// lock in one body for every key an object holds.
pub trait SessionKeys {
    /// Do what `ask` asks: the key held or shared, `None` for a release, or why no key was held.
    fn key(&self, ask: KeyAsk<'_>) -> Result<Option<HeldKey>, KeyNotHeld>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::bounded::{Arena, ARENA_ALIGN};
    use wz_session_core::key_arena::block_bytes;

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
        let held = HeldKey::of(keys.key("demo/held/key").expect("room"));
        assert_eq!(held.as_str(), "demo/held/key");
        assert!(!held.is_own());
        let block = block_bytes("demo/held/key".len()).expect("short");
        assert_eq!(keys.counts().used, block);
        // SAFETY: the test is the session's one thread, and the arena is leaked.
        let shared = unsafe { held.share(&keys) };
        assert_eq!(keys.counts().used, block, "a share takes no block");
        // SAFETY: as above.
        unsafe { held.release(&keys) };
        assert_eq!(shared.as_str(), "demo/held/key", "the share still reads it");
        assert_eq!(keys.counts().used, block);
        // SAFETY: as above.
        unsafe { shared.release(&keys) };
        assert_eq!(keys.counts().used, 0, "the last holder gave the block back");
    }

    /// An uncounted copy reads the key and is no holder; the counted holder's release gives the
    /// block back.
    #[test]
    fn an_uncounted_copy_is_no_holder() {
        let keys = keys_of(128);
        let held = HeldKey::of(keys.key("demo/uncounted").expect("room"));
        // SAFETY: the test makes no key and gives no block back while the copy lives, and never
        // hands the copy to the arena.
        let copy = unsafe { held.uncounted() };
        assert_eq!(copy.as_str(), "demo/uncounted");
        // SAFETY: the test is the session's one thread, and the arena is leaked.
        unsafe { held.release(&keys) };
        assert_eq!(keys.counts().used, 0, "the copy held nothing");
    }

    /// A copy of its own reads back its text and is freed by its owner; it is no key of an arena.
    #[test]
    fn a_copy_of_its_own_reads_back_and_is_freed() {
        let own = HeldKey::own("demo/own/key");
        assert!(own.is_own());
        assert_eq!(own.as_str(), "demo/own/key");
        let empty = HeldKey::own("");
        assert_eq!(empty.as_str(), "");
        // SAFETY: each is a copy of its own, freed once.
        unsafe {
            own.free_own();
            empty.free_own();
        }
    }

    /// A key dropped without being released keeps its block, and reads nothing freed.
    #[test]
    fn a_key_dropped_unreleased_keeps_its_block() {
        let keys = keys_of(128);
        let used = {
            let _unreleased = HeldKey::of(keys.key("demo/kept").expect("room"));
            keys.counts().used
        };
        assert!(used > 0);
        assert_eq!(keys.counts().used, used, "the block stays taken");
    }
}
