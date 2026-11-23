// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session's key arena: one span of its [`Arena`] that the rows of its tables keep the text of
//! their keys in, each row a [`KeyRef`] of a few words, instead of a buffer of
//! `MAX_KEYEXPR_BYTES` inline in every row whatever its key's length
//! (`docs/c-abi-no-heap-pools.md`, section 9.3). Its size is the session's `KEY_ARENA_BYTES`,
//! reserved with the rest of the arena when the session opens.
//!
//! # Blocks
//!
//! A key is one block: a header of [`BLOCK_HEADER`] bytes, the block's length and how many
//! [`KeyRef`]s hold it, then the key's bytes, the whole rounded up to [`BLOCK_ALIGN`]. An empty key
//! takes no block.
//!
//! A key takes the first free block, lowest address first, that holds it, and the rest of that
//! block stays free when it is long enough to be a block of its own; a key no free block holds
//! takes the next bytes of the bump area, above every block. A block given back joins the free
//! blocks in address order and is merged with a free neighbour on either side, and a free block
//! that ends where the bump area starts is given back to it. So no two free blocks lie side by
//! side, and a program that declares and undeclares keys of a few lengths reuses the same bytes. A
//! key that no free block and not the bump area holds is refused ([`KeysExhausted`]) and counted,
//! and nothing is taken: the declaration of the session's that asked for it is refused as one that
//! finds its table full is, and one a peer sent is dropped and counted with its table's refusals.
//!
//! # Sharing
//!
//! A row that copies another's key shares its block: cloning a [`KeyRef`] counts one more holder,
//! and the block is given back when the last holder is dropped. Nothing is copied and nothing can
//! fail.
//!
//! # One thread
//!
//! The arena's state is kept in cells, so a [`KeySpace`] and every [`KeyRef`] made from it are
//! neither `Send` nor `Sync`: they are reached by the one thread that holds the session's state at
//! a time, as the rest of that state is (the cooperative engine keeps it behind its one lock).
//!
//! # Lifetime
//!
//! The arena's state lies at the start of its span, and every [`KeyRef`] points at it. Like a
//! table lent from an [`Arena`], a key must be dropped before the memory the arena was reserved
//! from is given back: the session drops every table that holds one before its arena.

use core::cell::Cell;
use core::fmt;
use core::ops::Deref;
use core::ptr::NonNull;
#[cfg(debug_assertions)]
use core::sync::atomic::{AtomicBool, Ordering};

use crate::bounded::{Arena, KeyBacking, KeyMaker, KeyUnkept};

/// The bytes of a block's header: its length and how many keys hold it (or, free, the next free
/// block), each a `u32`.
pub const BLOCK_HEADER: usize = 8;

/// What every block's length is a multiple of, so each header is aligned for its `u32`s.
pub const BLOCK_ALIGN: usize = 4;

/// The shortest free block kept apart when a longer one is split: a header and one granule. A
/// remainder shorter than this stays with the key that split it.
const MIN_BLOCK: u32 = (BLOCK_HEADER + BLOCK_ALIGN) as u32;

/// No block: the end of the free list, and where an empty key points.
const NIL: u32 = u32::MAX;

/// The header word that holds a block's length: its bytes for a free block, and for a held one its
/// key's length with the granules the block took past the key's own (`held_word`).
const SIZE: u32 = 0;

/// The header word that holds how many keys hold a block, or the next free block of a free one.
const LINK: u32 = 1;

/// The most bytes of blocks an arena of keys holds: every offset and length is a `u32`, and the
/// largest `u32` marks no block.
pub const MAX_KEY_ARENA_BYTES: usize = (u32::MAX - BLOCK_ALIGN as u32) as usize;

/// The longest key a block's length word records (`held_word`).
const MAX_KEY_LEN: usize = (u32::MAX >> 2) as usize;

const _: () = assert!(
    BLOCK_ALIGN == 4 && MIN_BLOCK - (BLOCK_ALIGN as u32) < 4 * BLOCK_ALIGN as u32,
    "a held block's slack is at most three granules, which the length word's two low bits count"
);

/// The length word of a held block: the key's `len`, and the `slack` bytes the block holds past
/// the key's own block (a free block's remainder too short to be a block of its own), counted in
/// granules in the two low bits. A walk of the blocks reads each key's length from it
/// ([`KeySpace::kept`]).
const fn held_word(len: u32, slack: u32) -> u32 {
    (len << 2) | (slack / BLOCK_ALIGN as u32)
}

/// The bytes of a held block whose length word is `word`.
const fn held_bytes(word: u32) -> u32 {
    let own = ((word >> 2) + (BLOCK_HEADER + BLOCK_ALIGN - 1) as u32) & !(BLOCK_ALIGN as u32 - 1);
    own + (word & 3) * BLOCK_ALIGN as u32
}

/// The bytes a key of `len` bytes takes as a block: its header and its bytes, rounded up to
/// [`BLOCK_ALIGN`]. `None` past [`MAX_KEY_ARENA_BYTES`].
pub const fn block_bytes(len: usize) -> Option<usize> {
    match len.checked_add(BLOCK_HEADER + BLOCK_ALIGN - 1) {
        Some(up) if up & !(BLOCK_ALIGN - 1) <= MAX_KEY_ARENA_BYTES => Some(up & !(BLOCK_ALIGN - 1)),
        _ => None,
    }
}

/// The state of a key arena, kept at the start of the span it was lent.
struct KeyStore {
    /// The first byte of the blocks, aligned to [`BLOCK_ALIGN`].
    blocks: NonNull<u8>,
    /// How many bytes of blocks there are.
    bytes: u32,
    /// Where the bump area starts: no block lies at or past it.
    top: Cell<u32>,
    /// The free block of the lowest address, or [`NIL`].
    free: Cell<u32>,
    /// The bytes of the blocks that hold a key.
    used: Cell<u32>,
    /// The most `used` has been.
    peak: Cell<u32>,
    /// The keys refused for want of room.
    refused: Cell<u32>,
    /// Whether the arena's owner keeps it behind one lock ([`KeySpace::guard_by_owner_lock`]).
    #[cfg(debug_assertions)]
    guarded: AtomicBool,
    /// Whether that lock is held now.
    #[cfg(debug_assertions)]
    held: AtomicBool,
    /// The longest key the arena keeps: the session's `MAX_KEYEXPR_BYTES` its creator lent the
    /// arena with ([`Arena::lend_keys`]), held in no byte where the build fixes the bound.
    longest: crate::limits::MaxKeyexprBytesHeld,
}

impl KeyStore {
    /// Fail at once, in a build with debug assertions, when a key of an arena its owner's lock
    /// guards is made, shared or let go of with that lock not held: the counts are cells, and a
    /// thread that touches them outside the lock races the one that holds it.
    #[inline]
    fn assert_owner_lock(&self) {
        #[cfg(debug_assertions)]
        assert!(
            !self.guarded.load(Ordering::Relaxed) || self.held.load(Ordering::Relaxed),
            "a key of an arena its owner's lock guards was touched with that lock not held"
        );
    }

    /// Header word `word` of the block at `at`.
    fn word(&self, at: u32, word: u32) -> u32 {
        // SAFETY: every block lies below `top`, inside the blocks, and starts on a multiple of
        // `BLOCK_ALIGN` from their aligned start, so its header's words are in bounds and aligned.
        unsafe {
            self.blocks
                .as_ptr()
                .add(at as usize + 4 * word as usize)
                .cast::<u32>()
                .read()
        }
    }

    /// Write header word `word` of the block at `at`.
    fn set_word(&self, at: u32, word: u32, value: u32) {
        // SAFETY: as `word`; the arena's bytes are its own, and no reference to a header is held.
        unsafe {
            self.blocks
                .as_ptr()
                .add(at as usize + 4 * word as usize)
                .cast::<u32>()
                .write(value)
        }
    }

    /// The `len` bytes of the key the held block at `at` keeps.
    fn text(&self, at: u32, len: u32) -> &[u8] {
        // SAFETY: a held block holds its header and its key's `len` bytes after it, inside the
        // blocks, which nothing writes while a holder of the block lives.
        unsafe {
            core::slice::from_raw_parts(
                self.blocks.as_ptr().add(at as usize + BLOCK_HEADER),
                len as usize,
            )
        }
    }

    /// Make `to` follow `prev` in the free list, or head it when `prev` is [`NIL`].
    fn link(&self, prev: u32, to: u32) {
        if prev == NIL {
            self.free.set(to);
        } else {
            self.set_word(prev, LINK, to);
        }
    }

    /// A block of at least `need` bytes, its length written in its header, or `None` when no free
    /// block holds it and neither does the bump area.
    fn take(&self, need: u32) -> Option<u32> {
        let (mut prev, mut at) = (NIL, self.free.get());
        while at != NIL {
            let (size, next) = (self.word(at, SIZE), self.word(at, LINK));
            if size >= need {
                let rest = size - need;
                if rest >= MIN_BLOCK {
                    let tail = at + need;
                    self.set_word(tail, SIZE, rest);
                    self.set_word(tail, LINK, next);
                    self.link(prev, tail);
                    self.set_word(at, SIZE, need);
                } else {
                    self.link(prev, next);
                }
                return Some(at);
            }
            prev = at;
            at = next;
        }
        let top = self.top.get();
        if self.bytes - top < need {
            return None;
        }
        self.top.set(top + need);
        self.set_word(top, SIZE, need);
        Some(top)
    }

    /// Give the block of `size` bytes at `at` back: into the free list in address order, merged
    /// with a free block on either side, and to the bump area when it ends where that starts.
    fn give_back(&self, at: u32, mut size: u32) {
        // The free blocks around `at`: `before` the last below it, with the one before that, and
        // `after` the first above it.
        let (mut before_prev, mut before, mut after) = (NIL, NIL, self.free.get());
        while after != NIL && after < at {
            before_prev = before;
            before = after;
            after = self.word(after, LINK);
        }
        let (mut start, mut prev) = (at, before);
        if after != NIL && at + size == after {
            size += self.word(after, SIZE);
            after = self.word(after, LINK);
        }
        if before != NIL && before + self.word(before, SIZE) == at {
            start = before;
            size += self.word(before, SIZE);
            prev = before_prev;
        }
        if start + size == self.top.get() {
            // No free block lies above one that ends where the bump area starts.
            debug_assert_eq!(after, NIL, "a free block above the bump area's start");
            self.top.set(start);
            self.link(prev, NIL);
        } else {
            self.set_word(start, SIZE, size);
            self.set_word(start, LINK, after);
            self.link(prev, start);
        }
    }
}

/// A key refused for want of room in the key arena: no free block holds it, and neither does
/// what is left of the bump area. Nothing was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeysExhausted {
    /// The bytes of the block the key asked for; `None` past [`MAX_KEY_ARENA_BYTES`].
    pub asked: Option<usize>,
}

impl fmt::Display for KeysExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.asked {
            Some(asked) => write!(f, "no room for a key of {asked} bytes in the key arena"),
            None => f.write_str("a key past the key arena's address space"),
        }
    }
}

impl core::error::Error for KeysExhausted {}

/// What a key arena holds, as [`KeySpace::counts`] reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyCounts {
    /// The bytes of blocks the arena was lent.
    pub bytes: usize,
    /// The bytes of the blocks that hold a key now, headers included.
    pub used: usize,
    /// The most `used` has been.
    pub peak: usize,
    /// The bytes no block has ever reached since the arena was lent, or since the blocks above them
    /// were given back: the bump area.
    pub untouched: usize,
    /// The keys refused for want of room.
    pub refused: u32,
}

/// The key arena of a session, which makes its keys ([`Self::key`]). A handle: copies of it name
/// the same arena. Made by [`Arena::lend_keys`].
#[derive(Clone, Copy)]
pub struct KeySpace {
    store: NonNull<KeyStore>,
}

impl KeySpace {
    /// The bytes the arena's own state takes at the start of its span, a whole span of the arena.
    const STATE_BYTES: usize = match Arena::span(core::mem::size_of::<KeyStore>()) {
        Some(bytes) => bytes,
        None => panic!("the key arena's state fits the address space"),
    };

    /// The bytes a key arena of `bytes` bytes of blocks takes in an [`Arena`]: its state and its
    /// blocks. `None` past [`MAX_KEY_ARENA_BYTES`] or the address space.
    pub const fn span_bytes(bytes: usize) -> Option<usize> {
        if bytes > MAX_KEY_ARENA_BYTES {
            return None;
        }
        match Arena::span(bytes) {
            Some(blocks) => blocks.checked_add(Self::STATE_BYTES),
            None => None,
        }
    }

    /// A key arena of `bytes` bytes of blocks over the span at `span`, none of them taken, that
    /// keeps keys of at most `longest` bytes ([`Self::holds_key`]).
    ///
    /// # Safety
    /// `span` is aligned to [`ARENA_ALIGN`](crate::bounded::ARENA_ALIGN), the
    /// [`Self::span_bytes`] of `bytes` bytes from it are valid for reads and writes and used by
    /// nothing else for as long as any copy of the space or any key made from it lives, and
    /// `bytes` is at most [`MAX_KEY_ARENA_BYTES`].
    pub(crate) unsafe fn over(
        span: NonNull<u8>,
        bytes: usize,
        longest: crate::limits::MaxKeyexprBytesHeld,
    ) -> Self {
        const {
            assert!(
                core::mem::align_of::<KeyStore>() <= crate::bounded::ARENA_ALIGN,
                "the key arena's state asks for more alignment than an arena's spans start on"
            )
        };
        let store = span.cast::<KeyStore>();
        // SAFETY: the caller's contract: the span is aligned for the state, which it starts with,
        // and the blocks follow it at a multiple of the arena's alignment, inside the span.
        unsafe {
            store.as_ptr().write(KeyStore {
                blocks: NonNull::new_unchecked(span.as_ptr().add(Self::STATE_BYTES)),
                bytes: bytes as u32,
                top: Cell::new(0),
                free: Cell::new(NIL),
                used: Cell::new(0),
                peak: Cell::new(0),
                refused: Cell::new(0),
                #[cfg(debug_assertions)]
                guarded: AtomicBool::new(false),
                #[cfg(debug_assertions)]
                held: AtomicBool::new(false),
                longest,
            });
        }
        Self { store }
    }

    /// Whether the arena keeps a key of `len` bytes: at most the session's `MAX_KEYEXPR_BYTES` it
    /// was lent with. The value is compared even where the build fixes it, because on the lent
    /// policy no row is a buffer that would refuse a longer key by itself: the arena is the bound.
    pub fn holds_key(&self, len: usize) -> bool {
        self.store().longest.get().admits(len)
    }

    /// The arena's state.
    fn store(&self) -> &KeyStore {
        // SAFETY: `over`'s contract: the state lives for as long as this handle does.
        unsafe { self.store.as_ref() }
    }

    /// `text` kept in the arena, for a row to hold: a block of its own, or none for an empty key.
    /// Refused, taking nothing and counted, when no free block and not the bump area holds it.
    pub fn key(&self, text: &str) -> Result<KeyRef, KeysExhausted> {
        if text.is_empty() {
            return Ok(KeyRef {
                store: self.store,
                at: NIL,
                len: 0,
            });
        }
        let store = self.store();
        store.assert_owner_lock();
        let refused = |asked: Option<usize>| {
            store.refused.set(store.refused.get().wrapping_add(1));
            KeysExhausted { asked }
        };
        let Some(need) = block_bytes(text.len()).filter(|_| text.len() <= MAX_KEY_LEN) else {
            return Err(refused(None));
        };
        let Some(at) = store.take(need as u32) else {
            return Err(refused(Some(need)));
        };
        let size = store.word(at, SIZE);
        store.set_word(at, SIZE, held_word(text.len() as u32, size - need as u32));
        store.set_word(at, LINK, 1);
        // SAFETY: the block at `at` holds its header and at least `text.len()` bytes after it,
        // inside the blocks, and no key reads them until this one is made.
        unsafe {
            core::ptr::copy_nonoverlapping(
                text.as_ptr(),
                store.blocks.as_ptr().add(at as usize + BLOCK_HEADER),
                text.len(),
            );
        }
        let used = store.used.get() + size;
        store.used.set(used);
        store.peak.set(store.peak.get().max(used));
        Ok(KeyRef {
            store: self.store,
            at,
            len: text.len() as u32,
        })
    }

    /// The key of the arena whose text is `text`, one holder more of its block, when a block holds
    /// it now, or `None`: one walk of the blocks in address order, the free ones known by the free
    /// list, which is in the same order. A key a row or an object outside the owner's lock asks
    /// for then takes no second block for a text the arena keeps already, whoever holds it.
    pub fn kept(&self, text: &str) -> Option<KeyRef> {
        let store = self.store();
        store.assert_owner_lock();
        let (mut at, mut free) = (0, store.free.get());
        while at < store.top.get() {
            let word = store.word(at, SIZE);
            if at == free {
                free = store.word(at, LINK);
                at += word;
                continue;
            }
            if (word >> 2) as usize == text.len() && store.text(at, word >> 2) == text.as_bytes() {
                store.set_word(at, LINK, store.word(at, LINK) + 1);
                return Some(KeyRef {
                    store: self.store,
                    at,
                    len: word >> 2,
                });
            }
            at += held_bytes(word);
        }
        None
    }

    /// The key a holder kept as [`KeyRef::into_raw`] gave it, one of its block's holders again.
    ///
    /// # Safety
    /// `at` and `len` are what `into_raw` gave for a key of this arena, whose holder they still
    /// are, and are not used again.
    pub unsafe fn adopt(&self, at: u32, len: u32) -> KeyRef {
        KeyRef {
            store: self.store,
            at,
            len,
        }
    }

    /// Keep the arena behind its owner's one lock from now on: in a build with debug assertions a
    /// key of it made, shared or let go of while the owner has not marked the lock held
    /// ([`Self::owner_lock_taken`]) fails at once, so a path that lets go of a row's key after the
    /// lock is let go of fails every test that takes it rather than racing a holder of the lock.
    /// Nothing is kept or checked in a build without debug assertions.
    pub fn guard_by_owner_lock(&self) {
        #[cfg(debug_assertions)]
        self.store().guarded.store(true, Ordering::Relaxed);
    }

    /// The owner took the lock that guards the arena.
    #[inline]
    pub fn owner_lock_taken(&self) {
        #[cfg(debug_assertions)]
        self.store().held.store(true, Ordering::Relaxed);
    }

    /// The owner is letting go of the lock that guards the arena.
    #[inline]
    pub fn owner_lock_released(&self) {
        #[cfg(debug_assertions)]
        self.store().held.store(false, Ordering::Relaxed);
    }

    /// What the arena holds now.
    pub fn counts(&self) -> KeyCounts {
        let store = self.store();
        KeyCounts {
            bytes: store.bytes as usize,
            used: store.used.get() as usize,
            peak: store.peak.get() as usize,
            untouched: (store.bytes - store.top.get()) as usize,
            refused: store.refused.get(),
        }
    }
}

impl fmt::Debug for KeySpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeySpace").field(&self.counts()).finish()
    }
}

/// The key arena a table of the [`Lent`](crate::bounded::Lent) policy makes its rows' keys in
/// ([`Storage::Keys`](crate::bounded::Storage::Keys)): the session's [`KeySpace`], which the
/// table is handed with its rows, or none for a table made by `Default`, which keeps no key.
#[derive(Clone, Copy, Debug, Default)]
pub struct LentKeys(Option<KeySpace>);

impl LentKeys {
    /// The key arena the table keeps its keys in, if it was handed one.
    pub fn space(&self) -> Option<KeySpace> {
        self.0
    }
}

impl From<KeySpace> for LentKeys {
    fn from(keys: KeySpace) -> Self {
        Self(Some(keys))
    }
}

impl KeyMaker<KeyRef> for LentKeys {
    /// A key past the session's `MAX_KEYEXPR_BYTES` the arena was lent with is refused before any
    /// room is asked ([`KeySpace::holds_key`]), as a row of the static policy refuses one past its
    /// buffer; a key the arena has no room for is refused and counted by the arena
    /// ([`KeyCounts::refused`]). A table handed no arena keeps no key.
    fn key(&self, text: &str) -> Result<KeyRef, KeyUnkept> {
        let Some(keys) = &self.0 else {
            return Err(KeyUnkept::NoRoom);
        };
        if !keys.holds_key(text.len()) {
            return Err(KeyUnkept::TooLong);
        }
        keys.key(text).map_err(|_| KeyUnkept::NoRoom)
    }
}

/// A key a row holds: where its block lies in its session's key arena and how long it is. It reads
/// as the key's text ([`Deref`] to `str`); a clone shares the block, which is given back when the
/// last of them is dropped.
pub struct KeyRef {
    store: NonNull<KeyStore>,
    /// The block, or [`NIL`] for the empty key, which has none.
    at: u32,
    len: u32,
}

impl KeyRef {
    /// The key's text.
    pub fn as_str(&self) -> &str {
        if self.at == NIL {
            return "";
        }
        // SAFETY: a key with a block points at a store that outlives it (`KeySpace::over`), and
        // its block holds the `len` bytes of the `str` it was made from.
        unsafe { core::str::from_utf8_unchecked(self.store.as_ref().text(self.at, self.len)) }
    }

    /// The bytes of the block the key holds, header included; none for the empty key.
    pub fn block_bytes(&self) -> usize {
        if self.at == NIL {
            return 0;
        }
        // SAFETY: as `as_str`.
        held_bytes(unsafe { self.store.as_ref() }.word(self.at, SIZE)) as usize
    }

    /// The key as its block's place and its length, still one of the block's holders, which
    /// nothing counts while it is apart: for a holder outside the arena owner's lock, which hands
    /// them back to [`KeySpace::adopt`] under it to share or let go of the key.
    pub fn into_raw(self) -> (u32, u32) {
        let this = core::mem::ManuallyDrop::new(self);
        (this.at, this.len)
    }

    /// Let go of the key now and leave the empty key, which holds no block, in its place: for a
    /// row taken out of its table under the lock that guards the arena and dropped after that lock
    /// is let go of, for what else it holds.
    pub fn let_go(&mut self) {
        *self = Self {
            store: self.store,
            at: NIL,
            len: 0,
        };
    }
}

impl Clone for KeyRef {
    fn clone(&self) -> Self {
        if self.at != NIL {
            // SAFETY: as `as_str`.
            let store = unsafe { self.store.as_ref() };
            store.assert_owner_lock();
            let holders = store.word(self.at, LINK);
            store.set_word(self.at, LINK, holders + 1);
        }
        Self {
            store: self.store,
            at: self.at,
            len: self.len,
        }
    }
}

impl Drop for KeyRef {
    fn drop(&mut self) {
        if self.at == NIL {
            return;
        }
        // SAFETY: as `as_str`.
        let store = unsafe { self.store.as_ref() };
        store.assert_owner_lock();
        let holders = store.word(self.at, LINK) - 1;
        if holders > 0 {
            store.set_word(self.at, LINK, holders);
            return;
        }
        let size = held_bytes(store.word(self.at, SIZE));
        store.used.set(store.used.get() - size);
        store.give_back(self.at, size);
    }
}

impl Deref for KeyRef {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl KeyBacking for KeyRef {
    fn as_str(&self) -> &str {
        KeyRef::as_str(self)
    }
}

impl AsRef<str> for KeyRef {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl PartialEq for KeyRef {
    fn eq(&self, other: &KeyRef) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for KeyRef {}

impl PartialEq<str> for KeyRef {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for KeyRef {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{LendRefused, ARENA_ALIGN};
    use crate::limit_binding::{LimitSpec, Quota};
    use crate::limits::SessionLimits;

    /// One block of an arena's memory in a test, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block {
        _bytes: [u8; ARENA_ALIGN],
    }

    /// An arena over `bytes` bytes of memory the test process leaks, so it outlives every key.
    fn arena_of(bytes: usize) -> Arena {
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] =
            std::vec![Block { _bytes: [0; ARENA_ALIGN] }; blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `bytes` bytes, and is
        // leaked, so nothing else uses it and it outlives every key.
        unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) }
    }

    /// A key arena of `bytes` bytes of blocks, lent from an arena of exactly its span, that keeps
    /// keys as long as a session that states nothing does.
    fn keys_of(bytes: usize) -> KeySpace {
        keys_held_to(bytes, SessionLimits::defaults().max_keyexpr_bytes_held())
    }

    /// [`keys_of`], keeping keys of at most `longest` bytes.
    fn keys_held_to(bytes: usize, longest: crate::limits::MaxKeyexprBytesHeld) -> KeySpace {
        let span = KeySpace::span_bytes(bytes).expect("a test arena fits");
        let mut arena = arena_of(span);
        let keys = arena
            .lend_keys(bytes, longest)
            .expect("the arena is the key arena's span");
        assert_eq!(
            arena.high_water(),
            span,
            "the span is what the key arena takes"
        );
        keys
    }

    /// The free blocks, lowest first, as (offset, length).
    fn free_blocks(keys: &KeySpace) -> std::vec::Vec<(u32, u32)> {
        let store = keys.store();
        let mut out = std::vec::Vec::new();
        let mut at = store.free.get();
        while at != NIL {
            out.push((at, store.word(at, SIZE)));
            at = store.word(at, LINK);
        }
        out
    }

    /// A key reads back as written, compares equal to its text and to an equal key held apart, and
    /// a lookup by text in a table of keys finds the row that holds it; an empty key takes nothing.
    #[test]
    fn a_key_reads_back_and_a_lookup_by_text_finds_its_row() {
        let keys = keys_of(256);
        let rows = [
            keys.key("demo/example/a").expect("room"),
            keys.key("demo/example/**").expect("room"),
            keys.key("demo/example/b").expect("room"),
        ];
        assert_eq!(rows[1].as_str(), "demo/example/**");
        assert_eq!(rows[1], "demo/example/**");
        assert_eq!(&*rows[2], "demo/example/b");
        let again = keys.key("demo/example/b").expect("room");
        assert!(
            rows[2] == again,
            "equal text is an equal key, wherever it lies"
        );
        assert!(rows[0] != again);
        assert_eq!(
            rows.iter().position(|row| *row == "demo/example/b"),
            Some(2)
        );
        assert_eq!(rows.iter().position(|row| *row == "demo/example"), None);
        let before = keys.counts().used;
        let empty = keys.key("").expect("an empty key takes no room");
        assert_eq!((empty.as_str(), empty.block_bytes()), ("", 0));
        assert_eq!(keys.counts().used, before);
        assert_eq!(
            rows[0].block_bytes(),
            block_bytes("demo/example/a".len()).expect("short"),
            "a block is its header and the key, rounded up"
        );
    }

    /// A key no free block and not the bump area holds is refused, counted, and takes nothing; the
    /// arena keeps every key it holds and takes the next key that fits.
    #[test]
    fn a_key_past_the_room_left_is_refused_counted_and_takes_nothing() {
        let block = block_bytes(8).expect("short");
        let keys = keys_of(2 * block);
        let a = keys.key("aaaaaaaa").expect("room for one");
        let b = keys.key("bbbbbbbb").expect("room for two");
        let used = keys.counts().used;
        assert_eq!(used, 2 * block);
        assert_eq!(
            keys.key("c").err(),
            Some(KeysExhausted {
                asked: Some(block_bytes(1).expect("short"))
            })
        );
        let counts = keys.counts();
        assert_eq!(
            (counts.used, counts.refused, counts.untouched),
            (used, 1, 0)
        );
        assert_eq!((a.as_str(), b.as_str()), ("aaaaaaaa", "bbbbbbbb"));
        drop(a);
        assert_eq!(
            keys.key("cccc").expect("the freed block holds it").as_str(),
            "cccc"
        );
        let none = keys_of(0);
        assert!(none.key("k").is_err(), "an arena of no bytes holds no key");
        assert_eq!(none.key("").map(|k| k.block_bytes()), Ok(0));
    }

    /// A dropped key's block is taken by the next key of its length, at the same offset; when every
    /// key is dropped the arena is as it was lent, with its peak kept.
    #[test]
    fn a_dropped_key_gives_its_block_back_and_the_next_key_reuses_it() {
        let keys = keys_of(512);
        let a = keys.key("first/key").expect("room");
        let b = keys.key("second/key").expect("room");
        let c = keys.key("third/key").expect("room");
        let (at_b, peak) = (b.at, keys.counts().peak);
        drop(b);
        assert_eq!(
            free_blocks(&keys),
            [(at_b, block_bytes(10).expect("short") as u32)]
        );
        let d = keys.key("fourth/key").expect("the freed block");
        assert_eq!(
            d.at, at_b,
            "the same length lands where the dropped key was"
        );
        assert!(free_blocks(&keys).is_empty());
        assert_eq!(keys.counts().peak, peak, "reuse raises no peak");
        drop((a, c, d));
        let counts = keys.counts();
        assert_eq!((counts.used, counts.untouched, counts.peak), (0, 512, peak));
        assert!(
            free_blocks(&keys).is_empty(),
            "every block went back to the bump area"
        );
    }

    /// Two free blocks side by side are merged, and a key as long as both together takes them; a
    /// longer free block is split and the rest stays free for the next key.
    #[test]
    fn free_neighbours_merge_and_a_longer_block_is_split() {
        let keys = keys_of(512);
        let a = keys.key("aaaaaaaaaaaaaaaa").expect("room");
        let b = keys.key("bbbbbbbbbbbbbbbb").expect("room");
        let c = keys.key("c").expect("room");
        let (at_a, block) = (a.at, a.block_bytes() as u32);
        drop(a);
        drop(b);
        assert_eq!(
            free_blocks(&keys),
            [(at_a, 2 * block)],
            "one block, not two"
        );
        let long = "l".repeat(2 * block as usize - BLOCK_HEADER);
        let both = keys.key(&long).expect("the merged block holds it");
        assert_eq!(both.at, at_a);
        drop(both);
        let short = keys.key("s").expect("room");
        assert_eq!(short.at, at_a, "the lowest free block that holds it");
        let rest = 2 * block - short.block_bytes() as u32;
        assert_eq!(
            free_blocks(&keys),
            [(at_a + short.block_bytes() as u32, rest)]
        );
        drop((short, c));
        assert_eq!(keys.counts().used, 0);
        assert!(free_blocks(&keys).is_empty());
    }

    /// A clone shares its key's block: dropping the first holder leaves the text readable and the
    /// block held, and dropping the last gives it back.
    #[test]
    fn a_shared_key_lives_until_its_last_holder() {
        let keys = keys_of(128);
        let first = keys.key("shared/key").expect("room");
        let used = keys.counts().used;
        let second = first.clone();
        assert_eq!(keys.counts().used, used, "a clone takes no block");
        assert_eq!(first.at, second.at);
        drop(first);
        assert_eq!(second.as_str(), "shared/key");
        assert_eq!(keys.counts().used, used);
        drop(second);
        assert_eq!(keys.counts().used, 0);
    }

    /// A table's key arena keeps a key as the arena does, refuses one past the `MAX_KEYEXPR_BYTES`
    /// of a session that states nothing, the build's, as a row of the static policy refuses it,
    /// before any room is asked, and one the arena has no room for as no room; a table handed no
    /// key arena keeps no key.
    #[test]
    fn a_tables_key_arena_keeps_a_key_or_says_why_not() {
        let block = block_bytes(crate::caps::MAX_KEYEXPR_BYTES).expect("the longest key");
        let keys = keys_of(block);
        let lent = LentKeys::from(keys);
        let long = "k".repeat(crate::caps::MAX_KEYEXPR_BYTES + 1);
        assert_eq!(lent.key(&long).err(), Some(KeyUnkept::TooLong));
        assert_eq!(keys.counts().refused, 0, "a key too long asks no room");
        let longest = "k".repeat(crate::caps::MAX_KEYEXPR_BYTES);
        let held = lent.key(&longest).expect("the arena holds the longest key");
        assert_eq!(held.as_str(), longest);
        assert_eq!(lent.key("k").err(), Some(KeyUnkept::NoRoom));
        assert_eq!(
            keys.counts().refused,
            1,
            "the arena counts the key it had no room for"
        );
        drop(held);
        assert_eq!(lent.key("k").map(|key| key.len()), Ok(1));
        assert_eq!(LentKeys::default().key("k").err(), Some(KeyUnkept::NoRoom));
        assert!(LentKeys::default().space().is_none());
    }

    /// An arena its owner's lock guards takes, shares and lets go of keys while the owner marks
    /// the lock held; a key let go of after the lock is let go of fails a debug build at once.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "that lock not held")]
    fn a_key_let_go_of_outside_its_owners_lock_fails() {
        let keys = keys_of(128);
        keys.guard_by_owner_lock();
        keys.owner_lock_taken();
        let key = keys.key("demo/guarded").expect("room");
        let shared = key.clone();
        drop(shared);
        keys.owner_lock_released();
        drop(key);
    }

    /// The CONTROL: the same key let go of while the lock is held, and an arena no lock guards,
    /// pass.
    #[test]
    fn a_key_let_go_of_under_its_owners_lock_passes() {
        let keys = keys_of(128);
        keys.guard_by_owner_lock();
        keys.owner_lock_taken();
        let key = keys.key("demo/guarded").expect("room");
        drop(key);
        keys.owner_lock_released();
        let unguarded = keys_of(128);
        drop(unguarded.key("demo/free").expect("room"));
        assert_eq!(keys.counts().used, 0);
    }

    /// A key let go of in place reads as the empty key and is one holder fewer of its block: the
    /// block stays while another holder shares it, and goes back with the last, whose empty key
    /// then gives nothing back when it is dropped.
    #[test]
    fn a_key_let_go_of_in_place_leaves_the_empty_key() {
        let keys = keys_of(128);
        let mut key = keys.key("demo/let/go").expect("room");
        let mut shared = key.clone();
        let block = block_bytes("demo/let/go".len()).expect("short");
        key.let_go();
        assert_eq!(key.as_str(), "");
        assert_eq!(key.block_bytes(), 0);
        assert_eq!(keys.counts().used, block, "the share keeps the block");
        assert_eq!(shared.as_str(), "demo/let/go");
        shared.let_go();
        assert_eq!(keys.counts().used, 0, "the last holder gave the block back");
        drop((key, shared));
        assert_eq!(keys.counts().used, 0, "an empty key gives nothing back");
    }

    /// A key asked for by its text is found in whichever block holds it, one holder more of that
    /// block, past a free block before it; the start of a kept key, a text past one and the empty
    /// text are no block's, and a block given back holds no key.
    #[test]
    fn a_kept_key_is_found_by_its_text_past_free_blocks() {
        let keys = keys_of(256);
        let gone = keys.key("demo/kept/gone").expect("room");
        let held = keys.key("demo/kept/a").expect("room");
        drop(gone);
        assert_eq!(
            free_blocks(&keys).len(),
            1,
            "CONTROL: a free block lies before the key"
        );
        let used = keys.counts().used;
        let found = keys.kept("demo/kept/a").expect("the block that holds it");
        assert_eq!(found.as_str(), "demo/kept/a");
        assert_eq!(keys.counts().used, used, "a found key takes no block");
        assert!(keys.kept("demo/kept/").is_none(), "the start of a kept key");
        assert!(
            keys.kept("demo/kept/ab").is_none(),
            "a text past a kept key"
        );
        assert!(keys.kept("").is_none(), "the empty text");
        drop(held);
        assert_eq!(keys.counts().used, used, "the found key holds the block");
        drop(found);
        assert_eq!(keys.counts().used, 0);
        assert!(
            keys.kept("demo/kept/a").is_none(),
            "a block given back holds no key"
        );
    }

    /// A key that takes a free block too short to split keeps the block's slack: its length still
    /// reads from the block, a walk finds it and steps over the slack to the next key, and the
    /// whole block goes back with it.
    #[test]
    fn a_key_in_a_block_with_slack_reads_and_gives_back_the_whole_block() {
        let keys = keys_of(256);
        let wide = keys.key("demo/slack/abcd").expect("room");
        let after = keys.key("demo/after").expect("room");
        let wide_bytes = wide.block_bytes();
        drop(wide);
        let narrow = keys.key("demo/slack/a").expect("the free block");
        assert!(
            block_bytes("demo/slack/a".len()).expect("short") < wide_bytes,
            "CONTROL: the key's own block is shorter than the free block it took"
        );
        assert_eq!(
            narrow.block_bytes(),
            wide_bytes,
            "the slack stays with the key"
        );
        assert_eq!(narrow.as_str(), "demo/slack/a");
        let found = keys.kept("demo/slack/a").expect("found with its slack");
        let next = keys
            .kept("demo/after")
            .expect("the walk steps over the slack");
        assert_eq!(next.as_str(), "demo/after");
        drop((narrow, found, after, next));
        assert_eq!(keys.counts().used, 0);
        assert!(
            free_blocks(&keys).is_empty(),
            "every block went back to the bump area"
        );
    }

    /// A key kept apart as its raw parts is still one of its block's holders: adopted back, it
    /// reads its text and lets go of the block as the key would have.
    #[test]
    fn a_key_kept_apart_is_adopted_back_as_its_holder() {
        let keys = keys_of(128);
        let (at, len) = keys.key("demo/raw").expect("room").into_raw();
        assert!(keys.counts().used > 0, "the raw parts hold the block");
        // SAFETY: the parts are the raw form of a key of this arena, adopted once.
        let key = unsafe { keys.adopt(at, len) };
        assert_eq!(key.as_str(), "demo/raw");
        drop(key);
        assert_eq!(keys.counts().used, 0);
    }

    /// A key arena keeps keys up to the `MAX_KEYEXPR_BYTES` its creator lent it with, lowered
    /// under the build's, and refuses one byte more as too long, asking no room and counting
    /// nothing; a build whose domain is its own value alone has no lower bound to state.
    #[test]
    fn a_key_arena_holds_keys_to_the_bound_it_was_lent_with() {
        let mut limits = SessionLimits::defaults();
        if limits.select_max_keyexpr_bytes(Quota::at_most(8)).is_err() {
            assert!(
                <crate::limits::MaxKeyexprBytes as LimitSpec>::DOMAIN.is_singleton(),
                "only a domain of one value refuses a lower bound"
            );
            return;
        }
        let keys = keys_held_to(256, limits.max_keyexpr_bytes_held());
        assert!(keys.holds_key(8));
        assert!(!keys.holds_key(9));
        let lent = LentKeys::from(keys);
        let past = "k".repeat(9);
        assert_eq!(lent.key(&past).err(), Some(KeyUnkept::TooLong));
        assert_eq!(
            (keys.counts().used, keys.counts().refused),
            (0, 0),
            "a key past the bound takes and counts nothing"
        );
        let at = "k".repeat(8);
        let held = lent.key(&at).expect("a key of the bound itself is kept");
        assert_eq!(held.as_str(), at);
        let wide = keys_of(256);
        assert!(
            wide.holds_key(9),
            "an arena lent with the build's bound keeps the longer key"
        );
    }

    /// An arena refuses a key arena whose span is past what it has left, taking nothing, and one
    /// past the key arena's own address space.
    #[test]
    fn an_arena_refuses_a_key_arena_past_what_is_left() {
        let span = KeySpace::span_bytes(64).expect("fits");
        let mut arena = arena_of(span);
        let longest = SessionLimits::defaults().max_keyexpr_bytes_held();
        assert_eq!(
            arena.lend_keys(65, longest).err(),
            Some(LendRefused::Exhausted {
                asked: KeySpace::span_bytes(65),
                left: span,
            })
        );
        assert_eq!(arena.high_water(), 0, "a refused key arena takes nothing");
        assert_eq!(KeySpace::span_bytes(MAX_KEY_ARENA_BYTES + 1), None);
        assert!(arena.lend_keys(64, longest).is_ok());
    }
}
