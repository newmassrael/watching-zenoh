// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The droppable publishes a session that holds every face under one lock owes its other faces.
//!
//! Each of zenoh's transports has a transmission queue of its own, so a message one transport's
//! full queue drops is still queued on the others. A session that holds its faces under one lock
//! drops a droppable publish that finds the lock held by a send waiting on one face, and keeps it
//! here until whoever holds the session next sends it to the faces it was not dropped on. What it
//! keeps lies in room the session took when it opened: a place of the batch it advertises for each
//! publish, its key, payload and attachment together, and a row beside it for the rest of the
//! publish's options. A publish that finds no place, or is longer than one, is dropped on every
//! face, the drop it already is; nothing here takes memory of the heap.
//!
//! The faces a publish was dropped on are the places their rooms hold in the session's table of
//! rooms ([`FaceSlots`]), with the mark of when the set was read: a face that took a place after
//! that is not one the publish was dropped on, whatever place it holds.

use wz_session_core::bounded::{BoundedVec, Lent};
use wz_session_core::byte_cells::{ByteBuf, LentByteCells};
use wz_session_core::publish_options::{PublishEncoding, PublishOptions};
use wz_session_core::qos::Priority;
use wz_session_core::sample::BoundedEncoding;

/// A set of the places of a session's table of rooms, `WORDS` words of bits, read when the
/// table's mark stood at [`Self::as_of`]: the faces a droppable publish was dropped on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaceSlots<const WORDS: usize> {
    words: [u64; WORDS],
    as_of: u64,
    every: bool,
}

impl<const WORDS: usize> FaceSlots<WORDS> {
    /// No place, of a table whose mark stands at `as_of`.
    pub const fn none(as_of: u64) -> Self {
        Self {
            words: [0; WORDS],
            as_of,
            every: false,
        }
    }

    /// Add place `at`. A place past the set's words marks the set as every face's
    /// ([`Self::is_every`]): a publish dropped on a face the set cannot name is dropped on all.
    pub fn insert(&mut self, at: usize) {
        match bit_of(at).and_then(|(word, bit)| Some((self.words.get_mut(word)?, bit))) {
            Some((word, bit)) => *word |= bit,
            None => self.every = true,
        }
    }

    /// Whether place `at` is in the set.
    pub fn contains(&self, at: usize) -> bool {
        self.every
            || bit_of(at).is_some_and(|(word, bit)| {
                self.words.get(word).is_some_and(|held| (held & bit) != 0)
            })
    }

    /// How many places the set names.
    pub fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .fold(0, usize::saturating_add)
    }

    /// Whether the set names no place, nor every face.
    pub fn is_empty(&self) -> bool {
        !self.every && self.len() == 0
    }

    /// Whether the set names a place it has no word for, and so stands for every face.
    pub const fn is_every(&self) -> bool {
        self.every
    }

    /// Whether the face that took place `at` at the table's mark `since` is one of the set: its
    /// place is in the set and it held it when the set was read. The one reading of a set, which
    /// a face's own send state makes as the session's table of rooms does.
    pub fn names(&self, at: usize, since: u64) -> bool {
        since <= self.as_of && self.contains(at)
    }

    /// Whether the publish dropped on the set is owed to the face that took place `at` at the
    /// table's mark `since`: the face held its place when the set was read, as a transport that
    /// was there when the publish was made, and is not one of the set. A face that came after is
    /// owed nothing, as a transport that opened after a publish is not sent it.
    pub fn owes(&self, at: usize, since: u64) -> bool {
        since <= self.as_of && !self.contains(at)
    }

    /// The mark of the table of rooms when the set was read: a face that took its place after it
    /// is in no set read before.
    pub const fn as_of(&self) -> u64 {
        self.as_of
    }
}

/// The word of place `at` and its bit there.
fn bit_of(at: usize) -> Option<(usize, u64)> {
    let word = at.checked_shr(u64::BITS.trailing_zeros())?;
    let shift = u32::try_from(at & (u64::BITS as usize).wrapping_sub(1)).ok()?;
    Some((word, 1u64.checked_shl(shift)?))
}

/// One publish a session keeps for its other faces: its key, payload and attachment in a place of
/// its own, the rest of its options beside them, and the faces it was dropped on.
pub struct HandedLeg<const WORDS: usize> {
    bytes: ByteBuf,
    key: usize,
    payload: usize,
    attachment: Option<usize>,
    encoding: Option<BoundedEncoding>,
    options: PublishOptions<'static>,
    dropped_on: FaceSlots<WORDS>,
}

impl<const WORDS: usize> HandedLeg<WORDS> {
    /// The publish's key expression.
    pub fn keyexpr(&self) -> &str {
        let key = self.bytes.as_slice().get(..self.key).unwrap_or_default();
        core::str::from_utf8(key).unwrap_or_default()
    }

    /// The publish's payload.
    pub fn payload(&self) -> &[u8] {
        let end = self.key.saturating_add(self.payload);
        self.bytes.as_slice().get(self.key..end).unwrap_or_default()
    }

    /// The publish's options as it was made with them: its encoding and attachment read where the
    /// leg keeps them.
    pub fn options(&self) -> PublishOptions<'_> {
        let mut options: PublishOptions<'_> = self.options.clone();
        options.encoding = self
            .encoding
            .as_ref()
            .map(|encoding| PublishEncoding::Lent(encoding.view()));
        options.attachment = self.attachment.and_then(|len| {
            let from = self.key.saturating_add(self.payload);
            self.bytes.as_slice().get(from..from.saturating_add(len))
        });
        options
    }

    /// The faces the publish was dropped on.
    pub fn dropped_on(&self) -> &FaceSlots<WORDS> {
        &self.dropped_on
    }

    /// The priority the publish is sent at.
    pub fn priority(&self) -> Priority {
        self.options.priority_band()
    }
}

/// The publishes a session keeps for its other faces, in the order they were kept: a place of
/// `places` for each, and a row of `legs` for each, as many rows as places. A session that keeps
/// none has neither ([`Default`]).
#[derive(Default)]
pub struct HandedLegs<const WORDS: usize> {
    places: Option<LentByteCells>,
    legs: BoundedVec<HandedLeg<WORDS>, { usize::MAX }, Lent>,
}

// SAFETY: the table's places and rows lie in memory the session reserved, used by nothing but this
// table, and its holder reaches the table only under one lock: a place is claimed and given back,
// and a row pushed and taken, by one thread at a time. A leg taken out stays with the thread that
// took it and is given back under the same lock (`HandedLegs::give_back`).
unsafe impl<const WORDS: usize> Send for HandedLegs<WORDS> {}

impl<const WORDS: usize> HandedLegs<WORDS> {
    /// The publishes a session keeps in `places`, one to a place, each with its row of `legs`.
    pub fn over(
        places: LentByteCells,
        legs: BoundedVec<HandedLeg<WORDS>, { usize::MAX }, Lent>,
    ) -> Self {
        Self {
            places: Some(places),
            legs,
        }
    }

    /// Whether no publish is kept.
    pub fn is_empty(&self) -> bool {
        self.legs.is_empty()
    }

    /// How many kept publishes are sent at `priority`.
    pub fn held_at(&self, priority: Priority) -> usize {
        self.legs
            .iter()
            .filter(|leg| leg.priority() == priority)
            .count()
    }

    /// Keep the publish of `payload` on `keyexpr` with `options`, dropped on `dropped_on`:
    /// `false`, keeping nothing, when no place is free, the publish is longer than a place, or its
    /// encoding's schema is longer than a kept encoding holds. Nothing is allocated.
    pub fn keep(
        &mut self,
        keyexpr: &str,
        payload: &[u8],
        options: &PublishOptions<'_>,
        dropped_on: FaceSlots<WORDS>,
    ) -> bool {
        if dropped_on.is_every() {
            return false;
        }
        let (kept, encoding, attachment) = options.lend_apart();
        let Ok(encoding) = encoding.map(BoundedEncoding::of).transpose() else {
            return false;
        };
        let Some(mut bytes) = self.places.as_ref().and_then(LentByteCells::claim) else {
            return false;
        };
        let key = keyexpr.as_bytes();
        if !write_parts(
            bytes.as_mut_slice(),
            [key, payload, attachment.unwrap_or_default()],
        ) {
            return false;
        }
        let leg = HandedLeg {
            bytes,
            key: key.len(),
            payload: payload.len(),
            attachment: attachment.map(<[u8]>::len),
            encoding,
            options: kept,
            dropped_on,
        };
        self.legs.push(leg).is_ok()
    }

    /// The first publish kept, taken out to be sent. Its taker gives it back under the same lock it
    /// took it under ([`Self::give_back`]), so that its place is free for the next.
    pub fn take_first(&mut self) -> Option<HandedLeg<WORDS>> {
        if self.legs.is_empty() {
            None
        } else {
            Some(self.legs.remove(0))
        }
    }

    /// Give back `leg`'s place: what a taker does once it has sent it.
    pub fn give_back(&mut self, leg: HandedLeg<WORDS>) {
        drop(leg);
    }

    /// Give back every place: what the session does before it lets go of the memory they lie in.
    pub fn clear(&mut self) {
        self.legs.clear();
    }
}

/// Write `parts` one after the other at the start of `into`: `false` when they are longer.
fn write_parts(into: &mut [u8], parts: [&[u8]; 3]) -> bool {
    let mut at = 0usize;
    for part in parts {
        let Some(end) = at.checked_add(part.len()) else {
            return false;
        };
        let Some(room) = into.get_mut(at..end) else {
            return false;
        };
        room.copy_from_slice(part);
        at = end;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::alloc::Layout;
    use core::ptr::NonNull;
    use wz_session_core::bounded::{Arena, ARENA_ALIGN};

    const WORDS: usize = 2;

    /// An arena of `bytes` the test never gives back.
    fn arena(bytes: usize) -> Arena {
        let layout = Layout::from_size_align(bytes, ARENA_ALIGN).expect("a layout");
        // SAFETY: the layout is of a nonzero size.
        let base = NonNull::new(unsafe { alloc::alloc::alloc_zeroed(layout) }).expect("memory");
        // SAFETY: the memory is aligned to `ARENA_ALIGN`, `bytes` long, used by nothing else and
        // never given back.
        unsafe { Arena::over(base, bytes) }
    }

    fn table(arena: &mut Arena, places: usize, place_bytes: usize) -> HandedLegs<WORDS> {
        let cells = arena
            .lend_byte_cells(place_bytes, places)
            .expect("the arena holds the places");
        let legs = arena.lend(places).expect("the arena holds the rows");
        HandedLegs::over(cells, legs)
    }

    /// A kept publish is read back as it was made, its attachment and the faces it was dropped on
    /// with it, in the order kept; one past the places, or longer than a place, is not kept; and a
    /// place given back is kept into again. Turned red by a place left claimed after its leg is
    /// given back, or parts read back out of their places.
    #[test]
    fn a_kept_publish_reads_back_whole_and_its_place_comes_back() {
        let mut arena = arena(1 << 14);
        let mut handed = table(&mut arena, 2, 32);
        let mut dropped = FaceSlots::<WORDS>::none(3);
        dropped.insert(1);
        let attached = *b"att";
        let options = PublishOptions::put().with_attachment(&attached);
        assert!(handed.keep("demo/a", b"one", &options, dropped));
        assert!(handed.keep("demo/b", b"two", &PublishOptions::put(), FaceSlots::none(3)));
        assert!(
            !handed.keep(
                "demo/c",
                b"three",
                &PublishOptions::put(),
                FaceSlots::none(3)
            ),
            "a third publish finds no place"
        );
        let first = handed.take_first().expect("the first kept");
        assert_eq!(first.keyexpr(), "demo/a");
        assert_eq!(first.payload(), b"one");
        assert_eq!(first.options().attachment, Some(&attached[..]));
        assert!(first.dropped_on().contains(1));
        assert!(!first.dropped_on().contains(0));
        handed.give_back(first);
        assert!(
            handed.keep(
                "demo/c",
                b"three",
                &PublishOptions::put(),
                FaceSlots::none(3)
            ),
            "the place given back is kept into"
        );
        assert!(
            !handed.keep(
                "demo/d",
                &[0; 40],
                &PublishOptions::put(),
                FaceSlots::none(3)
            ),
            "a publish longer than a place is not kept"
        );
        assert_eq!(
            handed.take_first().map(|leg| leg.payload() == b"two"),
            Some(true)
        );
    }

    /// A set names a place's face only when that face held the place when the set was read, and
    /// the publish is owed only to a face that was there then and is not named. Turned red by a set
    /// that names a face that came after it, or a publish owed to a face that came after it.
    #[test]
    fn a_set_names_only_the_faces_that_held_their_places_when_it_was_read() {
        let mut set = FaceSlots::<WORDS>::none(5);
        set.insert(3);
        assert!(set.names(3, 5), "the face that held the place then");
        assert!(set.names(3, 1));
        assert!(
            !set.names(3, 6),
            "a face that took the place after the set was read"
        );
        assert!(!set.names(4, 1), "a place the set does not hold");
        assert!(
            set.owes(4, 1),
            "a face that was there and not dropped on is owed it"
        );
        assert!(!set.owes(3, 1), "a face it was dropped on is owed nothing");
        assert!(
            !set.owes(4, 6),
            "a face that came after the set is owed nothing"
        );
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
    }

    /// A set past its words stands for every face, and a publish dropped on every face is not
    /// kept; a table of no place keeps nothing. Turned red by a place past the words dropped
    /// silently, which would send the publish to the face it was dropped on.
    #[test]
    fn a_set_past_its_words_is_every_face_and_keeps_nothing() {
        let mut set = FaceSlots::<WORDS>::none(0);
        set.insert(WORDS * 64);
        assert!(set.is_every());
        assert!(set.contains(0));
        let mut arena = arena(1 << 12);
        let mut handed = table(&mut arena, 1, 32);
        assert!(!handed.keep("demo/a", b"x", &PublishOptions::put(), set));
        let mut none = HandedLegs::<WORDS>::default();
        assert!(!none.keep("demo/a", b"x", &PublishOptions::put(), FaceSlots::none(0)));
        assert!(none.is_empty());
    }
}
