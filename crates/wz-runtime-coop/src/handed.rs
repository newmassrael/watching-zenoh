// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The droppable publishes a session that holds every face under one lock owes its other faces.
//!
//! Each of zenoh's transports has a transmission queue of its own, so a message one transport's
//! full queue drops is still queued on the others. A session that holds its faces under one lock
//! drops a droppable publish that finds the lock held by a send waiting on one face, and keeps it
//! here until whoever holds the session next sends it to the faces it was not dropped on. What it
//! keeps lies in a place of the batch it advertises for each publish, its key, payload and
//! attachment together, and a row beside it for the rest of the publish's options. A publish that
//! finds no place, or is longer than one, is dropped on every face, the drop it already is.
//!
//! Where the places and the rows lie is the table's storage policy ([`LegStorage`]): room the
//! session took when it opened (`Lent`), where nothing here takes memory of the heap; or, where
//! the session's tables take their memory on use (`OnUse`), the rows taken at the first publish
//! kept and each place a buffer of its own, taken when a publish finds every place taken before
//! held, at most as many as the rows, and kept for the next once its publish is sent. A refusal of
//! the heap is a publish not kept, the drop it already is.
//!
//! The faces a publish was dropped on are the places their rooms hold in the session's table of
//! rooms ([`FaceSlots`]), with the mark of when the set was read: a face that took a place after
//! that is not one the publish was dropped on, whatever place it holds.

#[cfg(not(feature = "session-slot"))]
use alloc::vec::Vec;

#[cfg(not(feature = "session-slot"))]
use wz_session_core::bounded::OnUse;
use wz_session_core::bounded::{BoundedVec, CapacityFull, Lent, Storage};
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
/// its own, of the table's storage `P`, the rest of its options beside them, and the faces it was
/// dropped on.
pub struct HandedLeg<const WORDS: usize, P: LegStorage = Lent> {
    bytes: P::Place,
    key: usize,
    payload: usize,
    attachment: Option<usize>,
    encoding: Option<BoundedEncoding>,
    options: PublishOptions<'static>,
    dropped_on: FaceSlots<WORDS>,
}

impl<const WORDS: usize, P: LegStorage> HandedLeg<WORDS, P> {
    /// The publish's key expression.
    pub fn keyexpr(&self) -> &str {
        let key = P::bytes(&self.bytes).get(..self.key).unwrap_or_default();
        core::str::from_utf8(key).unwrap_or_default()
    }

    /// The publish's payload.
    pub fn payload(&self) -> &[u8] {
        let end = self.key.saturating_add(self.payload);
        P::bytes(&self.bytes).get(self.key..end).unwrap_or_default()
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
            P::bytes(&self.bytes).get(from..from.saturating_add(len))
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

/// Where a table of kept publishes keeps them, by the storage policy of its rows: the places each
/// publish's bytes lie in, claimed as a publish is kept and given back once it is sent. A type, so a
/// session that lends its tables at the open names no allocation, and one whose tables take their
/// memory on use names no lent table.
pub trait LegStorage: Storage {
    /// What the table's places are taken from; by [`Default`], none.
    type Places: Default;

    /// A place one publish's bytes lie in.
    type Place;

    /// A place for a publish kept now; `None` when every place is held, or there is no memory for
    /// another, and the publish is not kept.
    fn claim(places: &mut Self::Places) -> Option<Self::Place>;

    /// `place`, its publish sent or not kept, back to `places` for the next.
    fn give_back(places: &mut Self::Places, place: Self::Place);

    /// The bytes of `place`.
    fn bytes(place: &Self::Place) -> &[u8];

    /// The bytes of `place`, to write a publish into.
    fn bytes_mut(place: &mut Self::Place) -> &mut [u8];
}

/// The places a session lent from the memory it reserved when it opened, while it lent some.
impl LegStorage for Lent {
    type Places = Option<LentByteCells>;
    type Place = ByteBuf;

    fn claim(places: &mut Option<LentByteCells>) -> Option<ByteBuf> {
        places.as_ref().and_then(LentByteCells::claim)
    }

    /// The place goes back to its table as it is dropped.
    fn give_back(_places: &mut Option<LentByteCells>, _place: ByteBuf) {}

    fn bytes(place: &ByteBuf) -> &[u8] {
        place.as_slice()
    }

    fn bytes_mut(place: &mut ByteBuf) -> &mut [u8] {
        place.as_mut_slice()
    }
}

/// The places of a table whose rows take their memory on use ([`OnUse`]): each a buffer of the
/// session's batch, taken of the heap when a publish finds every place taken before held, at most
/// as many as the table has rows, and kept once its publish is sent for the next. Unsized
/// ([`Default`]), it gives no place.
#[cfg(not(feature = "session-slot"))]
#[derive(Debug, Default)]
pub struct OwnPlaces {
    /// The bytes of each place.
    bytes: usize,
    /// The most places taken.
    count: usize,
    /// The places taken and not let go of: held by a publish, or spare.
    taken: usize,
    /// The places whose publishes were sent.
    spare: Vec<Vec<u8>>,
}

#[cfg(not(feature = "session-slot"))]
impl OwnPlaces {
    /// At most `count` places of `bytes` each, none taken.
    pub const fn sized(bytes: usize, count: usize) -> Self {
        Self {
            bytes,
            count,
            taken: 0,
            spare: Vec::new(),
        }
    }
}

#[cfg(not(feature = "session-slot"))]
impl LegStorage for OnUse {
    type Places = OwnPlaces;
    type Place = Vec<u8>;

    /// A spare place, or one taken now while fewer than its count are; a place the heap has no
    /// room for is none.
    fn claim(places: &mut OwnPlaces) -> Option<Vec<u8>> {
        if let Some(place) = places.spare.pop() {
            return Some(place);
        }
        if places.taken >= places.count {
            return None;
        }
        let place = crate::link_storage::zeroed_bytes(places.bytes)?;
        places.taken = places.taken.saturating_add(1);
        Some(place)
    }

    /// Kept for the next publish; let go of, and no longer counted, where the heap has no room to
    /// list it.
    fn give_back(places: &mut OwnPlaces, place: Vec<u8>) {
        if places.spare.try_reserve(1).is_ok() {
            places.spare.push(place);
        } else {
            places.taken = places.taken.saturating_sub(1);
        }
    }

    fn bytes(place: &Vec<u8>) -> &[u8] {
        place
    }

    fn bytes_mut(place: &mut Vec<u8>) -> &mut [u8] {
        place
    }
}

/// The publishes a session keeps for its other faces, in the order they were kept: a place for
/// each, and a row for each, as many rows as places, both of the storage `P` ([`LegStorage`]). A
/// session that keeps none has neither ([`Default`]).
pub struct HandedLegs<const WORDS: usize, P: LegStorage = Lent> {
    places: P::Places,
    legs: BoundedVec<HandedLeg<WORDS, P>, { usize::MAX }, P>,
}

impl<const WORDS: usize, P: LegStorage> Default for HandedLegs<WORDS, P> {
    fn default() -> Self {
        Self {
            places: P::Places::default(),
            legs: BoundedVec::default(),
        }
    }
}

// SAFETY: the table's places and rows lie in memory the session reserved, used by nothing but this
// table, and its holder reaches the table only under one lock: a place is claimed and given back,
// and a row pushed and taken, by one thread at a time. A leg taken out stays with the thread that
// took it and is given back under the same lock (`HandedLegs::give_back`).
unsafe impl<const WORDS: usize> Send for HandedLegs<WORDS, Lent> {}

// SAFETY: the table's places and rows are allocations of its own, reached by nothing but this
// table, and its holder reaches the table only under one lock, as the lent form's; a leg keeps no
// borrow, its encoding and attachment copied into the leg (`HandedLegs::keep`).
#[cfg(not(feature = "session-slot"))]
unsafe impl<const WORDS: usize> Send for HandedLegs<WORDS, OnUse> {}

impl<const WORDS: usize> HandedLegs<WORDS, Lent> {
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
}

#[cfg(not(feature = "session-slot"))]
impl<const WORDS: usize> HandedLegs<WORDS, OnUse> {
    /// At most `legs` publishes, each in a place of `place_bytes`: the rows taken at the first
    /// publish kept, all of them at once, and each place as it is first needed.
    pub const fn counted(place_bytes: usize, legs: usize) -> Self {
        Self {
            places: OwnPlaces::sized(place_bytes, legs),
            legs: BoundedVec::counted(legs),
        }
    }
}

impl<const WORDS: usize, P: LegStorage> HandedLegs<WORDS, P> {
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
    /// `false`, keeping nothing, when no place is free or none can be taken, no row can be, the
    /// publish is longer than a place, or its encoding's schema is longer than a kept encoding
    /// holds. A place claimed for a publish not kept is given back.
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
        let Some(mut bytes) = P::claim(&mut self.places) else {
            return false;
        };
        let key = keyexpr.as_bytes();
        if !write_parts(
            P::bytes_mut(&mut bytes),
            [key, payload, attachment.unwrap_or_default()],
        ) {
            P::give_back(&mut self.places, bytes);
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
        match self.legs.push(leg) {
            Ok(()) => true,
            Err(CapacityFull(leg)) => {
                P::give_back(&mut self.places, leg.bytes);
                false
            }
        }
    }

    /// The first publish kept, taken out to be sent. Its taker gives it back under the same lock it
    /// took it under ([`Self::give_back`]), so that its place is free for the next.
    pub fn take_first(&mut self) -> Option<HandedLeg<WORDS, P>> {
        if self.legs.is_empty() {
            None
        } else {
            Some(self.legs.remove(0))
        }
    }

    /// Give back `leg`'s place: what a taker does once it has sent it.
    pub fn give_back(&mut self, leg: HandedLeg<WORDS, P>) {
        P::give_back(&mut self.places, leg.bytes);
    }

    /// Give back every place: what the session does before it lets go of the memory they lie in.
    pub fn clear(&mut self) {
        while let Some(leg) = self.legs.pop() {
            P::give_back(&mut self.places, leg.bytes);
        }
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
        reads_back_whole(table(&mut arena, 2, 32));
    }

    /// The same where the table takes its memory on use: its rows and its places its own, two of
    /// each, places of 32 bytes. Turned red by a place given back that the next publish does not
    /// find, or a place taken past the count.
    #[cfg(not(feature = "session-slot"))]
    #[test]
    fn a_publish_kept_in_its_own_place_reads_back_whole_and_its_place_comes_back() {
        reads_back_whole(HandedLegs::<WORDS, OnUse>::counted(32, 2));
    }

    /// Two publishes kept in `handed`, a table of two places of 32 bytes, read back whole and in
    /// order, a third and one longer than a place refused, and a place given back kept into.
    fn reads_back_whole<P: LegStorage>(mut handed: HandedLegs<WORDS, P>) {
        let mut dropped = FaceSlots::<WORDS>::none(3);
        dropped.insert(1);
        let attached = *b"att";
        // Set apart from `with_attachment`, which a build without `pubsub-attachment` has not: the
        // table keeps what the options carry whichever setter put it there.
        let mut options = PublishOptions::put();
        options.attachment = Some(&attached);
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

    /// A table that takes its memory on use takes nothing when it is made, its rows at its first
    /// publish, a place for each publish that finds every place taken before held and none past its
    /// count, and keeps a place given back for the next. Turned red by rows taken when the table is
    /// made, a place taken past the count, or a place given back let go of.
    #[cfg(not(feature = "session-slot"))]
    #[test]
    fn an_own_table_takes_its_rows_at_its_first_publish_and_no_place_past_its_count() {
        let mut handed = HandedLegs::<WORDS, OnUse>::counted(32, 2);
        assert!(!handed.legs.holds_rows(), "a table made takes no row");
        assert_eq!(handed.places.taken, 0, "nor any place");
        assert!(handed.keep("demo/a", b"one", &PublishOptions::put(), FaceSlots::none(0)));
        assert!(handed.legs.holds_rows(), "the first publish takes the rows");
        assert_eq!(handed.places.taken, 1, "and one place");
        assert!(handed.keep("demo/b", b"two", &PublishOptions::put(), FaceSlots::none(0)));
        assert!(
            !handed.keep(
                "demo/c",
                b"three",
                &PublishOptions::put(),
                FaceSlots::none(0)
            ),
            "a third publish finds no place"
        );
        assert_eq!(handed.places.taken, 2, "no place past the count");
        let first = handed.take_first().expect("the first kept");
        handed.give_back(first);
        assert_eq!(handed.places.spare.len(), 1, "a place given back is kept");
        assert!(handed.keep(
            "demo/c",
            b"three",
            &PublishOptions::put(),
            FaceSlots::none(0)
        ));
        assert_eq!(
            (handed.places.taken, handed.places.spare.len()),
            (2, 0),
            "the place given back is the one kept into"
        );
        handed.clear();
        assert_eq!(
            (handed.places.taken, handed.places.spare.len()),
            (2, 2),
            "clearing gives every place back"
        );
        assert!(handed.is_empty());
    }

    /// A table sized to nothing keeps nothing, and a place the heap has no room for is a publish not
    /// kept, which takes no row: the refusal is a value. Turned red by a place made by a path that
    /// ends the process when the heap refuses it, or rows taken before the place they would hold.
    #[cfg(not(feature = "session-slot"))]
    #[test]
    fn a_place_the_heap_refuses_keeps_nothing_and_takes_no_row() {
        let mut none = HandedLegs::<WORDS, OnUse>::default();
        assert!(!none.keep("demo/a", b"x", &PublishOptions::put(), FaceSlots::none(0)));
        assert!(!none.legs.holds_rows() && none.places.taken == 0);
        let mut refused = HandedLegs::<WORDS, OnUse>::counted(usize::MAX, 1);
        assert!(
            !refused.keep("demo/a", b"x", &PublishOptions::put(), FaceSlots::none(0)),
            "a place the heap has no room for keeps nothing"
        );
        assert!(!refused.legs.holds_rows(), "and takes no row");
        assert_eq!(refused.places.taken, 0);
        assert!(refused.is_empty());
    }
}
