// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The place of an object a program holds through this ABI and no session holds for it: a session,
//! a publisher, a subscriber, a queryable, a liveliness token, an owned sample, reply or query, a
//! payload, a config, and a hello the program keeps.
//!
//! Each such object is placed with [`Slot::take`] and [`Slot::fill`] (or [`Slot::fill_in_place`]),
//! and let go with [`release`], or held by value as a [`Placed`]; a session of the cooperative
//! engine is placed in its own arena instead (`crate::session_place`). In a library without the
//! tokio engine, and in one that has the pools' doors (`object-pool`), a slot comes from the
//! process pool of the object's kind (`crate::process_pool`), the program's or, when it reserved
//! none, the build's, which the first object reserves; a pool with no room refuses the object, and
//! nothing falls back to the heap. The call that wanted it answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY`
//! and has made, declared or opened nothing, because each caller takes its slot before it does
//! either. A library of the tokio engine without the doors places each object on the heap, as the
//! engine's sessions allocate theirs.
//!
//! An object let go is given back to where it lies: its pool, or the heap for one a constructor
//! still boxes. What decides is where the object lies, never which build placed it.

use alloc::sync::Arc;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use crate::prelude::*;

/// Which object a place is for. With the pools reserved each kind has a pool of its own, so the
/// count stated for one kind is never spent by another of the same size; a kind a build places
/// nowhere is not a variant of it, and each keeps its number in every build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    // The cooperative engine's session lies in its own arena (`crate::session_place`); its pool
    // is the program's to reserve where the doors are.
    #[cfg(any(feature = "engine-tokio", feature = "object-pool"))]
    Session = 0,
    Publisher = 1,
    Subscriber = 2,
    #[cfg(feature = "queryable")]
    Queryable = 3,
    #[cfg(feature = "liveliness")]
    LivelinessToken = 4,
    #[cfg(feature = "liveliness")]
    LivelinessSubscriber = 5,
    Sample = 6,
    #[cfg(feature = "query")]
    Reply = 7,
    #[cfg(feature = "queryable")]
    Query = 8,
    // A payload takes a slot only where there are pools to take it from; without them it is
    // boxed in the allocation its thread kept for it (`crate::bytes`).
    #[cfg(wz_process_pools)]
    Bytes = 9,
    Config = 10,
    // Without the pools a kept hello is the heap's copy (`crate::scout`).
    #[cfg(all(wz_process_pools, any(feature = "scout", feature = "scout-mcu")))]
    Hello = 11,
    #[cfg(feature = "query")]
    Querier = 12,
    /// A key expression the program holds declared (`z_declare_keyexpr`).
    Keyexpr = 13,
}

/// The place of one `T`, taken and not yet filled. Dropped unfilled, it is given back.
pub(crate) struct Slot<T> {
    place: NonNull<MaybeUninit<T>>,
    /// The session whose arena lent the place, for an entity's object on the cooperative engine
    /// ([`Self::take_entity`]); none for a place of the process pools or the heap.
    lender: Option<Lender>,
}

impl<T> Slot<T> {
    /// A place for one `T` of `kind`, or `None` when the pool of that kind is full.
    #[cfg(wz_process_pools)]
    pub(crate) fn take(kind: Kind) -> Option<Self> {
        crate::process_pool::take::<T>(kind).map(|place| Self {
            place: place.cast(),
            lender: None,
        })
    }

    /// A place for one `T`: without the pools every place is the heap's, whatever its kind.
    #[cfg(not(wz_process_pools))]
    pub(crate) fn take(kind: Kind) -> Option<Self> {
        let _ = kind;
        Some(Self {
            place: NonNull::from(Box::leak(Box::new(MaybeUninit::<T>::uninit()))),
            lender: None,
        })
    }

    /// A place for the object of one of `engine`'s entities of `kind`, let go with
    /// [`release_entity`]. On the cooperative engine it is a place of the session's own arena,
    /// one of those its open laid out for the kind ([`held_places`]), as many as the limit the
    /// session opened under admits, so one session's entities never take another's: `None`
    /// when every one is held, or the kind or `T` is not one the open laid places out for. On the
    /// tokio engine it is a place of the kind's pool ([`Self::take`]).
    #[cfg(not(feature = "engine-tokio"))]
    pub(crate) fn take_entity(engine: &Arc<crate::session::Engine>, kind: Kind) -> Option<Self> {
        let (entity, laid) = entity_place(kind)?;
        let needed = InSession::<T>::LAYOUT;
        if needed.size() > laid.size() || needed.align() > laid.align() {
            return None;
        }
        let place = engine.place_lender()?.claim_place(entity)?;
        Some(Self {
            place: place.as_ptr().cast(),
            lender: Some(Lender {
                place,
                engine: Arc::clone(engine),
            }),
        })
    }

    /// A place for the object of one of `engine`'s entities of `kind`: on the tokio engine, a
    /// place of the kind's pool ([`Self::take`]).
    #[cfg(feature = "engine-tokio")]
    pub(crate) fn take_entity(engine: &Arc<crate::session::Engine>, kind: Kind) -> Option<Self> {
        let _ = engine;
        Self::take(kind)
    }

    /// The place and the session that lent it, the slot given up.
    fn into_parts(self) -> (NonNull<MaybeUninit<T>>, Option<Lender>) {
        let mut this = core::mem::ManuallyDrop::new(self);
        (this.place, this.lender.take())
    }

    /// Put `value` in the place and hand back where it lies: the handle an owned struct holds,
    /// which [`release`] lets go, or [`release_entity`] for one [`Self::take_entity`] placed.
    pub(crate) fn fill(self, value: T) -> *mut T {
        let (place, lender) = self.into_parts();
        // SAFETY: the place is a live allocation sized and aligned for `T`, which nothing else
        // holds, and it is not filled yet.
        unsafe { place.as_ptr().write(MaybeUninit::new(value)) };
        if let Some(lender) = lender {
            // SAFETY: the place was lent for an `InSession<T>` and now holds its value.
            unsafe { lender.attach(place) };
        }
        place.as_ptr().cast::<T>()
    }

    /// Write the object where the slot lies with `write`, for an object too large to be made on
    /// the stack and moved into its place, and hand back where it lies, as [`Self::fill`] does.
    /// Should `write` unwind, the place is given back and nothing in it is dropped.
    ///
    /// # Safety
    /// `write` leaves a valid `T` at the place it is handed, which is sized and aligned for one and
    /// holds none.
    pub(crate) unsafe fn fill_in_place(self, write: impl FnOnce(*mut T)) -> *mut T {
        let at = self.place.as_ptr().cast::<T>();
        write(at);
        let (place, lender) = self.into_parts();
        if let Some(lender) = lender {
            // SAFETY: the place was lent for an `InSession<T>` and now holds its value.
            unsafe { lender.attach(place) };
        }
        at
    }
}

impl<T> Drop for Slot<T> {
    fn drop(&mut self) {
        match self.lender.take() {
            Some(lender) => lender.give_back(),
            // SAFETY: an unfilled place this slot took, given back once.
            None => unsafe { give_back(self.place) },
        }
    }
}

/// The session that lent a place of its arena for an entity's object, and the place as it lent
/// it: kept beside the object, so the object's release gives the place back to the session that
/// lent it, and holding the session so its arena stands while the object lies in it.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) struct Lender {
    place: wz_capi_port::EntityPlace,
    engine: Arc<crate::session::Engine>,
}

/// No session lends a place on the tokio engine: its entities' objects lie in the pools.
#[cfg(feature = "engine-tokio")]
pub(crate) enum Lender {}

#[cfg(not(feature = "engine-tokio"))]
impl Lender {
    /// Keep this lender beside the value at `place`.
    ///
    /// # Safety
    /// `place` is the place this lender lent, laid out for an `InSession<T>`, and holds its
    /// value.
    unsafe fn attach<T>(self, place: NonNull<MaybeUninit<T>>) {
        let at = place.as_ptr().cast::<InSession<T>>();
        // SAFETY: the caller's: the place holds an `InSession<T>`, whose lender is not written.
        unsafe { core::ptr::addr_of_mut!((*at).lender).write(core::mem::ManuallyDrop::new(self)) };
    }

    /// Give the place back to the session that lent it, whatever it held let go of first.
    fn give_back(self) {
        let Self { place, engine } = self;
        // The engine that lent the place lends places, so it takes it back.
        let given = engine
            .place_lender()
            .map(|lender| lender.give_back_place(place));
        debug_assert!(
            matches!(given, Some(Ok(()))),
            "a place goes back to the session that lent it"
        );
    }
}

#[cfg(feature = "engine-tokio")]
impl Lender {
    unsafe fn attach<T>(self, _place: NonNull<MaybeUninit<T>>) {
        match self {}
    }

    fn give_back(self) {
        match self {}
    }
}

/// An entity's object in a place of its session's arena, and the session that lent the place: the
/// object first, so the handle of the object is the place itself.
#[cfg(not(feature = "engine-tokio"))]
#[repr(C)]
struct InSession<T> {
    value: MaybeUninit<T>,
    lender: core::mem::ManuallyDrop<Lender>,
}

#[cfg(not(feature = "engine-tokio"))]
impl<T> InSession<T> {
    /// The layout a place of the session's arena is laid out by for a `T`.
    const LAYOUT: core::alloc::Layout = core::alloc::Layout::new::<Self>();
}

/// The entity kind of the engine's arena an object of `kind` is placed as, and the layout of its
/// place: the one table both the open's places ([`held_places`]) and each place taken
/// ([`Slot::take_entity`]) read. `None` for a kind that is no entity.
#[cfg(not(feature = "engine-tokio"))]
fn entity_place(kind: Kind) -> Option<(wz_capi_port::EntityKind, core::alloc::Layout)> {
    use wz_capi_port::EntityKind;
    match kind {
        Kind::Publisher => Some((
            EntityKind::Publisher,
            InSession::<crate::pubsub::PublisherState>::LAYOUT,
        )),
        Kind::Subscriber => Some((
            EntityKind::Subscriber,
            InSession::<crate::pubsub::SubscriberState>::LAYOUT,
        )),
        #[cfg(feature = "queryable")]
        Kind::Queryable => Some((
            EntityKind::Queryable,
            InSession::<crate::query::QueryableState>::LAYOUT,
        )),
        #[cfg(feature = "liveliness")]
        Kind::LivelinessToken => Some((
            EntityKind::Token,
            InSession::<crate::liveliness::TokenState>::LAYOUT,
        )),
        #[cfg(feature = "liveliness")]
        Kind::LivelinessSubscriber => Some((
            EntityKind::LivelinessSubscriber,
            InSession::<crate::pubsub::SubscriberState>::LAYOUT,
        )),
        #[cfg(feature = "query")]
        Kind::Querier => Some((
            EntityKind::Querier,
            InSession::<crate::querier::QuerierState>::LAYOUT,
        )),
        _ => None,
    }
}

#[cfg(all(not(feature = "engine-tokio"), feature = "queryable"))]
const QUERYABLE: Option<Kind> = Some(Kind::Queryable);
#[cfg(all(not(feature = "engine-tokio"), not(feature = "queryable")))]
const QUERYABLE: Option<Kind> = None;
#[cfg(all(not(feature = "engine-tokio"), feature = "liveliness"))]
const LIVELINESS: [Option<Kind>; 2] = [
    Some(Kind::LivelinessToken),
    Some(Kind::LivelinessSubscriber),
];
#[cfg(all(not(feature = "engine-tokio"), not(feature = "liveliness")))]
const LIVELINESS: [Option<Kind>; 2] = [None, None];
#[cfg(all(not(feature = "engine-tokio"), feature = "query"))]
const QUERIER: Option<Kind> = Some(Kind::Querier);
#[cfg(all(not(feature = "engine-tokio"), not(feature = "query")))]
const QUERIER: Option<Kind> = None;

/// Each kind of entity the build has, as the arena knows it, and the layout of its place: the one
/// list the open's places ([`held_places`]) are laid out from.
#[cfg(not(feature = "engine-tokio"))]
fn entity_places() -> impl Iterator<Item = (wz_capi_port::EntityKind, core::alloc::Layout)> {
    let [token, liveliness_subscriber] = LIVELINESS;
    [
        Some(Kind::Publisher),
        Some(Kind::Subscriber),
        QUERYABLE,
        token,
        liveliness_subscriber,
        QUERIER,
    ]
    .into_iter()
    .flatten()
    .filter_map(entity_place)
}

/// The places a session of the cooperative engine holds in its arena for what this ABI keeps of
/// it: its handle's, of `handle`, and one for each entity of each kind the build has, as many as
/// the session's limit of the kind admits, so an entity's object takes no memory of the process's
/// and no other session's.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn held_places(handle: core::alloc::Layout) -> wz_capi_coop::arena::HeldPlaces {
    entity_places().fold(
        wz_capi_coop::arena::HeldPlaces::handle(handle),
        |held, (entity, layout)| held.with_entity(entity, layout),
    )
}

/// Drop the object at `object` and give its place back.
///
/// # Safety
/// `object` is a live handle [`Slot::fill`], [`Slot::fill_in_place`] or `Box::into_raw` made for
/// a `T`, and is not used again.
pub(crate) unsafe fn release<T>(object: *mut T) {
    core::ptr::drop_in_place(object);
    give_back(NonNull::new_unchecked(object.cast::<MaybeUninit<T>>()));
}

/// Drop the object of an entity at `object` and give its place back to where it lies: the
/// session's arena that lent it on the cooperative engine, which the place says, and the kind's
/// pool on the tokio engine.
///
/// # Safety
/// `object` is a live handle [`Slot::take_entity`] placed and filled for a `T`, and is not used
/// again.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) unsafe fn release_entity<T>(object: *mut T) {
    let at = object.cast::<InSession<T>>();
    // SAFETY: the caller's: the object lies in an `InSession<T>` whose lender was written when it
    // was filled, and is read out once, here.
    let lender = core::mem::ManuallyDrop::into_inner(unsafe {
        core::ptr::read(core::ptr::addr_of!((*at).lender))
    });
    // SAFETY: the caller's: a live object, dropped once.
    unsafe { core::ptr::drop_in_place(object) };
    lender.give_back();
}

/// Drop the object of an entity at `object` and give its place back to the kind's pool.
///
/// # Safety
/// As [`release`].
#[cfg(feature = "engine-tokio")]
pub(crate) unsafe fn release_entity<T>(object: *mut T) {
    // SAFETY: the caller's.
    unsafe { release(object) }
}

/// Move the object at `object` out and give its place back.
///
/// # Safety
/// As [`release`].
#[cfg(wz_process_pools)]
pub(crate) unsafe fn reclaim<T>(object: *mut T) -> T {
    let value = object.read();
    give_back(NonNull::new_unchecked(object.cast::<MaybeUninit<T>>()));
    value
}

/// An object of a slot held by value, as a `Box` holds one: it reads as the object, and dropped it
/// lets the object go ([`release`]).
pub(crate) struct Placed<T> {
    object: NonNull<T>,
}

impl<T> Placed<T> {
    /// Hold the object at `object`, or `None` for a null one.
    ///
    /// # Safety
    /// `object` is null, or a live handle [`Slot::fill`], [`Slot::fill_in_place`] or
    /// `Box::into_raw` made for a `T` that nothing else uses after.
    pub(crate) unsafe fn from_raw(object: *mut T) -> Option<Self> {
        NonNull::new(object).map(|object| Self { object })
    }
}

impl<T> core::ops::Deref for Placed<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the object is live and this holds it alone (`Self::from_raw`).
        unsafe { self.object.as_ref() }
    }
}

impl<T> Drop for Placed<T> {
    fn drop(&mut self) {
        // SAFETY: the object is live and let go once, here.
        unsafe { release(self.object.as_ptr()) }
    }
}

/// Give back a place whose value is gone: to its pool when it lies in one, else to the heap.
///
/// # Safety
/// `place` was taken for a `T` (by a [`Slot`] or a `Box`), holds no live value, and is given
/// back once.
unsafe fn give_back<T>(place: NonNull<MaybeUninit<T>>) {
    #[cfg(wz_process_pools)]
    if crate::process_pool::give_back(place.cast::<u8>()) {
        return;
    }
    drop(Box::from_raw(place.as_ptr()));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts its drops, to tell a value dropped once from one dropped twice or never.
    struct Counted<'a>(&'a core::cell::Cell<usize>);

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    /// A slot is there for a sample (the heap's, or one of the build's pools the first object
    /// reserves), a filled one holds its value, and a release drops the value once.
    #[test]
    fn a_filled_slot_holds_its_value_and_a_release_drops_it_once() {
        let drops = core::cell::Cell::new(0);
        let object = Slot::take(Kind::Sample)
            .expect("a sample has a place")
            .fill(Counted(&drops));
        assert_eq!(drops.get(), 0, "filling drops nothing");
        // SAFETY: `object` was filled just above and is released once.
        unsafe { release(object) };
        assert_eq!(drops.get(), 1);
    }

    /// With the pools, a slot lies in the pool of its kind, and a release gives it back to it:
    /// nothing is the heap's.
    #[cfg(wz_process_pools)]
    #[test]
    fn a_slot_lies_in_the_pools_and_goes_back_to_them() {
        let drops = core::cell::Cell::new(0);
        let object = Slot::take(Kind::Sample)
            .expect("the build's pools hold samples")
            .fill(Counted(&drops));
        let place = NonNull::new(object.cast::<u8>()).expect("a place");
        assert!(
            crate::process_pool::lies_in_pools(place),
            "the place is a pool's, not the heap's"
        );
        // SAFETY: `object` was filled just above and is released once.
        unsafe { release(object) };
        assert_eq!(drops.get(), 1, "the value is dropped once");
    }

    /// An object written in place is read back where it was written, and a placed hold of it reads
    /// it and lets it go once when dropped.
    #[test]
    fn an_object_written_in_place_is_held_and_let_go_once() {
        let drops = core::cell::Cell::new(0);
        // SAFETY: the closure writes a whole `Counted` at the place it is handed.
        let object = unsafe {
            Slot::<Counted<'_>>::take(Kind::Sample)
                .expect("a sample has a place")
                .fill_in_place(|at| at.write(Counted(&drops)))
        };
        // SAFETY: `object` was filled just above, and only the hold uses it after.
        let held = unsafe { Placed::from_raw(object) }.expect("a live object");
        assert!(
            core::ptr::eq(held.0, &drops),
            "the hold reads the object written"
        );
        assert_eq!(drops.get(), 0);
        drop(held);
        assert_eq!(drops.get(), 1, "the hold lets it go once");
        // SAFETY: a null handle holds nothing.
        assert!(unsafe { Placed::<Counted<'_>>::from_raw(core::ptr::null_mut()) }.is_none());
    }

    /// An object a `Box` made is released as one a slot made: where it lies decides.
    #[test]
    fn an_object_a_box_made_is_released_like_one_a_slot_made() {
        let drops = core::cell::Cell::new(0);
        let object = Box::into_raw(Box::new(Counted(&drops)));
        // SAFETY: a live `Box::into_raw` handle, released once.
        unsafe { release(object) };
        assert_eq!(drops.get(), 1);
    }
    /// A session lends the objects of its entities places of its own arena, one for each its limit
    /// admits: every one is lent, the one past them is refused, another session's are its own and
    /// untouched by it, a released object's place and an unfilled slot's go back to the session
    /// that lent them, and a kind that is no entity is lent none. Turned red by entities placed in
    /// a pool the sessions share, which a session at its limit spends for the other.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_session_lends_its_entities_places_and_spends_none_of_anothers() {
        use crate::session::{
            engine_of, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };
        use wz_capi_port::{EntityKind, PlaceLender};

        let open = || {
            let session = listening_on_loopback();
            // SAFETY: the session is live and owned by this frame.
            let handle = unsafe { session_handle(z_session_loan(&session)) };
            let engine = engine_of(handle.expect("an open session has its handle"));
            (session, engine)
        };
        let (mut one, one_engine) = open();
        let (mut other, other_engine) = open();
        let (lent, places) = one_engine
            .place_lender()
            .expect("the engine lends places")
            .place_counts(EntityKind::Publisher);
        assert_eq!(lent, 0);
        assert!(places > 0, "the session's limit admits publishers");

        let drops = core::cell::Cell::new(0);
        let held: Vec<*mut Counted<'_>> = (0..places)
            .map(|_| {
                Slot::take_entity(&one_engine, Kind::Publisher)
                    .expect("a place for each the limit admits")
                    .fill(Counted(&drops))
            })
            .collect();
        assert!(
            Slot::<Counted<'_>>::take_entity(&one_engine, Kind::Publisher).is_none(),
            "none past the session's limit"
        );
        let theirs = Slot::take_entity(&other_engine, Kind::Publisher)
            .expect("another session's places are its own")
            .fill(Counted(&drops));
        assert_eq!(
            other_engine
                .place_lender()
                .expect("the engine lends places")
                .place_counts(EntityKind::Publisher),
            (1, places)
        );
        for object in held {
            // SAFETY: each object was filled above and is released once.
            unsafe { release_entity(object) };
        }
        // SAFETY: as above.
        unsafe { release_entity(theirs) };
        assert_eq!(drops.get(), places + 1, "each object is dropped once");
        assert_eq!(
            one_engine
                .place_lender()
                .expect("the engine lends places")
                .place_counts(EntityKind::Publisher),
            (0, places)
        );
        assert_eq!(
            other_engine
                .place_lender()
                .expect("the engine lends places")
                .place_counts(EntityKind::Publisher),
            (0, places)
        );

        let unfilled =
            Slot::<u64>::take_entity(&one_engine, Kind::Publisher).expect("a place given back");
        assert_eq!(
            one_engine
                .place_lender()
                .expect("the engine lends places")
                .place_counts(EntityKind::Publisher),
            (1, places)
        );
        drop(unfilled);
        assert_eq!(
            one_engine
                .place_lender()
                .expect("the engine lends places")
                .place_counts(EntityKind::Publisher),
            (0, places)
        );
        assert!(
            Slot::<u64>::take_entity(&one_engine, Kind::Sample).is_none(),
            "a kind that is no entity has no place"
        );

        drop((one_engine, other_engine));
        // SAFETY: each session is live and owned here, and given up by this call.
        unsafe {
            z_session_drop(z_session_move(&mut one));
            z_session_drop(z_session_move(&mut other));
        }
    }

    /// What one entity of each kind takes of its session's arena for the ABI's object, printed for
    /// reading beside the engine's own rows of the kind: the place, the object and the session that
    /// lent it, and the flag that says it is lent. Run with `cargo test -p wz-capi-pico --lib
    /// print_the_place_bytes_of_each_entity_kind -- --ignored --nocapture` under the features of
    /// the build to read.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    #[ignore = "a measurement printed for reading, not a check"]
    fn print_the_place_bytes_of_each_entity_kind() {
        let flag = wz_session_core::byte_cells::LentByteCells::FLAG_BYTES;
        for (kind, layout) in entity_places() {
            std::println!(
                "place-row: {kind:?} place_bytes={} align={} flag_bytes={flag} per_entity={}",
                layout.size(),
                layout.align(),
                layout.size() + flag
            );
        }
    }
}
