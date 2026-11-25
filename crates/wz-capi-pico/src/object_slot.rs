// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The place of an object a program holds through this ABI and no session holds for it: a session,
//! a publisher, a subscriber, a queryable, a liveliness token, an owned sample, reply or query, a
//! payload, an encoding, a config, and a hello the program keeps.
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
    // 9 was an owned payload's, which its value holds now (`crate::bytes::ByteBuf`).
    Config = 10,
    // Without the pools a kept hello is the heap's copy (`crate::scout`).
    #[cfg(all(wz_process_pools, any(feature = "scout", feature = "scout-mcu")))]
    Hello = 11,
    #[cfg(feature = "query")]
    Querier = 12,
    /// A key expression the program holds declared (`z_declare_keyexpr`).
    Keyexpr = 13,
    /// An encoding the program holds (`z_owned_encoding_t`), its schema in the slot.
    Encoding = 14,
    /// A get the program issued, held until its last leg ends (`crate::get::GetPlace`).
    #[cfg(feature = "query")]
    Get = 15,
    /// A liveliness get the program issued, held as a get is.
    #[cfg(feature = "liveliness-get")]
    LivelinessGet = 16,
    /// A matching listener of a publisher or a querier, held while its write filter can reach it
    /// (`crate::matching::MatchingPlace`).
    MatchingListener = 17,
    /// A watch of what the peers declare, held until its handle and the engine let go of it
    /// (`crate::decl_watch::WatchPlace`).
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    DeclWatch = 18,
    /// A transport events listener, held while its session's hub can reach it
    /// (`crate::connectivity::TransportPlace`).
    #[cfg(feature = "connectivity")]
    TransportEventsListener = 19,
    /// An advanced publisher (`crate::advanced::AdvPubState`). Its number follows those the
    /// listeners and the watches take.
    #[cfg(feature = "advanced")]
    AdvancedPublisher = 20,
    /// An advanced subscriber, owned or background (`crate::advanced::AdvSubPlace`).
    #[cfg(feature = "advanced")]
    AdvancedSubscriber = 21,
    /// A link events listener, held while its session's hub can reach it
    /// (`crate::connectivity::LinkPlace`).
    #[cfg(feature = "connectivity")]
    LinkEventsListener = 22,
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
    pub(crate) fn take_entity(engine: &crate::session::EngineHold, kind: Kind) -> Option<Self> {
        let lender = Lender::lend(engine, kind, InSession::<T>::LAYOUT)?;
        Some(Self {
            place: lender.place.as_ptr().cast(),
            lender: Some(lender),
        })
    }

    /// A place for the object of one of `engine`'s entities of `kind`: on the tokio engine, a
    /// place of the kind's pool ([`Self::take`]).
    #[cfg(feature = "engine-tokio")]
    pub(crate) fn take_entity(engine: &crate::session::EngineHold, kind: Kind) -> Option<Self> {
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

    /// [`Self::fill_in_place`] with a `write` that can be refused: refused, the place is given
    /// back with nothing in it dropped, and the refusal handed back.
    ///
    /// # Safety
    /// `write` leaves a valid `T` at the place it is handed when it answers `Ok`, and nothing
    /// there to drop when it answers `Err`; the place is sized and aligned for one and holds none.
    pub(crate) unsafe fn try_fill_in_place<E>(
        self,
        write: impl FnOnce(*mut T) -> Result<(), E>,
    ) -> Result<*mut T, E> {
        write(self.place.as_ptr().cast::<T>())?;
        // SAFETY: the caller's: the place holds the `T` written above, which writing nothing keeps.
        Ok(unsafe { self.fill_in_place(|_| {}) })
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
    engine: crate::session::EngineHold,
}

/// No session lends a place on the tokio engine: its entities' objects lie in the pools.
#[cfg(feature = "engine-tokio")]
pub(crate) enum Lender {}

#[cfg(not(feature = "engine-tokio"))]
impl Lender {
    /// A place of `engine`'s arena for an entity of `kind` whose object, with its lender, is laid
    /// out by `needed`: `None` when every place of the kind is held, or the kind or the layout is
    /// not one the open laid places out for. One body for every kind of entity, out of the line of
    /// each declare, so the layout is a value rather than each object's own copy of the take.
    #[inline(never)]
    fn lend(
        engine: &crate::session::EngineHold,
        kind: Kind,
        needed: core::alloc::Layout,
    ) -> Option<Self> {
        let (entity, laid) = entity_place(kind)?;
        if needed.size() > laid.size() || needed.align() > laid.align() {
            return None;
        }
        // The cooperative engine lends places itself, reached as its own type.
        let place = wz_capi_port::PlaceLender::claim_place(
            crate::session::EngineHold::as_ref(engine),
            entity,
        )?;
        Some(Self {
            place,
            engine: crate::session::EngineHold::clone(engine),
        })
    }

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

    /// Give the place back to the session that lent it, whatever it held let go of first. One
    /// body for every kind of entity, out of the line of each release.
    #[inline(never)]
    fn give_back(self) {
        let Self { place, engine } = self;
        // The engine that lent the place lends places, so it takes it back.
        let given = wz_capi_port::PlaceLender::give_back_place(
            crate::session::EngineHold::as_ref(&engine),
            place,
        );
        debug_assert!(
            given.is_ok(),
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
const fn entity_place(kind: Kind) -> Option<(wz_capi_port::EntityKind, core::alloc::Layout)> {
    use wz_capi_port::EntityKind;
    match kind {
        Kind::Publisher => Some((
            EntityKind::Publisher,
            InSession::<crate::pubsub::PublisherState>::LAYOUT,
        )),
        Kind::Subscriber => Some((
            EntityKind::Subscriber,
            InSession::<crate::pubsub::SubscriberPlace>::LAYOUT,
        )),
        #[cfg(feature = "queryable")]
        Kind::Queryable => Some((
            EntityKind::Queryable,
            InSession::<crate::query::QueryablePlace>::LAYOUT,
        )),
        #[cfg(feature = "liveliness")]
        Kind::LivelinessToken => Some((
            EntityKind::Token,
            InSession::<crate::liveliness::TokenState>::LAYOUT,
        )),
        #[cfg(feature = "liveliness")]
        Kind::LivelinessSubscriber => Some((
            EntityKind::LivelinessSubscriber,
            InSession::<crate::pubsub::SubscriberPlace>::LAYOUT,
        )),
        #[cfg(feature = "query")]
        Kind::Querier => Some((
            EntityKind::Querier,
            InSession::<Answering<crate::querier::QuerierState>>::LAYOUT,
        )),
        #[cfg(feature = "query")]
        Kind::Get => Some((
            EntityKind::PendingGet,
            InSession::<crate::get::GetPlace>::LAYOUT,
        )),
        #[cfg(feature = "liveliness-get")]
        Kind::LivelinessGet => Some((
            EntityKind::PendingLivelinessGet,
            InSession::<crate::get::GetPlace>::LAYOUT,
        )),
        Kind::MatchingListener => Some((
            EntityKind::MatchingListener,
            InSession::<crate::matching::MatchingPlace>::LAYOUT,
        )),
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        Kind::DeclWatch => Some((
            EntityKind::DeclWatch,
            InSession::<crate::decl_watch::WatchPlace>::LAYOUT,
        )),
        #[cfg(feature = "connectivity")]
        Kind::TransportEventsListener => Some((
            EntityKind::TransportEventsListener,
            InSession::<crate::connectivity::TransportPlace>::LAYOUT,
        )),
        #[cfg(feature = "advanced")]
        Kind::AdvancedPublisher => Some((
            EntityKind::AdvancedPublisher,
            InSession::<crate::advanced::AdvPubState>::LAYOUT,
        )),
        #[cfg(feature = "advanced")]
        Kind::AdvancedSubscriber => Some((
            EntityKind::AdvancedSubscriber,
            InSession::<crate::advanced::AdvSubPlace>::LAYOUT,
        )),
        #[cfg(feature = "connectivity")]
        Kind::LinkEventsListener => Some((
            EntityKind::LinkEventsListener,
            InSession::<crate::connectivity::LinkPlace>::LAYOUT,
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
const QUERIER: [Option<Kind>; 2] = [Some(Kind::Querier), Some(Kind::Get)];
#[cfg(all(not(feature = "engine-tokio"), not(feature = "query")))]
const QUERIER: [Option<Kind>; 2] = [None, None];
#[cfg(all(not(feature = "engine-tokio"), feature = "liveliness-get"))]
const LIVELINESS_GET: Option<Kind> = Some(Kind::LivelinessGet);
#[cfg(all(not(feature = "engine-tokio"), not(feature = "liveliness-get")))]
const LIVELINESS_GET: Option<Kind> = None;
#[cfg(all(
    not(feature = "engine-tokio"),
    any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    )
))]
const DECL_WATCH: Option<Kind> = Some(Kind::DeclWatch);
#[cfg(all(
    not(feature = "engine-tokio"),
    not(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))
))]
const DECL_WATCH: Option<Kind> = None;
#[cfg(all(not(feature = "engine-tokio"), feature = "connectivity"))]
const CONNECTIVITY: [Option<Kind>; 2] = [
    Some(Kind::TransportEventsListener),
    Some(Kind::LinkEventsListener),
];
#[cfg(all(not(feature = "engine-tokio"), not(feature = "connectivity")))]
const CONNECTIVITY: [Option<Kind>; 2] = [None, None];
#[cfg(all(not(feature = "engine-tokio"), feature = "advanced"))]
const ADVANCED: [Option<Kind>; 2] = [
    Some(Kind::AdvancedPublisher),
    Some(Kind::AdvancedSubscriber),
];
#[cfg(all(not(feature = "engine-tokio"), not(feature = "advanced")))]
const ADVANCED: [Option<Kind>; 2] = [None, None];

/// Each kind of entity the build has, `None` for one it has not: the one list the open's places
/// ([`held_places`]) are laid out from.
#[cfg(not(feature = "engine-tokio"))]
const BUILT_KINDS: [Option<Kind>; wz_capi_port::ENTITY_KINDS] = {
    let [token, liveliness_subscriber] = LIVELINESS;
    let [querier, get] = QUERIER;
    let [advanced_publisher, advanced_subscriber] = ADVANCED;
    let [transport_events, link_events] = CONNECTIVITY;
    [
        Some(Kind::Publisher),
        Some(Kind::Subscriber),
        QUERYABLE,
        token,
        liveliness_subscriber,
        querier,
        get,
        LIVELINESS_GET,
        Some(Kind::MatchingListener),
        DECL_WATCH,
        transport_events,
        advanced_publisher,
        advanced_subscriber,
        link_events,
    ]
};

/// The places a session of the cooperative engine holds in its arena for what this ABI keeps of
/// it: its handle's, of `handle`, and one for each entity of each kind the build has, as many as
/// the session's limit of the kind admits, so an entity's object takes no memory of the process's
/// and no other session's. A `const fn`: every kind and layout is known when the library is built,
/// so the open reads its places as a constant and lays none of them out.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) const fn held_places(handle: core::alloc::Layout) -> wz_capi_coop::arena::HeldPlaces {
    let mut held = wz_capi_coop::arena::HeldPlaces::handle(handle);
    let mut kinds: &[Option<Kind>] = &BUILT_KINDS;
    while let [kind, rest @ ..] = kinds {
        let place = match *kind {
            Some(kind) => entity_place(kind),
            None => None,
        };
        if let Some((entity, layout)) = place {
            held = held.with_entity(entity, layout);
        }
        kinds = rest;
    }
    #[cfg(feature = "connectivity")]
    {
        held = crate::session_ext::held_lodgings(held);
    }
    held
}

/// An entity's object, the count of the program's closures it answers for (a querier's gets, a
/// queryable's or a subscriber's closure), and what those closures keep in the place past the
/// object (`K`: the C closure a queryable's or a subscriber's row calls), inline in the entity's
/// place. The handle of the
/// object is the place itself, the object first, so a handle read as a `T` reads the object. The
/// owner's release lets go of the object and leaves the place, with the count and what is kept in
/// it, to the last closure still held ([`retire_entity`]), so a closure let go of after its owner
/// (an undeclare made from inside its own callback) finds both standing, and no closure takes
/// memory of its own.
#[repr(C)]
pub(crate) struct Answering<T, K = ()> {
    value: core::mem::ManuallyDrop<T>,
    open: crate::ffi::OpenClosures,
    kept: core::mem::ManuallyDrop<K>,
}

impl<T, K> Answering<T, K> {
    /// `value`, keeping `kept` for its closures, with none counted yet.
    pub(crate) fn keeping(value: T, kept: K) -> Self {
        Self {
            value: core::mem::ManuallyDrop::new(value),
            open: crate::ffi::OpenClosures::default(),
            kept: core::mem::ManuallyDrop::new(kept),
        }
    }

    /// As [`Self::keeping`], the value and what is kept written by `write` and `write_kept` in
    /// the places where they stay: what a value holding a lock is made in, its lock made there
    /// ([`wz_capi_port::os::mutex_in`]).
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self`, aligned for it and holds none; `write` leaves a valid
    /// `T` and `write_kept` a valid `K` in the place each is handed.
    #[cfg(any(feature = "query", feature = "connectivity"))]
    pub(crate) unsafe fn write_at(
        at: *mut Self,
        write: impl FnOnce(NonNull<T>),
        write_kept: impl FnOnce(NonNull<K>),
    ) {
        // SAFETY: the caller's: each field is written once through a pointer to it, not null as
        // `at` is valid; a `ManuallyDrop` has the layout of what it holds.
        unsafe {
            write(NonNull::new_unchecked(
                core::ptr::addr_of_mut!((*at).value).cast::<T>(),
            ));
            core::ptr::addr_of_mut!((*at).open).write(crate::ffi::OpenClosures::default());
            write_kept(NonNull::new_unchecked(
                core::ptr::addr_of_mut!((*at).kept).cast::<K>(),
            ));
        }
    }
}

/// The count of the closures the entity whose object is at `object` answers for, which its owner
/// waits on before letting go of it ([`retire_entity`]).
///
/// # Safety
/// `object` is a live handle [`Slot::take_entity`] placed and filled for an [`Answering<T, K>`].
pub(crate) unsafe fn closures_of<'a, T, K>(object: *const T) -> &'a crate::ffi::OpenClosures {
    // SAFETY: the caller's: the count stands while the place does.
    unsafe { &(*object.cast::<Answering<T, K>>()).open }
}

/// Where the entity whose object is at `object` keeps what its closures read past the object.
///
/// # Safety
/// As [`closures_of`]; what is kept there is read and taken out only as the entity's closures
/// say.
pub(crate) unsafe fn kept_at<T, K>(object: *const T) -> *mut K {
    let at = object.cast::<Answering<T, K>>().cast_mut();
    // SAFETY: the caller's: the place holds an `Answering<T, K>`; a `ManuallyDrop<K>` is a `K`.
    unsafe { core::ptr::addr_of_mut!((*at).kept).cast::<K>() }
}

/// Count `closure` in the entity whose object is at `object`: the owner's release waits for its
/// `drop(context)`, and the entity's place stands until it has run.
///
/// # Safety
/// `object` is a live handle [`Slot::take_entity`] placed and filled for an [`Answering<T, K>`],
/// whose owner has not let go of it.
pub(crate) unsafe fn count_in_entity<T, K, C>(
    object: *const T,
    closure: &mut crate::ffi::CClosure<C>,
) {
    // SAFETY: the caller's.
    closure.count_in(unsafe { count_of::<T, K>(object) });
}

/// Hold the place of the entity whose object is at `object` open as a closure counted in it does:
/// for what reaches the place apart from its owner (a write filter's list of its listeners), so
/// the place stands until the hold is dropped, which gives it back if its owner and every closure
/// went first.
///
/// # Safety
/// As [`count_in_entity`].
pub(crate) unsafe fn hold_entity<T, K>(object: *const T) -> crate::ffi::HeldIn {
    // SAFETY: the caller's.
    unsafe { count_of::<T, K>(object) }.hold()
}

/// Keep the place of the entity whose object is at `object` for what lies in it past the object and
/// is reached apart from its owner: the place stands until the keep is dropped, which gives it back
/// if its owner and every closure went first, and the owner's wait does not wait for it
/// ([`crate::ffi::KeptIn`]).
///
/// # Safety
/// As [`count_in_entity`].
#[cfg(any(
    feature = "advanced",
    all(
        test,
        not(feature = "engine-tokio"),
        feature = "peer",
        feature = "query"
    )
))]
pub(crate) unsafe fn keep_entity<T, K>(object: *const T) -> crate::ffi::KeptIn {
    // SAFETY: the caller's.
    unsafe { count_of::<T, K>(object) }.keep()
}

/// The count of the entity whose object is at `object`, and how its place is given back.
///
/// # Safety
/// As [`count_in_entity`].
unsafe fn count_of<T, K>(object: *const T) -> crate::ffi::CountIn {
    let at = object.cast::<Answering<T, K>>();
    // SAFETY: the caller's: the place holds an `Answering<T, K>`, whose count stands until the
    // place goes back, which only `give_back_answering` does, called by whichever of the owner's
    // release and the last hold counted goes last.
    unsafe {
        crate::ffi::CountIn::new(
            &(*at).open,
            NonNull::new_unchecked(at.cast_mut().cast()),
            give_back_answering::<T, K>,
        )
    }
}

/// Let go of an entity's object for its owner: drop the object, and give its place back now when
/// no closure counted in it is held, or leave that to the last one let go of. The owner waits for
/// those closures first ([`closures_of`]) where the entity's contract says it does; one that does
/// not (an owner inside a callback, a background declaration) leaves the place to them.
///
/// # Safety
/// `object` is a live handle [`Slot::take_entity`] placed and filled for an [`Answering<T, K>`],
/// let go of once, here, and not used again.
pub(crate) unsafe fn retire_entity<T, K>(object: *mut T) {
    let at = object.cast::<Answering<T, K>>();
    // SAFETY: the caller's: the place holds an `Answering<T, K>` its owner lets go of once, here;
    // the object alone is dropped, as a closure may still read what is kept beside it.
    unsafe {
        core::mem::ManuallyDrop::drop(&mut (*at).value);
        retire_answering(at);
    }
}

/// The owner's letting go of an `Answering<T, K>` whose object is dropped: the place given back
/// now when nothing counted in it is held, else left to the last hold.
///
/// # Safety
/// As [`retire_entity`], its object dropped.
#[cfg(not(feature = "engine-tokio"))]
unsafe fn retire_answering<T, K>(at: *mut Answering<T, K>) {
    // SAFETY: the caller's.
    unsafe {
        let (open, lender) = lent_count(at);
        retire_lent(open, lender);
    }
}

/// As the cooperative engine's, the place going back to the kind's pool.
///
/// # Safety
/// As [`retire_entity`], its object dropped.
#[cfg(feature = "engine-tokio")]
unsafe fn retire_answering<T, K>(at: *mut Answering<T, K>) {
    // SAFETY: the caller's.
    unsafe {
        if (*at).open.retire() {
            release_entity(at);
        }
    }
}

/// The count of an `Answering<T, K>` lying in a place its session lent, and the lender kept
/// beside it: the two the place's letting go reads, apart from `T` and `K`.
///
/// # Safety
/// `at` is an `Answering<T, K>` [`Slot::take_entity`] placed and filled.
#[cfg(not(feature = "engine-tokio"))]
unsafe fn lent_count<T, K>(
    at: *mut Answering<T, K>,
) -> (
    *mut crate::ffi::OpenClosures,
    *const core::mem::ManuallyDrop<Lender>,
) {
    let place = at.cast::<InSession<Answering<T, K>>>();
    // SAFETY: the caller's: the place is an `InSession<Answering<T, K>>`, the object first.
    unsafe {
        (
            core::ptr::addr_of_mut!((*at).open),
            core::ptr::addr_of!((*place).lender),
        )
    }
}

/// The owner's letting go of a lent place by its count and its lender. One body for every kind
/// of entity whose closures are counted: each kind's own copy of the count's lock and of the
/// place given back differed only in where the two lie.
///
/// # Safety
/// As [`lent_count`]'s two, of a place whose object is dropped; called once.
#[cfg(not(feature = "engine-tokio"))]
#[inline(never)]
unsafe fn retire_lent(
    open: *mut crate::ffi::OpenClosures,
    lender: *const core::mem::ManuallyDrop<Lender>,
) {
    // SAFETY: the caller's: the count stands until the place goes back.
    if unsafe { (*open).retire() } {
        // SAFETY: the caller's; nothing holds the place, so it goes back here, once.
        unsafe { give_back_lent(open, lender) };
    }
}

/// Let go of the count of a lent place and give the place back to the session that lent it: the
/// rest of an `Answering` is its object and what its closures kept, let go of before.
///
/// # Safety
/// As [`lent_count`]'s two, of a place nothing holds any more; called once.
#[cfg(not(feature = "engine-tokio"))]
#[inline(never)]
unsafe fn give_back_lent(
    open: *mut crate::ffi::OpenClosures,
    lender: *const core::mem::ManuallyDrop<Lender>,
) {
    // SAFETY: the caller's: the lender was written when the place was filled, and is read out
    // once, here, as the count is dropped once.
    let lender = core::mem::ManuallyDrop::into_inner(unsafe { core::ptr::read(lender) });
    // SAFETY: the caller's: the count is live and nothing reads it after.
    unsafe { core::ptr::drop_in_place(open) };
    lender.give_back();
}

/// Give back the place of an entity whose owner and closures are all gone.
///
/// # Safety
/// `place` is an [`Answering<T, K>`]'s place whose object was dropped by [`retire_entity`], what
/// it kept taken out by its closures, and in which no closure is counted; called once.
unsafe fn give_back_answering<T, K>(place: NonNull<core::ffi::c_void>) {
    // SAFETY: the caller's: its count is all that is left to drop, and the place goes back once.
    unsafe { give_back_place(place.cast::<Answering<T, K>>().as_ptr()) };
}

/// Give back the place of an `Answering<T, K>` nothing holds any more, to the session that lent
/// it.
///
/// # Safety
/// As [`give_back_answering`].
#[cfg(not(feature = "engine-tokio"))]
unsafe fn give_back_place<T, K>(at: *mut Answering<T, K>) {
    // SAFETY: the caller's.
    unsafe {
        let (open, lender) = lent_count(at);
        give_back_lent(open, lender);
    }
}

/// As the cooperative engine's, the place going back to the kind's pool.
///
/// # Safety
/// As [`give_back_answering`].
#[cfg(feature = "engine-tokio")]
unsafe fn give_back_place<T, K>(at: *mut Answering<T, K>) {
    // SAFETY: the caller's.
    unsafe { release_entity(at) };
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

impl<T: core::fmt::Debug> core::fmt::Debug for Placed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&**self, f)
    }
}

impl<T> Drop for Placed<T> {
    /// One body out of line for each kind of object: every door that lets go of a held encoding
    /// drops one, and the release inlined at each held its own copy of giving the place back.
    #[inline(never)]
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

    /// An object that does not fit the place its kind is laid out with, by size or by alignment, is
    /// lent none. The CONTROL is a word, which fits. Turned red by a take that hands out a place
    /// for whatever object asks.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn an_object_larger_or_stricter_than_its_kinds_place_is_lent_none() {
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };

        const PAST_THE_PLACE: usize = match entity_place(Kind::Publisher) {
            Some((_, laid)) => laid.size() + 1,
            None => 1,
        };
        #[repr(align(4096))]
        struct Strict;

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        assert!(
            Slot::<[u8; PAST_THE_PLACE]>::take_entity(&engine, Kind::Publisher).is_none(),
            "larger than the place"
        );
        assert!(
            Slot::take_entity(&engine, Kind::Publisher)
                .map(|slot| slot.fill(Strict))
                .is_none(),
            "aligned past the place"
        );
        let word = Slot::<u64>::take_entity(&engine, Kind::Publisher);
        assert!(word.is_some(), "CONTROL: a word fits");
        drop((word, engine));
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
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
            engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };

        // How many publisher places `engine` has free: each claimed, then all given back.
        let free = |engine: &crate::session::EngineHold| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::Publisher)).collect();
            claimed.len()
        };
        let open = || {
            let session = listening_on_loopback();
            // SAFETY: the session is live and owned by this frame.
            let handle = unsafe { session_handle(z_session_loan(&session)) };
            let engine = engine_held(handle.expect("an open session has its handle")).clone();
            (session, engine)
        };
        let (mut one, one_engine) = open();
        let (mut other, other_engine) = open();
        let places = free(&one_engine);
        assert!(places > 0, "the session's limit admits publishers");
        assert_eq!(
            free(&one_engine),
            places,
            "a claim given back is free again"
        );

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
            free(&other_engine),
            places - 1,
            "the other lent one of its own"
        );
        for object in held {
            // SAFETY: each object was filled above and is released once.
            unsafe { release_entity(object) };
        }
        // SAFETY: as above.
        unsafe { release_entity(theirs) };
        assert_eq!(drops.get(), places + 1, "each object is dropped once");
        assert_eq!(free(&one_engine), places);
        assert_eq!(free(&other_engine), places);

        let unfilled =
            Slot::<u64>::take_entity(&one_engine, Kind::Publisher).expect("a place given back");
        assert_eq!(free(&one_engine), places - 1);
        drop(unfilled);
        assert_eq!(free(&one_engine), places);
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

    /// An entity its owner lets go of from inside a callback, while a closure counted in it is
    /// held, has its object dropped at once and its place left to that closure, whose drop gives it
    /// back; one let go of with no closure held gives its place back at once. Turned red by a
    /// release that gives the place back under a closure still counted in it, or never.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer", feature = "query"))]
    #[test]
    fn an_entitys_place_goes_back_with_the_last_of_its_owner_and_closures() {
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };

        unsafe extern "C" fn no_drop(_context: *mut core::ffi::c_void) {}

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        // How many querier places `engine` has free: each claimed, then all given back.
        let free = |engine: &crate::session::EngineHold| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::Querier)).collect();
            claimed.len()
        };
        let places = free(&engine);
        assert!(places > 0, "the session's limit admits queriers");

        let drops = core::cell::Cell::new(0);
        let object = Slot::take_entity(&engine, Kind::Querier)
            .expect("a querier's place")
            .fill(Answering::keeping(Counted(&drops), ()))
            .cast::<Counted<'_>>();
        let mut closure = crate::ffi::CClosure::<Option<unsafe extern "C" fn()>>::uncounted(
            core::ptr::null_mut(),
            None,
            Some(no_drop),
        );
        // SAFETY: `object` was filled for an `Answering` just above, and its owner holds it.
        unsafe { count_in_entity::<_, (), _>(object, &mut closure) };
        {
            // An owner inside a callback does not wait for the closures it counts.
            let _inside = crate::ffi::InCallback::enter().expect("a thread is marked");
            // SAFETY: as above; the owner lets go of `object` once, here.
            unsafe {
                closures_of::<_, ()>(object).wait_none();
                retire_entity::<_, ()>(object);
            }
        }
        assert_eq!(drops.get(), 1, "the owner's release drops the object");
        assert_eq!(
            free(&engine),
            places - 1,
            "the closure still holds the place"
        );
        drop(closure);
        assert_eq!(free(&engine), places, "the closure's drop gave it back");

        let object = Slot::take_entity(&engine, Kind::Querier)
            .expect("a querier's place")
            .fill(Answering::keeping(Counted(&drops), ()))
            .cast::<Counted<'_>>();
        // SAFETY: as above, with no closure counted.
        unsafe { retire_entity::<_, ()>(object) };
        assert_eq!(drops.get(), 2);
        assert_eq!(free(&engine), places, "the owner gave it back itself");

        drop(engine);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// A keep of an entity's place holds it past its owner's release, and the owner's wait does not
    /// wait for it, as it is no closure; the keep's drop gives the place back. Turned red by a wait
    /// that waits for a keep (the test hangs), or a release that gives the place back under one.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer", feature = "query"))]
    #[test]
    fn a_kept_place_outlives_its_owner_and_is_not_waited_for() {
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        // How many querier places `engine` has free: each claimed, then all given back.
        let free = |engine: &crate::session::EngineHold| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::Querier)).collect();
            claimed.len()
        };
        let places = free(&engine);

        let drops = core::cell::Cell::new(0);
        let object = Slot::take_entity(&engine, Kind::Querier)
            .expect("a querier's place")
            .fill(Answering::keeping(Counted(&drops), ()))
            .cast::<Counted<'_>>();
        // SAFETY: `object` was filled for an `Answering` just above, and its owner holds it.
        let kept = unsafe { keep_entity::<_, ()>(object) };
        // SAFETY: as above; the owner lets go of `object` once, here.
        unsafe {
            closures_of::<_, ()>(object).wait_none();
            retire_entity::<_, ()>(object);
        }
        assert_eq!(drops.get(), 1, "the owner's release drops the object");
        assert_eq!(free(&engine), places - 1, "the keep holds the place");
        drop(kept);
        assert_eq!(free(&engine), places, "the keep's drop gave it back");

        drop(engine);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// A subscriber's place, its owner let go of while a hold counted in it stands, has its object
    /// dropped at once and goes back with the hold's drop; one let go of with nothing held goes back
    /// at once, and a matching listener's place does the same through the one body both kinds
    /// share. Turned red by a release that gives the place back under a hold, never, or to no
    /// session (`retire_lent` or `give_back_lent` reading the lender at the wrong place).
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_counted_place_goes_back_with_the_last_of_its_owner_and_holds() {
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        // How many places of `kind` `engine` has free: each claimed, then all given back.
        let free = |kind: Kind| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(&engine, kind)).collect();
            claimed.len()
        };
        let drops = core::cell::Cell::new(0);
        for kind in [Kind::Subscriber, Kind::MatchingListener] {
            let places = free(kind);
            assert!(places > 0, "the session's limit admits the kind");

            let object = Slot::take_entity(&engine, kind)
                .expect("a place")
                .fill(Answering::keeping(Counted(&drops), ()))
                .cast::<Counted<'_>>();
            // SAFETY: `object` was filled for an `Answering` just above, and its owner holds it.
            let held = unsafe { hold_entity::<_, ()>(object) };
            // SAFETY: as above; the owner lets go of `object` once, here.
            unsafe { retire_entity::<_, ()>(object) };
            let dropped = drops.get();
            assert_eq!(free(kind), places - 1, "the hold keeps the place");
            drop(held);
            assert_eq!(free(kind), places, "the hold's drop gave it back");

            let object = Slot::take_entity(&engine, kind)
                .expect("a place")
                .fill(Answering::keeping(Counted(&drops), ()))
                .cast::<Counted<'_>>();
            // SAFETY: as above, with nothing counted.
            unsafe { retire_entity::<_, ()>(object) };
            assert_eq!(drops.get(), dropped + 1, "each release drops its object");
            assert_eq!(free(kind), places, "the owner gave it back itself");
        }
        assert_eq!(drops.get(), 4, "each object is dropped once");

        drop(engine);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// The places an open holds are laid out when the library is built, and they are what a walk of
    /// the build's kinds at run time lays out: each kind's place the build has, none missed. Turned
    /// red by a walk that stops before the last kind or skips one.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    fn the_held_places_are_each_built_kinds_place_laid_out_as_a_constant() {
        use wz_capi_coop::arena::HeldPlaces;
        const HANDLE: core::alloc::Layout = core::alloc::Layout::new::<[u64; 2]>();
        const HELD: HeldPlaces = held_places(HANDLE);
        let walked = BUILT_KINDS
            .into_iter()
            .flatten()
            .filter_map(entity_place)
            .fold(HeldPlaces::handle(HANDLE), |held, (entity, layout)| {
                held.with_entity(entity, layout)
            });
        #[cfg(feature = "connectivity")]
        let walked = crate::session_ext::held_lodgings(walked);
        assert_eq!(HELD, walked);
        assert_ne!(
            HELD,
            HeldPlaces::handle(HANDLE),
            "every build has publishers, so some place is held"
        );
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
        for (kind, layout) in BUILT_KINDS.into_iter().flatten().filter_map(entity_place) {
            std::println!(
                "place-row: {kind:?} place_bytes={} align={} flag_bytes={flag} per_entity={}",
                layout.size(),
                layout.align(),
                layout.size() + flag
            );
        }
    }
}
