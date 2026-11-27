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

// `Box` places an object only where no pool does; the tests make their objects with it too.
#[cfg(any(not(wz_process_pools), test))]
use crate::prelude::*;

/// Which object a place is for. With the pools reserved each kind has a pool of its own, so the
/// count stated for one kind is never spent by another of the same size; a kind a build places
/// nowhere is not a variant of it, and each keeps its number in every build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    // The cooperative engine's session lies in its own arena (`crate::session_place`), and the
    // sessions open at once are counted by its engine's rows (`wz_capi_coop::RowClaim`).
    #[cfg(feature = "engine-tokio")]
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
    /// Whether a session's arena lent the place for an entity's object on the cooperative engine
    /// ([`Self::take_entity`]), which wrote its lender in the place as it lent it; else the place
    /// is one of the process pools or the heap.
    #[cfg(not(feature = "engine-tokio"))]
    lent: bool,
}

impl<T> Slot<T> {
    /// A place for one `T` of `kind`, or `None` when the pool of that kind is full.
    #[cfg(wz_process_pools)]
    pub(crate) fn take(kind: Kind) -> Option<Self> {
        crate::process_pool::take::<T>(kind).map(|place| Self {
            place: place.cast(),
            #[cfg(not(feature = "engine-tokio"))]
            lent: false,
        })
    }

    /// A place for one `T`: without the pools every place is the heap's, whatever its kind.
    #[cfg(not(wz_process_pools))]
    pub(crate) fn take(kind: Kind) -> Option<Self> {
        let _ = kind;
        Some(Self {
            place: NonNull::from(Box::leak(Box::new(MaybeUninit::<T>::uninit()))),
            #[cfg(not(feature = "engine-tokio"))]
            lent: false,
        })
    }

    /// A place for the object of one of `engine`'s entities of `kind`, let go with
    /// [`release_entity`]. On the cooperative engine it is a place of the session's own arena,
    /// one of those its open laid out for the kind ([`held_places`]), as many as the limit the
    /// session opened under admits, so one session's entities never take another's: `None`
    /// when every one is held, or the kind or `T` is not one the open laid places out for. On the
    /// tokio engine it is a place of the kind's pool ([`Self::take`]).
    ///
    /// The lender is written in the place as it is lent, so the slot is the place alone and its
    /// fill writes the object only.
    #[cfg(not(feature = "engine-tokio"))]
    pub(crate) fn take_entity(engine: &crate::session::EngineHold, kind: Kind) -> Option<Self> {
        let place = Lender::lend_into(
            engine,
            kind,
            InSession::<T>::LAYOUT,
            InSession::<T>::LENDER_AT,
        )?;
        Some(Self {
            place: place.cast(),
            lent: true,
        })
    }

    /// A place for the object of one of `engine`'s entities of `kind`: on the tokio engine, a
    /// place of the kind's pool ([`Self::take`]).
    #[cfg(feature = "engine-tokio")]
    pub(crate) fn take_entity(engine: &crate::session::EngineHold, kind: Kind) -> Option<Self> {
        let _ = engine;
        Self::take(kind)
    }

    /// The place, the slot given up: what lies there is its holder's to let go of.
    fn into_place(self) -> NonNull<MaybeUninit<T>> {
        core::mem::ManuallyDrop::new(self).place
    }

    /// Put `value` in the place and hand back where it lies: the handle an owned struct holds,
    /// which [`release`] lets go, or [`release_entity`] for one [`Self::take_entity`] placed.
    pub(crate) fn fill(self, value: T) -> *mut T {
        let place = self.into_place();
        // SAFETY: the place is a live allocation sized and aligned for `T`, which nothing else
        // holds, and it is not filled yet; a lent place's lender lies past the object.
        unsafe { place.as_ptr().write(MaybeUninit::new(value)) };
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
        self.into_place();
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
        #[cfg(not(feature = "engine-tokio"))]
        if self.lent {
            // SAFETY: a place lent for an `InSession<T>`, its lender written at the take and its
            // object never written, given back once.
            unsafe { give_back_lent_place(self.place.cast(), InSession::<T>::LENDER_AT) };
            return;
        }
        // SAFETY: an unfilled place this slot took, given back once.
        unsafe { give_back(self.place) }
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

#[cfg(not(feature = "engine-tokio"))]
impl Lender {
    /// A place of `engine`'s arena for an entity of `kind` whose object, with its lender, is laid
    /// out by `needed`, the lender written in it `lender_at` bytes past its start: `None` when
    /// every place of the kind is held, or the kind or the layout is not one the open laid places
    /// out for. One body for every kind of entity, out of the line of each declare, so the layout
    /// and the lender's offset are values, and no declare carries a copy of the take or moves the
    /// lender to its object's fill.
    #[inline(never)]
    fn lend_into(
        engine: &crate::session::EngineHold,
        kind: Kind,
        needed: core::alloc::Layout,
        lender_at: usize,
    ) -> Option<NonNull<u8>> {
        let (entity, laid) = entity_place(kind)?;
        if needed.size() > laid.size() || needed.align() > laid.align() {
            return None;
        }
        // The cooperative engine lends places itself, reached as its own type.
        let place = wz_capi_port::PlaceLender::claim_place(
            crate::session::EngineHold::as_ref(engine),
            entity,
        )?;
        let base = place.as_ptr();
        let lender = Self {
            place,
            engine: crate::session::EngineHold::clone(engine),
        };
        // SAFETY: the place is at least as large and as aligned as `needed`, the layout of an
        // `InSession` whose lender lies `lender_at` bytes in, which nothing has written yet.
        unsafe {
            base.as_ptr()
                .add(lender_at)
                .cast::<core::mem::ManuallyDrop<Self>>()
                .write(core::mem::ManuallyDrop::new(lender));
        }
        Some(base)
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
    /// How many bytes past the start of the place its lender lies.
    const LENDER_AT: usize = core::mem::offset_of!(InSession<T>, lender);
}

/// Give back the place at `place` to the session that lent it, reading its lender `lender_at`
/// bytes in: what the place held let go of first, or never written. One body for every kind of
/// entity, so the release of an object and the drop of an unfilled slot read the lender in one
/// place, apart from `T`.
///
/// # Safety
/// `place` is a place [`Lender::lend_into`] lent with its lender at `lender_at`, which holds no
/// live object and is given back once.
#[cfg(not(feature = "engine-tokio"))]
#[inline(never)]
unsafe fn give_back_lent_place(place: NonNull<u8>, lender_at: usize) {
    // SAFETY: the caller's: the lender was written there as the place was lent, and is read out
    // once, here.
    let lender = core::mem::ManuallyDrop::into_inner(unsafe {
        core::ptr::read(
            place
                .as_ptr()
                .add(lender_at)
                .cast::<core::mem::ManuallyDrop<Lender>>(),
        )
    });
    lender.give_back();
}

/// The engine of the session whose arena lent the place `object` lies in, as the place's lender
/// holds it: an entity's object reaches its session through the one count its place keeps, and
/// keeps none of its own beside it.
///
/// # Safety
/// `object` is the object of a place [`Slot::take_entity`] lent for a `T` and filled, read through
/// the pointer the place was filled at, and the place stands for `'a`.
#[cfg(not(feature = "engine-tokio"))]
unsafe fn lent_engine<'a, T>(object: *const T) -> &'a crate::session::EngineHold {
    // SAFETY: the caller's: the object is the start of an `InSession<T>` (`repr(C)`, its value
    // first), whose lender the take wrote `LENDER_AT` bytes in, where it stays until the place goes
    // back.
    let lender = unsafe {
        &*object
            .cast::<u8>()
            .add(InSession::<T>::LENDER_AT)
            .cast::<core::mem::ManuallyDrop<Lender>>()
    };
    &lender.engine
}

/// An entity's object that reaches the engine of the session it was declared on
/// ([`entity_engine`]): on the cooperative engine through the one count its place's lender keeps,
/// so the object keeps none beside it; on the tokio engine, whose places are its pools' and hold
/// none, through the count the object keeps.
pub(crate) trait SessionEntity {
    /// What the entity's place was taken for: the object itself, or the [`Answering`] the object
    /// begins.
    #[cfg(not(feature = "engine-tokio"))]
    type Placed;

    /// The count of the engine the object keeps on the tokio engine.
    #[cfg(feature = "engine-tokio")]
    fn kept_engine(&self) -> &crate::session::EngineHold;
}

/// The engine of the session the entity whose object is at `object` was declared on: the one
/// every door of the entity reads, its undeclaration included.
///
/// # Safety
/// `object` is a live object [`Slot::take_entity`] placed and filled for a `T::Placed` (the
/// object first), read through the pointer the place was filled at, and the place stands for
/// `'a`.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) unsafe fn entity_engine<'a, T: SessionEntity>(
    object: *const T,
) -> &'a crate::session::EngineHold {
    // SAFETY: the caller's: the object begins a filled `T::Placed` its session's arena lent.
    unsafe { lent_engine(object.cast::<T::Placed>()) }
}

/// The engine of the session the entity whose object is at `object` was declared on, the count
/// the object keeps on the tokio engine.
///
/// # Safety
/// `object` is a live object, which stands for `'a`.
#[cfg(feature = "engine-tokio")]
pub(crate) unsafe fn entity_engine<'a, T: SessionEntity + 'a>(
    object: *const T,
) -> &'a crate::session::EngineHold {
    // SAFETY: the caller's.
    unsafe { (*object).kept_engine() }
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
            InSession::<crate::pubsub::SubscriberState>::LAYOUT,
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
            InSession::<crate::pubsub::SubscriberState>::LAYOUT,
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
/// queryable's closure), and what those closures keep in the place past the object (`K`: the C
/// closure a queryable's row calls), inline in the entity's
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
    /// `value`, keeping `kept` for its closures, with none counted yet, made by value: a test's
    /// place, whose count's lock is the host's and is not taken before the place is filled.
    #[cfg(test)]
    pub(crate) fn keeping(value: T, kept: K) -> Self {
        Self {
            value: core::mem::ManuallyDrop::new(value),
            open: crate::ffi::OpenClosures::default(),
            kept: core::mem::ManuallyDrop::new(kept),
        }
    }

    /// `value` and `kept` written in the place at `at`, beside a count with none held made there
    /// (`OpenClosures::init_at`): a kernel's lock is made where it stays.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self`, aligned for it and holds none, and the place is not
    /// moved while it holds one.
    unsafe fn write_parts(at: *mut Self, value: T, kept: K) {
        // SAFETY: the caller's: each field is written once through a pointer to it, not null as
        // `at` is valid.
        unsafe {
            core::ptr::addr_of_mut!((*at).value).write(core::mem::ManuallyDrop::new(value));
            crate::ffi::OpenClosures::init_at(NonNull::new_unchecked(core::ptr::addr_of_mut!(
                (*at).open
            )));
            core::ptr::addr_of_mut!((*at).kept).write(core::mem::ManuallyDrop::new(kept));
        }
    }

    /// As `Slot::fill_answering`, the value and what is kept written by `write` and `write_kept`
    /// in the places where they stay: what a value holding a lock is made in, its lock made there
    /// ([`wz_capi_port::os::mutex_in`]).
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self`, aligned for it and holds none; `write` leaves a valid
    /// `T` and `write_kept` a valid `K` in the place each is handed.
    #[cfg(any(feature = "query", feature = "connectivity", feature = "advanced"))]
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
            crate::ffi::OpenClosures::init_at(NonNull::new_unchecked(core::ptr::addr_of_mut!(
                (*at).open
            )));
            write_kept(NonNull::new_unchecked(
                core::ptr::addr_of_mut!((*at).kept).cast::<K>(),
            ));
        }
    }
}

impl<T, K> Slot<Answering<T, K>> {
    /// The place filled with `value`, keeping `kept` for its closures, with none counted yet:
    /// each part written where it stays, the count's lock made there.
    pub(crate) fn fill_answering(self, value: T, kept: K) -> *mut Answering<T, K> {
        // SAFETY: the slot's place is sized and aligned for an `Answering<T, K>` and holds none,
        // and `write_parts` leaves one there.
        unsafe { self.fill_in_place(|at| Answering::write_parts(at, value, kept)) }
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
    // SAFETY: the caller's: the lender was written when the place was lent, and is read out
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
    // SAFETY: the caller's: a live object, dropped once, in an `InSession<T>` whose lender was
    // written when its place was lent, which goes back once, here.
    unsafe {
        core::ptr::drop_in_place(object);
        give_back_lent_place(
            NonNull::new_unchecked(object.cast()),
            InSession::<T>::LENDER_AT,
        );
    }
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

/// Give back a place whose value is gone: to its pool when it lies in one, else to the heap. The
/// typed face of [`give_back_laid`], which every type shares.
///
/// # Safety
/// `place` was taken for a `T` (by a [`Slot`] or a `Box`), holds no live value, and is given
/// back once.
unsafe fn give_back<T>(place: NonNull<MaybeUninit<T>>) {
    // SAFETY: the caller's; a `Box` of a `T` was allocated with the layout of a `T`.
    unsafe { give_back_laid(place.cast::<u8>(), core::alloc::Layout::new::<T>()) }
}

/// Give back the place at `place`, laid out by `layout`: to its pool when it lies in one, else
/// to the heap it was allocated from with `layout`. Inlined into each release: few types are
/// released through it, and a body of its own cost more than the copies it replaced.
///
/// # Safety
/// `place` holds no live value, is given back once, and lies in a pool or was allocated from the
/// global heap with `layout`.
#[inline]
unsafe fn give_back_laid(place: NonNull<u8>, layout: core::alloc::Layout) {
    #[cfg(wz_process_pools)]
    if crate::process_pool::give_back(place) {
        return;
    }
    // A `Box` of nothing allocated nothing, so there is nothing to give back.
    if layout.size() != 0 {
        // SAFETY: the caller's: the heap allocated `place` with `layout`.
        unsafe { alloc::alloc::dealloc(place.as_ptr(), layout) };
    }
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

    /// The shared give-back hands a heap place back with the layout its `Box` was allocated by,
    /// whatever the type: one over-aligned, and one of no bytes, which allocated nothing and so is
    /// given nothing back. Turned red (the test process aborts in the heap) by a give-back that
    /// frees the dangling place of a type of no bytes.
    #[test]
    fn a_heap_object_of_any_layout_goes_back_through_the_one_body() {
        #[repr(align(64))]
        struct Wide(u8);
        struct Nothing;
        let wide = Box::into_raw(Box::new(Wide(7)));
        let nothing = Box::into_raw(Box::new(Nothing));
        // SAFETY: two live `Box::into_raw` handles, each released once.
        unsafe {
            assert_eq!((*wide).0, 7);
            release(wide);
            release(nothing);
        }
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
        // Filled as a door fills an entity's place, its count made where it stays.
        let object = Slot::<Answering<Counted<'_>>>::take_entity(&engine, Kind::Querier)
            .expect("a querier's place")
            .fill_answering(Counted(&drops), ())
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

    /// Every kind of entity the build has, whose door it exports, is laid at least one place in
    /// the arena of a session that opens under the opening limits and states nothing, a client of
    /// as many endpoints as the build dials; and in a build that opens by its region, whose tables
    /// no config resizes, a querier and a liveliness subscriber are laid two, where the build's
    /// domain holds two, so a program holds a second of each. Turned red by a kind left out of the
    /// rows (`entity_rows` in `wz-capi-coop`) or a region laid out under the open values.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    fn every_built_kind_is_laid_a_place_by_the_open_of_a_session_that_states_nothing() {
        use crate::session::{opening_limits, pico_unicast_batch};
        use wz_capi_coop::arena::{ArenaPlan, PlanShape};
        let limits = opening_limits();
        let shape = PlanShape::dial_only(
            wz_session_core::caps::MAX_STATIC_CONNECT,
            pico_unicast_batch(&limits),
            &wz_session_core::policy::SessionPolicy::defaults(),
        );
        let rows = ArenaPlan::planned(shape, &limits)
            .expect("a client of the opening limits lays out")
            .entities();
        let built: Vec<(Kind, wz_capi_port::EntityKind)> = BUILT_KINDS
            .into_iter()
            .flatten()
            .filter_map(|kind| Some((kind, entity_place(kind)?.0)))
            .collect();
        assert!(
            built.iter().any(|(kind, _)| *kind == Kind::Publisher),
            "CONTROL: every build has publishers"
        );
        for (kind, entity) in &built {
            assert!(
                rows.of_kind(*entity) >= 1,
                "{kind:?} is a kind the build has, and its session is laid no place for one"
            );
        }
        #[cfg(all(
            feature = "query",
            not(any(
                feature = "config-policy",
                feature = "peer",
                feature = "multicast-transport"
            ))
        ))]
        if wz_session_core::limits::SessionLimits::defaults()
            .select_max_queriers(wz_session_core::limit_binding::Quota::at_most(2))
            .is_ok()
        {
            assert_eq!(rows.of_kind(wz_capi_port::EntityKind::Querier), 2);
        }
        #[cfg(all(
            feature = "liveliness",
            not(any(
                feature = "config-policy",
                feature = "peer",
                feature = "multicast-transport"
            ))
        ))]
        if wz_session_core::limits::SessionLimits::defaults()
            .select_max_liveliness_subscriptions(wz_session_core::limit_binding::Quota::at_most(2))
            .is_ok()
        {
            assert_eq!(
                rows.of_kind(wz_capi_port::EntityKind::LivelinessSubscriber),
                2
            );
        }
    }

    /// The lender of a lent place lies past its object and within the place, aligned for itself,
    /// for objects of several sizes and alignments: the take writes it there before the object is
    /// written, so a fill that wrote over it, or a place with no room for it, would lose the
    /// session that lent the place. Turned red by a `LENDER_AT` that is not `InSession`'s own
    /// offset of its lender.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    fn a_lent_places_lender_lies_past_its_object_within_the_place() {
        fn holds<T>() {
            let at = InSession::<T>::LENDER_AT;
            assert!(at >= core::mem::size_of::<T>(), "past the object");
            assert!(
                at + core::mem::size_of::<Lender>() <= InSession::<T>::LAYOUT.size(),
                "within the place"
            );
            assert_eq!(
                at % core::mem::align_of::<Lender>(),
                0,
                "aligned for itself"
            );
        }
        holds::<u8>();
        holds::<u64>();
        holds::<[u8; 13]>();
        holds::<crate::pubsub::PublisherState>();
        holds::<crate::pubsub::SubscriberState>();
    }

    /// A lent place whose fill is refused goes back to the session that lent it, its lender read
    /// where the take wrote it, and a filled one goes back at its release: the path a declaration
    /// the engine refuses takes. Turned red by an unfilled lent slot given back as a pool's place,
    /// or by a fill or a release that does not find the lender the take wrote.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_refused_fill_gives_the_lent_place_back_to_its_session() {
        use crate::session::{
            engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
            z_session_move,
        };

        // How many subscriber places `engine` has free: each claimed, then all given back.
        let free = |engine: &crate::session::EngineHold| {
            let claimed: Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::Subscriber))
                    .collect();
            claimed.len()
        };
        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        let places = free(&engine);
        assert!(places > 0, "the session's limit admits subscribers");

        let slot = Slot::<u64>::take_entity(&engine, Kind::Subscriber).expect("a place");
        assert_eq!(free(&engine), places - 1, "the slot holds its place");
        // SAFETY: the refused write writes nothing.
        let refused = unsafe { slot.try_fill_in_place(|_| Err::<(), i32>(7)) };
        assert_eq!(refused.err(), Some(7));
        assert_eq!(free(&engine), places, "a refused fill gives the place back");

        let drops = core::cell::Cell::new(0);
        let object = Slot::take_entity(&engine, Kind::Subscriber)
            .expect("a place")
            .fill(Counted(&drops));
        assert_eq!(free(&engine), places - 1, "a filled place stays lent");
        // SAFETY: the object was filled above and is released once.
        unsafe { release_entity(object) };
        assert_eq!(drops.get(), 1, "the object is dropped once");
        assert_eq!(free(&engine), places, "the release gives the place back");

        drop(engine);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
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

    /// What each part of a publisher's and a subscriber's place takes, printed for choosing which
    /// part of the places their limits multiply is to be made smaller: the place, the object and
    /// each value the object holds, in bytes. Run with `cargo test -p wz-capi-pico --lib
    /// print_the_parts_of_the_publisher_and_subscriber_places -- --ignored --nocapture` under the
    /// features of the build to read.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    #[ignore = "a measurement printed for reading, not a check"]
    fn print_the_parts_of_the_publisher_and_subscriber_places() {
        use core::mem::size_of;
        let parts: [(&str, usize); 22] = [
            (
                "publisher place",
                InSession::<crate::pubsub::PublisherState>::LAYOUT.size(),
            ),
            (
                "subscriber place",
                InSession::<crate::pubsub::SubscriberState>::LAYOUT.size(),
            ),
            ("PublisherState", size_of::<crate::pubsub::PublisherState>()),
            ("PlainPublisher", size_of::<crate::pubsub::PlainPublisher>()),
            ("PublisherQos", size_of::<crate::pubsub::PublisherQos>()),
            (
                "Option<OwnedEncoding>",
                size_of::<Option<crate::encoding::OwnedEncoding>>(),
            ),
            ("FilteredKey", size_of::<crate::write_filter::FilteredKey>()),
            ("WriteFilter", size_of::<crate::write_filter::WriteFilter>()),
            (
                "DeclaredKeyexpr",
                size_of::<crate::keyexpr::DeclaredKeyexpr>(),
            ),
            ("KeyText", size_of::<crate::keyexpr::KeyText>()),
            ("HeldKey", size_of::<wz_capi_port::HeldKey>()),
            (
                "Option<WireDeclaration>",
                size_of::<Option<crate::keyexpr::WireDeclaration>>(),
            ),
            ("KeyHold", size_of::<wz_capi_port::KeyHold>()),
            ("WireKey", size_of::<wz_capi_port::WireKey>()),
            (
                "z_loaned_keyexpr_t",
                size_of::<crate::abi::z_loaned_keyexpr_t>(),
            ),
            (
                "SubscriberState",
                size_of::<crate::pubsub::SubscriberState>(),
            ),
            (
                "Option<DeclaredSubscriber>",
                size_of::<Option<crate::pubsub::DeclaredSubscriber>>(),
            ),
            ("OpenClosures", size_of::<crate::ffi::OpenClosures>()),
            ("Option<HeldIn>", size_of::<Option<crate::ffi::HeldIn>>()),
            ("Lender", size_of::<Lender>()),
            ("EntityPlace", size_of::<wz_capi_port::EntityPlace>()),
            ("EngineHold", size_of::<crate::session::EngineHold>()),
        ];
        for (part, bytes) in parts {
            std::println!("place-part: {part:<28} {bytes:>5} B");
        }
    }

    /// The arena a session that listens opens, row by row: its tables' rows and the ABI's places
    /// as the open lays them out for a listener (and for a dialer) under the build's limits, each
    /// row's limit, count and the bytes of one, and the bytes a real open of a listener reserved.
    /// What that open reserved past the listener's rows is the engine's own holds: its links'
    /// cells, the faces' rooms, the runtime's tables, the engine's place, its planes and the
    /// admission. Run with `cargo test -p wz-capi-pico --lib
    /// the_arena_a_listening_session_opens_by_row_measured -- --ignored --nocapture` under the
    /// features and limits of the build to read.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    #[ignore = "a measurement printed for reading, not a check"]
    fn the_arena_a_listening_session_opens_by_row_measured() {
        use crate::session::{
            engine_ref, listening_on_loopback, pico_unicast_batch, session_handle, z_session_drop,
            z_session_loan, z_session_move, SessionPlace,
        };
        use wz_capi_coop::arena::{admitted_faces, admitted_handshakes, ArenaPlan, PlanShape};
        use wz_session_core::limits::SessionLimits;

        let print = |name: &str, plan: &ArenaPlan| {
            std::println!("arena-rows: {name}");
            for row in plan.rows() {
                std::println!(
                    "arena-rows:   {:<36} {:<52} {:>6} x {:>7} = {:>9}",
                    row.part(),
                    row.basis(),
                    row.count,
                    row.entry_bytes,
                    row.bytes().unwrap_or(usize::MAX),
                );
            }
            std::println!(
                "arena-rows:   reserved {}",
                plan.reserved_bytes().unwrap_or(usize::MAX)
            );
        };
        let limits = SessionLimits::defaults();
        let batch = pico_unicast_batch(&limits);
        let held = held_places(SessionPlace::LAYOUT);
        let listener = PlanShape {
            listens: 1,
            max_faces: admitted_faces(&limits).expect("the build admits its own faces"),
            accept_pending: admitted_handshakes(&limits).expect("the build admits its handshakes"),
            ..PlanShape::dial_only(
                0,
                batch,
                &wz_session_core::policy::SessionPolicy::defaults(),
            )
        };
        let mut listens = ArenaPlan::planned(listener, &limits).expect("a listener's rows lay out");
        listens.holding(&held).expect("the places lay out");
        print("a listener's tables and places", &listens);
        let mut dials = ArenaPlan::planned(
            PlanShape::dial_only(
                1,
                batch,
                &wz_session_core::policy::SessionPolicy::defaults(),
            ),
            &limits,
        )
        .expect("a dial lays out");
        dials.holding(&held).expect("the places lay out");
        print("a dialer's tables and places", &dials);

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let opened = engine_ref(handle.expect("an open session has its handle")).arena_bytes();
        let rows = listens.reserved_bytes().unwrap_or(usize::MAX);
        std::println!(
            "arena-rows: a listener's open reserved {opened}, its rows {rows}, the engine's own \
             holds {}",
            opened.saturating_sub(rows)
        );
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }
}
