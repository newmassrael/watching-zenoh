// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How a pico advanced subscriber names its entities on the wire.
//!
//! zenoh-pico builds its advanced subscriber out of its own primitives: a plain
//! subscriber, a startup history query, a liveliness subscriber for late
//! publishers, a second plain subscriber for heartbeats and a liveliness token
//! for detection
//! (`vendor/zenoh-pico/src/api/advanced_subscriber.c` @
//! `z_result_t ze_declare_advanced_subscriber(const z_loaned_session_t *zs, ze_owned_advanced_subscriber_t *sub,`).
//! Each of those is an ordinary pico declaration, and what each one puts on the
//! wire is decided by the same three rules the plain entry points follow:
//!
//! - a subscriber declares the NON-WILD PREFIX of its key, is announced on the
//!   CALLER's key, and retracts naming the prefix;
//! - a liveliness subscriber declares the WHOLE key and is announced on it;
//! - a liveliness token declares the whole key, is announced on it and retracts
//!   naming it.
//!
//! The runtime's advanced subscriber knows none of that — it announces every
//! entity on its literal key — so it asks ([`DeclarationForms`]) and this file
//! answers with the plain constructors' own functions
//! ([`DeclaredKeyexpr::declare_non_wild_prefix`], [`DeclaredKeyexpr::declare`],
//! [`DeclaredKeyexpr::retraction_naming_in`]), so an advanced subscriber and the
//! entities it is made of cannot describe one key two ways.
//!
//! # One declaration per entity, however many faces
//!
//! The runtime declares a subscriber once per face, and asks once per face. pico
//! has ONE session and one declaration per entity, and a key declared again goes
//! on the wire again, so answering every face with a fresh declaration would put
//! a face's worth of duplicates on each connection. The first face's answer
//! declares and the later faces' reuse it, through a weak reference: the
//! declaration stands for as long as some face still holds an entity on it and
//! is retracted with the last — which is when pico lets go of a key it counted.

use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use wz_capi_port::lodge::{Kept, Lodging, Strong, WeakRef};
use wz_capi_port::os::Mutex;
use wz_ext_pubsub::advanced_subscriber::{DeclarationForms, EntityForm};
use wz_session_core::WhatAmI;

use crate::ffi::{CountIn, KeptIn};
use crate::keyexpr::DeclaredKeyexpr;
use crate::session::Engine;
use crate::write_filter::PicoSession;

/// How many entities an advanced subscriber declares ([`Entity`]).
const ENTITIES: usize = 4;

/// The four entities an advanced subscriber declares, in the order the forms
/// are asked about them and the index of each one's answer.
#[derive(Clone, Copy)]
enum Entity {
    Subscriber,
    LatePublishers,
    Heartbeat,
    Token,
}

/// What one entity's name stands on, held for as long as the entity stands.
///
/// `key` is the declaration made for the entity and `announced` the key the
/// entity is announced on: the caller's for a subscriber, the key it was derived
/// from for the heartbeat, its own for the two liveliness entities. Dropping it
/// releases both, `key` first.
struct Anchor {
    key: DeclaredKeyexpr,
    announced: DeclaredKeyexpr,
}

/// The places the anchors of one subscriber's entities are lodged in, one per entity, kept beside
/// the subscriber in its place, so an anchor takes no memory of its own.
pub(crate) struct AnchorRooms([AnchorRoom; ENTITIES]);

/// One entity's room: the anchor lodged in it, and the keep of the place the rooms lie in, held
/// while an anchor is, so the place stands until the anchor's last count goes.
struct AnchorRoom {
    lodging: UnsafeCell<MaybeUninit<Lodging<Anchor>>>,
    keep: UnsafeCell<Option<KeptIn>>,
    /// Set when the last count of the anchor lodged here let go of the room ([`vacate`]), read
    /// before another is lodged.
    vacant: AtomicBool,
}

impl AnchorRooms {
    /// Four rooms holding no anchor.
    pub(crate) fn new() -> Self {
        Self(core::array::from_fn(|_| AnchorRoom {
            lodging: UnsafeCell::new(Lodging::vacant()),
            keep: UnsafeCell::new(None),
            vacant: AtomicBool::new(true),
        }))
    }

    fn room(&self, entity: Entity) -> &AnchorRoom {
        let [subscriber, late_publishers, heartbeat, token] = &self.0;
        match entity {
            Entity::Subscriber => subscriber,
            Entity::LatePublishers => late_publishers,
            Entity::Heartbeat => heartbeat,
            Entity::Token => token,
        }
    }

    /// `anchor` lodged in `entity`'s room, which `keep` keeps standing until its last count goes.
    ///
    /// # Safety
    /// The room is vacant, these rooms stand unmoved until it is given back, and no other thread
    /// lodges in it meanwhile.
    unsafe fn lodge(&self, entity: Entity, anchor: Anchor, keep: Option<KeptIn>) -> Strong<Anchor> {
        let room = self.room(entity);
        room.vacant.store(false, Ordering::Relaxed);
        // SAFETY: the caller's: the room is vacant and lodged in by this thread alone, so its keep
        // is written before the anchor that `vacate` reads it for, and the lodging is free.
        unsafe {
            *room.keep.get() = keep;
            Strong::lodge(
                NonNull::new_unchecked(room.lodging.get()),
                anchor,
                vacate,
                core::ptr::from_ref(room).cast_mut().cast::<c_void>(),
            )
        }
    }
}

/// The last count of an anchor let go of its room: the room is vacant, and the keep of the place
/// it held goes last, as it may give the place back.
///
/// # Safety
/// `context` is the room the anchor was lodged in ([`AnchorRooms::lodge`]), given back once.
unsafe fn vacate(context: *mut c_void) {
    let room = context.cast::<AnchorRoom>();
    // SAFETY: the caller's: no count of the anchor is left, so nothing else reads the keep.
    let keep = unsafe { (*(*room).keep.get()).take() };
    // SAFETY: as above; the room stands while the keep is held.
    unsafe { (*room).vacant.store(true, Ordering::Release) };
    drop(keep);
}

/// The [`DeclarationForms`] of one C advanced subscriber.
pub(crate) struct PicoSubscriberForms {
    /// Weak, because the registry holds these forms (they are in the entry it
    /// replays) and a strong reference back is a session that can never end.
    shared: Weak<Engine>,
    mode: WhatAmI,
    /// The caller's key: declared when the caller's is, a literal otherwise.
    base: DeclaredKeyexpr,
    /// The declaration each entity stands on now, indexed by [`Entity`]. Held
    /// weakly: a face's entity holds it, the forms do not.
    answered: Mutex<[Option<WeakRef<Anchor>>; ENTITIES]>,
    /// Where each entity's anchor is lodged.
    rooms: NonNull<AnchorRooms>,
    /// The count of the place the rooms lie in, kept once for each anchor lodged; `None` for
    /// rooms that stand by other means.
    place: Option<CountIn>,
    /// Declarations handed over when a subscriber runs in the background, one per entity.
    retained: Mutex<[Option<Kept>; ENTITIES]>,
}

// SAFETY: the rooms are reached through shared borrows; a room's cells are written only while it
// is vacant, under `answered`'s lock, or by its anchor's last count, which nothing else reads
// past; the place's count is `Send + Sync`.
unsafe impl Send for PicoSubscriberForms {}
// SAFETY: as `Send`.
unsafe impl Sync for PicoSubscriberForms {}

impl PicoSubscriberForms {
    /// The forms of an advanced subscriber on `base`, declared on `session`, lodging each
    /// entity's anchor in `rooms`, whose place `place` counts.
    ///
    /// # Safety
    /// `rooms` are vacant and stand unmoved until every anchor lodged in them is let go of: the
    /// place `place` counts stands while it is kept, which every anchor is; with no `place`, the
    /// caller keeps the rooms past the forms and every anchor they answer with. Anchors are
    /// lodged only while the place's owner holds it.
    pub(crate) unsafe fn new(
        session: &PicoSession,
        base: DeclaredKeyexpr,
        rooms: NonNull<AnchorRooms>,
        place: Option<CountIn>,
    ) -> Self {
        Self {
            shared: Arc::downgrade(&session.engine),
            mode: session.mode,
            base,
            answered: Mutex::new([None, None, None, None]),
            rooms,
            place,
            retained: Mutex::new([None, None, None, None]),
        }
    }

    /// The declaration `entity` stands on: the one another face already holds,
    /// else a new one, lodged in the entity's room. `None` when the session cannot make it, or
    /// when the last holder of the previous one is letting go of its room on another thread.
    fn anchor(
        &self,
        shared: &crate::session::EngineHold,
        entity: Entity,
        keyexpr: &str,
    ) -> Option<Strong<Anchor>> {
        // Held across the declaration, so two faces asking at once cannot both
        // declare: the second finds the first's answer.
        let mut answered = self.answered.lock();
        let slot = answered.get_mut(entity as usize)?;
        if let Some(held) = slot.as_ref().and_then(WeakRef::upgrade) {
            return Some(held);
        }
        // Every face let go: the room goes back with the weak count let go of here, unless the
        // last count is going on another thread right now.
        drop(slot.take());
        // SAFETY: the rooms stand while the forms do (`Self::new`).
        let rooms = unsafe { self.rooms.as_ref() };
        if !rooms.room(entity).vacant.load(Ordering::Acquire) {
            return None;
        }
        // The key the entity's own derives from. The subscriber is on the
        // caller's; the rest are on keys built FROM it (`z_keyexpr_clone` then
        // an append, or `z_keyexpr_join`), which keep the caller's declaration
        // while they still begin with it.
        let carrier = match entity {
            Entity::Subscriber => self.base.share().ok()?,
            Entity::LatePublishers | Entity::Heartbeat | Entity::Token => {
                self.base.extended(keyexpr).ok()?
            }
        };
        let (key, announced) = match entity {
            Entity::Subscriber | Entity::Heartbeat => {
                let key = DeclaredKeyexpr::declare_non_wild_prefix(shared, keyexpr, Some(&carrier))
                    .ok()?;
                (key, carrier)
            }
            Entity::LatePublishers | Entity::Token => {
                let key = DeclaredKeyexpr::declare(shared, keyexpr, Some(&carrier)).ok()?;
                let announced = key.share().ok()?;
                (key, announced)
            }
        };
        // SAFETY: the room is vacant, lodged in under `answered`'s lock alone, and the rooms
        // stand until its anchor's last count goes (`Self::new`); the place is kept while its
        // owner holds it, as anchors are lodged only then.
        let anchor = unsafe {
            rooms.lodge(
                entity,
                Anchor { key, announced },
                self.place.map(CountIn::keep),
            )
        };
        *slot = Some(Strong::downgrade(&anchor));
        Some(anchor)
    }

    /// How `entity` on `keyexpr` is named, declaring what names it.
    ///
    /// A session that is gone, or one that cannot declare the key, is answered
    /// with the literal form: the entity still reaches its peers, only without
    /// the shorthand.
    fn form(&self, entity: Entity, keyexpr: &str) -> EntityForm {
        let Some(shared) = self.shared.upgrade() else {
            return EntityForm::literal();
        };
        let Some(anchor) = self.anchor(&shared, entity, keyexpr) else {
            return EntityForm::literal();
        };
        let kept = Kept::lodged(anchor.clone());
        let form = match anchor.announced.aliased_parts(Arc::as_ref(&shared)) {
            // SAFETY: the rest lies in the anchor's announced key, which the anchor keeps,
            // unchanged, for as long as a count of it is held, and `kept` is one.
            Some((mapping_id, rest)) => unsafe { EntityForm::aliased_in(mapping_id, rest, kept) },
            None => EntityForm::literal().keeping(kept),
        };
        match entity {
            Entity::Subscriber | Entity::Heartbeat => form.with_retraction_naming(
                anchor
                    .key
                    .retraction_naming_in(self.mode, Arc::as_ref(&shared)),
            ),
            Entity::LatePublishers => form,
            Entity::Token => form.with_token_retraction_naming_the_key(true),
        }
    }
}

impl DeclarationForms for PicoSubscriberForms {
    fn subscriber(&self, keyexpr: &str) -> EntityForm {
        self.form(Entity::Subscriber, keyexpr)
    }

    fn late_publishers(&self, keyexpr: &str) -> EntityForm {
        self.form(Entity::LatePublishers, keyexpr)
    }

    fn heartbeat(&self, keyexpr: &str) -> EntityForm {
        self.form(Entity::Heartbeat, keyexpr)
    }

    fn token(&self, keyexpr: &str) -> EntityForm {
        self.form(Entity::Token, keyexpr)
    }

    fn retain(&self, anchor: Kept) {
        let mut retained = self.retained.lock();
        // A subscriber hands over one keep per entity, so a free row is always found; one past
        // them is let go of, as the engine's entry for the entity holds a count of its own.
        if let Some(free) = retained.iter_mut().find(|row| row.is_none()) {
            *free = Some(anchor);
        }
    }
}

#[cfg(all(test, feature = "engine-tokio"))]
mod tests {
    use super::*;

    use wz_capi_core::faces::SharedSession;
    use wz_capi_core::runtime::runtime_impl::TokioTime;
    use wz_node_time::node_clock::NodeHlc;

    /// The forms of an advanced subscriber on `key`, over a registry with no
    /// face: what they declare is read back from the registry's key table, which
    /// needs no peer.
    fn forms_on(key: &str) -> (Arc<SharedSession>, Box<AnchorRooms>, PicoSubscriberForms) {
        let shared = Arc::new(
            SharedSession::new(
                TokioTime::new(),
                [0x11; 16].into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        );
        let session = PicoSession {
            engine: shared.as_engine(),
            mode: WhatAmI::Peer,
            hlc: NodeHlc::default(),
            time: crate::last_timestamp::SessionTime::new(),
        };
        let rooms = Box::new(AnchorRooms::new());
        // SAFETY: the rooms are vacant, and each test keeps them past the forms and every anchor
        // they answer with (it binds them before both).
        let forms = unsafe {
            PicoSubscriberForms::new(
                &session,
                DeclaredKeyexpr::literal_only(key).expect("the test's heap"),
                NonNull::from(&*rooms),
                None,
            )
        };
        (shared, rooms, forms)
    }

    /// The keys the registry holds, in declaration order.
    fn declared(shared: &SharedSession) -> Vec<String> {
        shared
            .keyexpr_declarations()
            .into_iter()
            .map(|(_, key)| key)
            .collect()
    }

    const BASE: &str = "demo/kd/asub/**";

    /// An anchor lies in its entity's room: lodging it, counting it into an entity's form, copying
    /// that and letting every count go takes no memory, and the last count leaves the room vacant
    /// for the next anchor.
    ///
    /// # Control
    ///
    /// Lodging the anchor in a box of its own (`Strong::boxed`) counts one allocation; a
    /// `vacate` that does not mark the room vacant reds the second assertion.
    #[test]
    fn an_anchor_lies_in_its_room_and_takes_no_memory() {
        let rooms = AnchorRooms::new();
        let anchor = Anchor {
            key: DeclaredKeyexpr::literal_only(BASE).expect("the test's heap"),
            announced: DeclaredKeyexpr::literal_only(BASE).expect("the test's heap"),
        };
        let taken = crate::connectivity::tests::allocations(|| {
            // SAFETY: the room is vacant, lodged in by this thread alone, and the rooms outlive
            // every count taken here.
            let lodged = unsafe { rooms.lodge(Entity::Heartbeat, anchor, None) };
            let form = EntityForm::literal().keeping(Kept::lodged(lodged.clone()));
            let copy = form.clone();
            drop(lodged);
            drop(form);
            drop(copy);
        });
        assert_eq!(taken, 0, "the anchor and its counts take no memory");
        assert!(
            rooms.room(Entity::Heartbeat).vacant.load(Ordering::Acquire),
            "the last count gave the room back"
        );
    }
    const PUBLISHERS: &str = "demo/kd/asub/**/@adv/pub/**";
    const DETECTION: &str = "demo/kd/asub/**/@adv/sub/zid/7/_";

    /// Each entity declares the key its own entry point does, and the two that
    /// share a prefix share ONE key held twice, which goes with its last holder.
    ///
    /// The subscription and the heartbeat subscription both declare the
    /// non-wild prefix `demo/kd/asub`; the late-publisher subscription and the
    /// token declare their whole keys. Released in pico's order — subscription,
    /// late-publisher subscription, heartbeat subscription, token — the prefix
    /// outlives the subscription and goes with the heartbeat subscription.
    ///
    /// # Control
    ///
    /// Declaring the subscription's WHOLE key instead of its prefix reds the
    /// first assertion; letting each holder retract the key on its own release
    /// reds the second.
    #[test]
    fn each_entity_declares_its_own_key_and_a_shared_prefix_goes_with_its_last_holder() {
        let (shared, _rooms, forms) = forms_on(BASE);

        let subscription = forms.subscriber(BASE);
        let late = forms.late_publishers(PUBLISHERS);
        let heartbeat = forms.heartbeat(PUBLISHERS);
        let token = forms.token(DETECTION);
        assert_eq!(
            declared(&shared),
            vec!["demo/kd/asub", PUBLISHERS, DETECTION],
            "the subscription and the heartbeat subscription share the prefix; the other \
             two declare their whole keys"
        );

        drop(subscription);
        assert_eq!(
            declared(&shared).len(),
            3,
            "the prefix outlives the subscription: the heartbeat subscription still holds it"
        );
        drop(late);
        assert_eq!(declared(&shared), vec!["demo/kd/asub", DETECTION]);
        drop(heartbeat);
        assert_eq!(
            declared(&shared),
            vec![DETECTION],
            "the prefix goes with its last holder"
        );
        drop(token);
        assert!(declared(&shared).is_empty());
    }

    /// A face that asks about an entity another face already holds is answered
    /// with the same declaration, and the declaration is retracted when the last
    /// face lets go — one declaration per entity however many faces, which is
    /// pico's one session.
    ///
    /// Read as the number of holders of the answer: two faces holding one
    /// declaration is a count of two on it, where two declarations would be a
    /// count of one each.
    ///
    /// # Control
    ///
    /// Answering every face with a declaration of its own reds the holder count.
    #[test]
    fn a_second_face_shares_the_declaration_and_the_last_to_let_go_retracts_it() {
        let (shared, _rooms, forms) = forms_on(BASE);

        let first = forms.subscriber(BASE);
        let second = forms.subscriber(BASE);
        assert_eq!(declared(&shared), vec!["demo/kd/asub"], "one declaration");
        let held = forms.answered.lock()[Entity::Subscriber as usize]
            .as_ref()
            .and_then(WeakRef::upgrade)
            .expect("the answer stands");
        assert_eq!(
            Strong::strong_count(&held),
            3,
            "both faces hold the one declaration, and this read a third count"
        );
        drop(held);

        drop(first);
        assert_eq!(
            declared(&shared),
            vec!["demo/kd/asub"],
            "the declaration stands while a face holds an entity on it"
        );
        drop(second);
        assert!(
            declared(&shared).is_empty(),
            "and goes with the last face's entity"
        );
    }

    /// A declaration every face has let go of is made again for the next face
    /// that asks, rather than kept alive by the forms.
    ///
    /// # Control
    ///
    /// Holding the answer strongly in the forms keeps the key declared after the
    /// last face lets go, which reds the first assertion.
    #[test]
    fn a_declaration_every_face_let_go_of_is_made_again_for_the_next() {
        let (shared, _rooms, forms) = forms_on(BASE);

        drop(forms.subscriber(BASE));
        assert!(
            declared(&shared).is_empty(),
            "the forms keep nothing alive once every face has let go"
        );

        let _again = forms.subscriber(BASE);
        assert_eq!(declared(&shared), vec!["demo/kd/asub"]);
    }
}
