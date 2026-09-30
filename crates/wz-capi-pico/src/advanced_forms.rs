// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use std::sync::{Arc, Mutex, PoisonError, Weak};

use wz_capi_core::faces::SharedSession;
use wz_runtime_tokio::advanced_subscriber::{DeclarationForms, EntityForm};
use wz_runtime_tokio::session_glue::WhatAmI;

use crate::keyexpr::DeclaredKeyexpr;
use crate::write_filter::PicoSession;

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

/// The [`DeclarationForms`] of one C advanced subscriber.
pub(crate) struct PicoSubscriberForms {
    /// Weak, because the registry holds these forms (they are in the entry it
    /// replays) and a strong reference back is a session that can never end.
    shared: Weak<SharedSession>,
    mode: WhatAmI,
    /// The caller's key: declared when the caller's is, a literal otherwise.
    base: DeclaredKeyexpr,
    /// The declaration each entity stands on now, indexed by [`Entity`]. Held
    /// weakly: a face's entity holds it, the forms do not.
    answered: Mutex<[Weak<Anchor>; 4]>,
    /// Declarations handed over when a subscriber runs in the background.
    retained: Mutex<Vec<Arc<dyn Send + Sync>>>,
}

impl PicoSubscriberForms {
    /// The forms of an advanced subscriber on `base`, declared on `session`.
    pub(crate) fn new(session: &PicoSession, base: DeclaredKeyexpr) -> Self {
        Self {
            shared: Arc::downgrade(&session.shared),
            mode: session.mode,
            base,
            answered: Mutex::new([Weak::new(), Weak::new(), Weak::new(), Weak::new()]),
            retained: Mutex::new(Vec::new()),
        }
    }

    /// The declaration `entity` stands on: the one another face already holds,
    /// else a new one. `None` when the session cannot make it.
    fn anchor(
        &self,
        shared: &Arc<SharedSession>,
        entity: Entity,
        keyexpr: &str,
    ) -> Option<Arc<Anchor>> {
        // Held across the declaration, so two faces asking at once cannot both
        // declare: the second finds the first's answer.
        let mut answered = self.answered.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = answered[entity as usize].upgrade() {
            return Some(held);
        }
        // The key the entity's own derives from. The subscriber is on the
        // caller's; the rest are on keys built FROM it (`z_keyexpr_clone` then
        // an append, or `z_keyexpr_join`), which keep the caller's declaration
        // while they still begin with it.
        let carrier = match entity {
            Entity::Subscriber => self.base.share(),
            Entity::LatePublishers | Entity::Heartbeat | Entity::Token => {
                self.base.extended(keyexpr.to_owned())
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
                let announced = key.share();
                (key, announced)
            }
        };
        let anchor = Arc::new(Anchor { key, announced });
        answered[entity as usize] = Arc::downgrade(&anchor);
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
        let wire = anchor.announced.wire(&shared);
        let form = if wire.mapping_id == 0 {
            EntityForm::literal()
        } else {
            EntityForm::aliased(wire.mapping_id, wire.suffix)
        };
        let form = match entity {
            Entity::Subscriber | Entity::Heartbeat => {
                form.with_retraction_naming(anchor.key.retraction_naming_in(self.mode, &shared))
            }
            Entity::LatePublishers => form,
            Entity::Token => form.with_token_retraction_naming_the_key(true),
        };
        form.keeping(anchor)
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

    fn retain(&self, anchor: Arc<dyn Send + Sync>) {
        self.retained
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(anchor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use wz_runtime_tokio::node_clock::NodeHlc;
    use wz_runtime_tokio::runtime_impl::TokioTime;

    /// The forms of an advanced subscriber on `key`, over a registry with no
    /// face: what they declare is read back from the registry's key table, which
    /// needs no peer.
    fn forms_on(key: &str) -> (Arc<SharedSession>, PicoSubscriberForms) {
        let shared = Arc::new(
            SharedSession::new(TokioTime::new(), vec![0x11; 16]).expect("test host entropy"),
        );
        let session = PicoSession {
            shared: shared.clone(),
            mode: WhatAmI::Peer,
            hlc: NodeHlc::default(),
        };
        let forms =
            PicoSubscriberForms::new(&session, DeclaredKeyexpr::literal_only(key.to_owned()));
        (shared, forms)
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
        let (shared, forms) = forms_on(BASE);

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
        let (shared, forms) = forms_on(BASE);

        let first = forms.subscriber(BASE);
        let second = forms.subscriber(BASE);
        assert_eq!(declared(&shared), vec!["demo/kd/asub"], "one declaration");
        assert_eq!(
            forms.answered.lock().unwrap()[Entity::Subscriber as usize].strong_count(),
            2,
            "both faces hold the one declaration"
        );

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
        let (shared, forms) = forms_on(BASE);

        drop(forms.subscriber(BASE));
        assert!(
            declared(&shared).is_empty(),
            "the forms keep nothing alive once every face has let go"
        );

        let _again = forms.subscriber(BASE);
        assert_eq!(declared(&shared), vec!["demo/kd/asub"]);
    }
}
