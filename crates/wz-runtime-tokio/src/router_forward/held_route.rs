// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A client leg's route that holds its faces, and the one message it may send through them.
//!
//! A route named its faces by id and every delivery found each in the version's face table, a
//! walk of the persistent map that cost a delivery 7 to 15 times what reading held state does
//! (`docs/router-table-snapshots.md`, section 6.9). Upstream's route holds each face's state
//! (`zenoh/src/net/routing/dispatcher/resource.rs` @ `pub(crate) dst_face: Arc<FaceState>,`).
//! A route outlives the version it was computed from, so what it holds of a face must not change
//! while the face is up, and what can change must not be read through it. [`HeldFace`] holds the
//! face's id, tier, routing zid and runtime, all fixed from `register` to `deregister`, which
//! closes the runtime ([`FaceRuntime::close`]); a send through a closed runtime is skipped.
//!
//! The one fact of a face a send could read that changes while it is up is its aliases
//! (`RouterFaceState::keyexpr_table`, moved by the face's own alias declarations). A send reads
//! them only to resolve the message's key, for the egress interceptors and their verdict cache. A
//! held route sends only a [`LiteralPush`], whose key is a literal by construction, so its key is
//! read off the message and no alias table is asked ([`HeldFaceContext`]), or the bytes of one
//! ([`SharedCarrier`]).

use std::cell::OnceCell;
use std::sync::Weak;

use super::face_runtime::{FaceRuntime, SendFace};
use super::*;
use wz_session_core::encoded_push::{EncodedPush, LeafPush};
use wz_session_core::wireexpr_resolve::id_and_suffix;

/// One face of a client leg's route: what the router holds of it that is fixed while it is up.
#[derive(Clone)]
pub(super) struct HeldFace {
    pub(super) id: FaceId,
    pub(super) tier: Region,
    peer_zid: Option<Zid>,
    runtime: Arc<FaceRuntime>,
}

impl HeldFace {
    /// Face `id` as `state` holds it in the version a route is computed from.
    pub(super) fn of(id: FaceId, state: &RouterFaceState) -> Self {
        Self {
            id,
            tier: state.tier,
            peer_zid: state.peer_zid,
            runtime: Arc::clone(&state.runtime),
        }
    }

    /// What a send to the face reads of it.
    pub(super) fn send_face(&self) -> SendFace<'_> {
        SendFace {
            runtime: &self.runtime,
            peer_zid: self.peer_zid,
        }
    }

    /// Whether the face has left the tables since the route was computed.
    pub(super) fn is_closed(&self) -> bool {
        self.runtime.is_closed()
    }
}

/// The key of `push` when its key expression is a literal: id 0, the key in its suffix. Read
/// without any alias table, which a literal needs none of.
fn literal_key(push: &PushOwned) -> Option<&str> {
    match id_and_suffix(&push.keyexpr.body) {
        (0, suffix) => suffix,
        _ => None,
    }
}

/// A Push whose key expression is a literal, so that sending it to a face needs none of the face's
/// aliases. Made only by [`LiteralPush::new`] and [`LiteralPush::lent`], which refuse any other
/// Push, and lent again by [`LiteralPush::borrowed`]. A lent one is the message the router
/// received, or the copy a fan-out made of it, which is copied only when a face is to be sent a
/// message of its own.
#[derive(Clone)]
pub(super) struct LiteralPush<'a>(Cow<'a, PushOwned>);

impl LiteralPush<'static> {
    /// `push` as a literal Push, or `None` when its key expression names an alias or no key. The
    /// caller has no use for a Push refused, so it is dropped rather than handed back.
    pub(super) fn new(push: PushOwned) -> Option<Self> {
        literal_key(&push)
            .is_some()
            .then_some(Self(Cow::Owned(push)))
    }
}

impl<'a> LiteralPush<'a> {
    /// `push` itself as a literal Push, lent and not copied, or `None` as [`Self::new`] refuses.
    pub(super) fn lent(push: &'a PushOwned) -> Option<Self> {
        literal_key(push)
            .is_some()
            .then_some(Self(Cow::Borrowed(push)))
    }

    /// Whether this is a message the router holds as it was handed it, and not a copy.
    #[cfg(test)]
    pub(super) fn is_lent(&self) -> bool {
        matches!(self.0, Cow::Borrowed(_))
    }

    /// The key the Push names.
    #[cfg(test)]
    pub(super) fn keyexpr(&self) -> &str {
        literal_key(&self.0).expect("a literal Push names its key (LiteralPush::new)")
    }

    /// The Push lent, so that a send copies it only into the message it makes.
    pub(super) fn borrowed(&self) -> LiteralPush<'_> {
        LiteralPush(Cow::Borrowed(&*self.0))
    }

    /// The message to send: the Push itself when this holds it, a copy when it is lent.
    pub(super) fn into_message(self) -> NetworkMessage {
        NetworkMessage::Push(Box::new(self.0.into_owned()))
    }

    /// The Push itself, to be read.
    #[cfg(test)]
    pub(super) fn as_push(&self) -> &PushOwned {
        &self.0
    }
}

/// The carrier of one fan-out to the client faces: the Put the router received, as a client is
/// sent it, under its key as a literal and naming no routing source, since a client is a leaf and
/// refuses a Push that names a source (`deliver_to_client_subscribers`).
///
/// It is made of the received Put without a copy. The bytes every face that can be sent them is
/// sent are written from it once, however many faces the fan-out reaches, re-keyed and without
/// the source as they are written ([`LeafPush::encode`]); upstream builds each destination's Push
/// from the key form of the route's direction and a reference to the payload
/// (`zenoh/src/net/routing/dispatcher/pubsub.rs` @ `payload: msg.payload.clone(),`). The message is
/// made only for a face that must hold it, send it another way, or have it read by an
/// interceptor: the Put itself, lent, for a literal that names no source, and otherwise a copy,
/// re-keyed and its source reset, made once for the fan-out.
///
/// What it holds of its own has no lifetime, so that a carrier made for a longer borrow can be
/// lent for a shorter one, as a fan-out lends it to one region's faces at a time.
pub(super) struct SharedCarrier<'a> {
    leaf: LeafPush<'a>,
    as_received: bool,
    copy: OnceCell<Option<LiteralPush<'static>>>,
    encoded: OnceCell<EncodedPush>,
}

impl<'a> SharedCarrier<'a> {
    /// The fan-out of `received` under `keyexpr`, the key the router resolved it to. `None` for a
    /// key no literal carries, which drops the Put for every client.
    pub(super) fn new(received: &'a PushOwned, keyexpr: &'a str) -> Option<Self> {
        let leaf = LeafPush::new(received, keyexpr).ok()?;
        Some(Self {
            leaf,
            as_received: leaf.is_as_received(),
            copy: OnceCell::new(),
            encoded: OnceCell::new(),
        })
    }

    /// The Put as the router received it: what a send reads of the carrier besides its key and
    /// its source, which the carrier keeps of it (its QoS, its payload, its timestamp).
    pub(super) fn received(&self) -> &'a PushOwned {
        self.leaf.received()
    }

    /// The carrier as a message, lent, for a face that is sent one of its own: the received Put,
    /// or the copy made on the first call, when `on_copy` runs, and lent on every later one.
    /// `None` when the copy cannot be made, which the key [`Self::new`] took leaves no cause for.
    pub(super) fn message(&self, on_copy: impl FnOnce()) -> Option<LiteralPush<'_>> {
        if self.as_received {
            return LiteralPush::lent(self.leaf.received());
        }
        let copy = self.copy.get_or_init(|| {
            on_copy();
            let made = self.leaf.to_push();
            if let Err(err) = &made {
                log::debug!("forward: DROP a Push for a client face, its copy failed: {err:?}");
            }
            LiteralPush::new(made.ok()?)
        });
        copy.as_ref().map(LiteralPush::borrowed)
    }

    /// The carrier's bytes, encoded on the first call; `on_encode` runs then and on no other call.
    pub(super) fn encoded(&self, on_encode: impl FnOnce()) -> &EncodedPush {
        self.encoded.get_or_init(|| {
            on_encode();
            self.leaf.encode()
        })
    }
}

/// The client legs a face's Puts that named one of its aliases with no suffix were routed by, kept
/// on the face by the alias's id: a Put that names the alias again is routed by them without its
/// key being looked up by its text, as upstream reaches the route of a Put through the resource
/// its mapping names (`zenoh/src/net/routing/dispatcher/face.rs` @
/// `Mapping::Sender => self.remote_mappings.get(prefixid),`). The face is given an empty one
/// whenever its aliases change, so a leg is only ever kept for the key its alias names now.
///
/// A leg is kept with the memo of the client routes it was read from, and served only while the
/// tables hold that same memo: every change that can move the leg (a subscriber of the region
/// declared or withdrawn, a face that leaves) gives the tables another memo
/// ([`bring_client_routes`](crate::linkstate_forward::bring_client_routes)). The memo is held
/// weakly, so a leg keeps none of its routes alive, and its address cannot be another memo's
/// while the leg is kept.
///
/// Only the face's own thread routes its Puts, so the lock is not contended.
#[derive(Default)]
pub(super) struct AliasRoutes {
    legs: PlainMutex<hashbrown::HashMap<u64, Vec<AliasLeg>>>,
}

/// The leg of one client region kept for an alias ([`AliasRoutes`]).
struct AliasLeg {
    region: Region,
    memo: Weak<HeldClientRoutes>,
    route: Arc<[HeldFace]>,
}

impl AliasRoutes {
    /// The leg of `region` kept for the alias `id`, when it was read from `memo`.
    pub(super) fn get(
        &self,
        id: u64,
        region: Region,
        memo: &Arc<HeldClientRoutes>,
    ) -> Option<Arc<[HeldFace]>> {
        let legs = self.legs.guard();
        legs.get(&id)?
            .iter()
            .find(|leg| leg.region == region && std::ptr::eq(leg.memo.as_ptr(), Arc::as_ptr(memo)))
            .map(|leg| Arc::clone(&leg.route))
    }

    /// Keep `route`, read from `memo`, as the leg of `region` for the alias `id`, in place of the
    /// one it held for that region.
    pub(super) fn keep(
        &self,
        id: u64,
        region: Region,
        memo: &Arc<HeldClientRoutes>,
        route: &Arc<[HeldFace]>,
    ) {
        let leg = AliasLeg {
            region,
            memo: Arc::downgrade(memo),
            route: Arc::clone(route),
        };
        let mut legs = self.legs.guard();
        let legs = legs.entry(id).or_default();
        match legs.iter_mut().find(|held| held.region == region) {
            Some(held) => *held = leg,
            None => legs.push(leg),
        }
    }
}

/// The egress interceptors' view of a face reached through a held route: its fixed facts, and the
/// key of the message read off the message itself, which a held route only sends as a literal.
pub(super) struct HeldFaceContext<'a> {
    face: SendFace<'a>,
}

impl<'a> HeldFaceContext<'a> {
    pub(super) fn new(face: SendFace<'a>) -> Self {
        Self { face }
    }
}

impl InterceptorContext for HeldFaceContext<'_> {
    fn subject(&self) -> Option<Zid> {
        self.face.peer_zid
    }

    fn link_subject(&self) -> Option<&LinkSubject> {
        self.face.runtime.actions.link_subject()
    }

    fn username(&self) -> Option<String> {
        peer_acl_username(&self.face.runtime.actions)
    }

    /// A literal Push's key, and `None` for anything else, which a governed kind is denied on: no
    /// alias table is read, because none of this face's aliases can name what a held route sends.
    fn full_keyexpr(&self, msg: MessageRef<'_>) -> Option<String> {
        match msg {
            MessageRef::Push(push) => literal_key(push).map(str::to_owned),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::push_build::{build_push_aliased, build_push_literal};

    /// A Push that names an alias is refused; a literal one is taken and names its key. Turned red
    /// by a `LiteralPush` made of a Push whose key needs an alias table.
    #[test]
    fn a_literal_push_is_only_made_of_a_push_with_a_literal_key() {
        let aliased = build_push_aliased(5, None, b"x").expect("build aliased push");
        assert_eq!(id_and_suffix(&aliased.keyexpr.body), (5, None));
        assert!(
            LiteralPush::new(aliased).is_none(),
            "a Push naming an alias is refused"
        );
        let literal = build_push_literal("demo/a", b"x").expect("build literal push");
        let Some(taken) = LiteralPush::new(literal) else {
            panic!("a literal Push is taken");
        };
        assert_eq!(taken.keyexpr(), "demo/a");
    }

    /// The held context reads a literal Push's key off the message, and answers no key for a Push
    /// whose key would need the face's aliases, which a governed kind is denied on: it reads no
    /// alias table. Its subject is the zid it holds. Turned red by a held context that resolves an
    /// alias, or that loses a literal's key.
    #[test]
    fn the_held_context_reads_a_literal_key_and_no_alias() {
        let (actions, _sink) = crate::test_fixtures::recording_actions();
        let runtime = FaceRuntime::new(actions);
        let peer = Zid::from_slice(&[7, 7, 7, 7]);
        let context = HeldFaceContext::new(SendFace {
            runtime: &runtime,
            peer_zid: Some(peer),
        });
        let message = |push: PushOwned| NetworkMessage::Push(Box::new(push));
        let literal = message(build_push_literal("demo/a", b"x").expect("build literal push"));
        let aliased = message(build_push_aliased(5, None, b"x").expect("build aliased push"));
        assert_eq!(
            context.full_keyexpr(literal.view()).as_deref(),
            Some("demo/a")
        );
        assert_eq!(context.full_keyexpr(aliased.view()), None);
        assert_eq!(context.subject(), Some(peer));
    }

    /// A literal Push is lent as it is, and is copied only into the message a face is sent; a Push
    /// that names an alias is not lent. Turned red by a lent carrier that is a copy, or one made of
    /// a Push whose key needs an alias table.
    #[test]
    fn a_literal_push_is_lent_and_copied_only_into_a_message() {
        let literal = build_push_literal("demo/a", b"x").expect("build literal push");
        let lent = LiteralPush::lent(&literal).expect("a literal Push is lent");
        assert!(lent.is_lent());
        assert!(std::ptr::eq(lent.as_push(), &literal), "the Push itself");
        let NetworkMessage::Push(sent) = lent.clone().into_message() else {
            panic!("a lent Push is sent as a Push");
        };
        assert_eq!(sent.encode_to_vec(), literal.encode_to_vec());
        let owned = LiteralPush::new(literal.clone()).expect("a literal Push is taken");
        assert!(!owned.is_lent());
        let aliased = build_push_aliased(5, None, b"x").expect("build aliased push");
        assert!(LiteralPush::lent(&aliased).is_none());
    }

    /// A leg kept for an alias is served for that alias and region only while it is asked with the
    /// memo it was read from, and a leg kept again for the region takes the place of the one
    /// before. Turned red by a leg served from another memo, region or alias.
    #[test]
    fn an_alias_leg_is_served_only_with_the_memo_it_was_read_from() {
        let routes = AliasRoutes::default();
        let memo = Arc::new(HeldClientRoutes::indexed());
        let other = Arc::new(HeldClientRoutes::indexed());
        let first: Arc<[HeldFace]> = Arc::from([]);
        let second: Arc<[HeldFace]> = Arc::from([]);
        assert!(
            routes.get(5, Region::Local, &memo).is_none(),
            "nothing kept"
        );
        routes.keep(5, Region::Local, &memo, &first);
        let served = routes.get(5, Region::Local, &memo).expect("the leg kept");
        assert!(Arc::ptr_eq(&served, &first));
        assert!(
            routes.get(5, Region::Local, &other).is_none(),
            "another memo"
        );
        assert!(
            routes.get(5, NORTH_REGION, &memo).is_none(),
            "another region"
        );
        assert!(
            routes.get(6, Region::Local, &memo).is_none(),
            "another alias"
        );
        routes.keep(5, Region::Local, &other, &second);
        assert!(
            routes.get(5, Region::Local, &memo).is_none(),
            "the leg read from the memo before was replaced"
        );
        let served = routes.get(5, Region::Local, &other).expect("the leg kept");
        assert!(Arc::ptr_eq(&served, &second));
    }

    /// The carrier is encoded on the first ask and on no other, and what every ask is handed is
    /// the encoding of the Push a client is sent. Turned red by a carrier that encodes again for
    /// each face.
    #[test]
    fn a_shared_carrier_is_encoded_once_however_often_it_is_asked() {
        let push = build_push_literal("demo/a", b"x").expect("build literal push");
        let carrier = SharedCarrier::new(&push, "demo/a").expect("a literal key");
        let encodes = std::cell::Cell::new(0usize);
        for _ in 0..3 {
            assert_eq!(
                carrier
                    .encoded(|| encodes.set(encodes.get() + 1))
                    .as_bytes(),
                &push.encode_to_vec()[..]
            );
        }
        assert_eq!(encodes.get(), 1, "one encode for three asks");
    }

    /// An aliased Put's carrier is encoded under the key it was given, as a literal, without a copy
    /// of the Put; the message is copied, re-keyed, only when a face asks for one, and once for
    /// every face that asks. A literal that names no source is lent as it came and never copied.
    /// Turned red by a carrier that copies the Put to encode it, copies it again for a second face,
    /// or copies a Put that needs no change.
    #[test]
    fn an_aliased_carrier_is_copied_only_for_a_face_sent_a_message_of_its_own() {
        let aliased = build_push_aliased(5, None, b"x").expect("build aliased push");
        let expected = build_push_literal("demo/a", b"x").expect("build literal push");
        let carrier = SharedCarrier::new(&aliased, "demo/a").expect("a literal key");
        let copies = std::cell::Cell::new(0usize);
        assert_eq!(
            carrier.encoded(|| {}).as_bytes(),
            &expected.encode_to_vec()[..],
            "the bytes are the literal's"
        );
        assert_eq!(copies.get(), 0, "no copy to encode");
        for _ in 0..3 {
            let message = carrier
                .message(|| copies.set(copies.get() + 1))
                .expect("a message");
            assert_eq!(message.keyexpr(), "demo/a");
            assert!(!std::ptr::eq(message.as_push(), &aliased), "a copy");
        }
        assert_eq!(copies.get(), 1, "one copy for three faces");
        let literal = build_push_literal("demo/a", b"x").expect("build literal push");
        let lent = SharedCarrier::new(&literal, "demo/a").expect("a literal key");
        let message = lent
            .message(|| copies.set(copies.get() + 1))
            .expect("a message");
        assert!(message.is_lent());
        assert!(std::ptr::eq(message.as_push(), &literal), "the Put itself");
        assert_eq!(copies.get(), 1, "no copy of a literal");
    }
}
