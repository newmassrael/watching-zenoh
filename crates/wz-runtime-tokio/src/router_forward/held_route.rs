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
//! read off the message and no alias table is asked ([`HeldFaceContext`]).

use std::cell::OnceCell;

use super::face_runtime::{FaceRuntime, SendFace};
use super::*;
use wz_session_core::session_actions::EncodedPush;
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
/// Push. A lent one is the message the router received, which is copied only when a face is to
/// be sent a message of its own.
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
    pub(super) fn is_lent(&self) -> bool {
        matches!(self.0, Cow::Borrowed(_))
    }

    /// The key the Push names.
    #[cfg(test)]
    pub(super) fn keyexpr(&self) -> &str {
        literal_key(&self.0).expect("a literal Push names its key (LiteralPush::new)")
    }

    /// The message to send: the Push itself when this holds it, a copy when it is lent.
    pub(super) fn into_message(self) -> NetworkMessage {
        NetworkMessage::Push(Box::new(self.0.into_owned()))
    }

    /// The Push itself, to be read.
    pub(super) fn as_push(&self) -> &PushOwned {
        &self.0
    }
}

/// The carrier of one fan-out to the client faces, and the bytes it encodes to, made at most once
/// however many faces the fan-out reaches. Every face the carrier can be sent to as those bytes is
/// sent them; a face is handed a copy of the message only when it must hold it, send it another
/// way, or have it read by an interceptor.
pub(super) struct SharedCarrier<'a> {
    push: LiteralPush<'a>,
    encoded: OnceCell<EncodedPush>,
}

impl<'a> SharedCarrier<'a> {
    /// The fan-out of `push`, encoded by the first face that is sent the bytes.
    pub(super) fn new(push: LiteralPush<'a>) -> Self {
        Self {
            push,
            encoded: OnceCell::new(),
        }
    }

    /// The carrier, for a face that is sent a message of its own.
    pub(super) fn push(&self) -> &LiteralPush<'a> {
        &self.push
    }

    /// The carrier's bytes, encoded on the first call; `on_encode` runs then and on no other call.
    pub(super) fn encoded(&self, on_encode: impl FnOnce()) -> &EncodedPush {
        self.encoded.get_or_init(|| {
            on_encode();
            EncodedPush::of(self.push.as_push())
        })
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
    fn full_keyexpr(&self, msg: &NetworkMessage) -> Option<String> {
        match msg {
            NetworkMessage::Push(push) => literal_key(push).map(str::to_owned),
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
        assert_eq!(context.full_keyexpr(&literal).as_deref(), Some("demo/a"));
        assert_eq!(context.full_keyexpr(&aliased), None);
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
        assert_eq!(EncodedPush::of(&sent), EncodedPush::of(&literal));
        let owned = LiteralPush::new(literal.clone()).expect("a literal Push is taken");
        assert!(!owned.is_lent());
        let aliased = build_push_aliased(5, None, b"x").expect("build aliased push");
        assert!(LiteralPush::lent(&aliased).is_none());
    }

    /// The carrier is encoded on the first ask and on no other, and what every ask is handed is
    /// the Push's own encoding. Turned red by a carrier that encodes again for each face.
    #[test]
    fn a_shared_carrier_is_encoded_once_however_often_it_is_asked() {
        let push = build_push_literal("demo/a", b"x").expect("build literal push");
        let expected = EncodedPush::of(&push);
        let carrier = SharedCarrier::new(LiteralPush::new(push).expect("a literal Push is taken"));
        let encodes = std::cell::Cell::new(0usize);
        for _ in 0..3 {
            assert_eq!(
                carrier.encoded(|| encodes.set(encodes.get() + 1)),
                &expected
            );
        }
        assert_eq!(encodes.get(), 1, "one encode for three asks");
        assert_eq!(carrier.push().keyexpr(), "demo/a");
    }
}
