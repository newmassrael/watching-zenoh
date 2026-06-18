// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qc — the data-plane forwarding kernel: the `routing-routes` atom.
//!
//! [`crate::switchboard`] turns an inbound Push into a *local* statechart
//! event; the [`RouteTable`] here turns an inbound Push into *outbound Pushes
//! on the other peers' links* — a router's data plane. The
//! `routing-router` foundation ([`accept_loop`](../../wz_runtime_tokio/accept_loop/index.html))
//! binds once and *holds* N concurrent peer faces with no traffic between
//! them; this kernel is what makes a held face a *route*: a Put received on
//! face A is forwarded to every other face that has declared a matching
//! subscriber.
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh's dispatcher data-plane forward (zenoh 1.5.0,
//! `zenoh/src/net/routing`): a face's subscriptions live as
//! `Resource::session_ctxs[face].subs` (`dispatcher/resource.rs`), an inbound
//! Push routes via `route_data` -> `compute_data_route` to the set of faces
//! whose subscription matches (`hat/router/pubsub.rs`, `sub.matches(res)` =
//! keyexpr intersection), and each destination receives it through
//! `outface.primitives.send_push` (`dispatcher/pubsub.rs`). Here the per-face
//! subscription set is [`FaceRoute::subs`], the route computation is the
//! [`declared_intersects`](crate::declare) scan in
//! [`RouteTable::forward_push`] — the SAME matcher the destination's own
//! [`SubscriberRegistry`](crate::declare::subscriber) uses, so the router's
//! route decision and the endpoint's fire decision cannot diverge — and the
//! per-destination send is
//! [`SessionLinkActions::send_network_message`](crate::session_actions::SessionLinkActions::send_network_message),
//! the same transport send seam a session's own publish routes through, so the
//! forwarded Push is framed and SN-stamped by the *destination* face's own
//! outbound (exactly as zenoh's egress `Mux` re-frames a forwarded message).
//!
//! Divergence from zenoh (documented, not yet matched): zenoh caches a
//! computed `Route` on the resource and invalidates it on declaration change;
//! this kernel recomputes the destination set per Put (an O(faces x subs) scan).
//! Correct, but not zenoh's cached-route performance — a later increment can add
//! a per-keyexpr route cache if the scan ever shows up in a profile.
//!
//! ## Scope of this atom (literal keyexprs)
//!
//! A peer's default publish / declare path emits a **literal** keyexpr
//! (`WireexprLocal { id: 0, suffix }`, see `push_build` / `declare_build`).
//! This atom routes those: a subscription is keyed off the resolved literal,
//! and a Put with a literal keyexpr is matched and forwarded **verbatim** (the
//! cloned [`PushOwned`] is understood as-is by every destination, and all Put
//! metadata — payload, encoding, attachment — is preserved). The per-face
//! expr-id alias table ([`FaceRoute::peer_aliases`]) is the resolution seam
//! [`resolve_wireexpr`] consumes; it is empty in this atom (so a
//! DeclareKeyexpr-aliased `id != 0` keyexpr resolves to `None` and is not yet
//! routed) and is populated by the sibling alias increment, which also switches
//! [`forward_push`](RouteTable::forward_push) from verbatim to a re-literalized
//! rebuild (a destination that never saw face A's mapping cannot decode an
//! `id != 0` keyexpr). Keeping that one coupling explicit is why the alias
//! handling is deferred as a unit rather than split.
//!
//! ## NON-goals (this atom)
//!
//! Multi-hop declaration propagation (a router forwarding a peer's
//! DeclareSubscriber to the *other* peers so they gate their own emit — an
//! interest optimisation, not required for a single-hop star: a producer
//! sends its Put unconditionally and the router routes it), expr-id alias
//! resolution (above), zid-keyed mesh de-duplication (the `src != dst` skip
//! suffices for the star topology; a mesh needs source-zid suppression), and
//! Queryable / liveliness routing (Push only). Self-echo cannot occur: a face
//! never receives its own Put back (`src_id` is skipped).

#[cfg(all(feature = "alloc", feature = "routing-routes"))]
pub use imp::{FaceRoute, RouteTable};

#[cfg(all(feature = "alloc", feature = "routing-routes"))]
mod imp {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;
    use hashbrown::HashMap;

    use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
    use wz_codecs::push::PushOwned;
    use wz_runtime_core::TimeSource;

    use crate::declare::declared_intersects;
    use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
    use crate::link::SessionRuntime;
    use crate::network_message::NetworkMessage;
    use crate::session_actions::SessionLinkActions;
    use crate::wireexpr_resolve::resolve_wireexpr;
    use alloc::sync::Arc;

    /// One held peer face's routing state: the outbound send seam shared with
    /// the face's own session driver (so this kernel can forward TO the peer)
    /// plus the subscriptions it has declared.
    pub struct FaceRoute<R: SessionRuntime, T: TimeSource> {
        /// The face's transport send seam — an [`Arc`] clone of the same
        /// [`SessionLinkActions`] the face's driver holds. A forward is a
        /// [`SessionLinkActions::send_network_message`] call on this, so the
        /// Put is framed + SN-stamped on the destination face's own outbound.
        actions: Arc<SessionLinkActions<R, T>>,
        /// Declared subscriptions: the resolved keyexpr string, keyed by the
        /// wire subscriber id so an `UndeclareSubscriber` removes exactly the
        /// matching one. This is the SAME stored form as the destination's own
        /// [`SubscriberRegistry`](crate::declare::subscriber)`::declared`
        /// (id -> resolved keyexpr `String`), and the match below routes through
        /// the SAME [`declared_intersects`] SSOT that registry uses — so the
        /// router's route decision and the destination subscriber's fire
        /// decision are computed by one function and cannot disagree.
        subs: HashMap<u64, String>,
        /// Per-face expr-id -> literal-keyexpr alias table, the resolution
        /// context [`resolve_wireexpr`] consumes. Empty in this atom (only
        /// literal `id == 0` keyexprs resolve); the sibling alias increment
        /// populates it from inbound DeclareKeyexpr records. Per-face because
        /// each peer owns an independent expr-id namespace.
        peer_aliases: HashMap<u64, String>,
    }

    impl<R: SessionRuntime, T: TimeSource> FaceRoute<R, T> {
        fn new(actions: Arc<SessionLinkActions<R, T>>) -> Self {
            Self {
                actions,
                subs: HashMap::new(),
                peer_aliases: HashMap::new(),
            }
        }

        /// Does any of this face's subscriptions match `keyexpr`? Routes through
        /// [`declared_intersects`] — the exact matcher
        /// [`SubscriberRegistry::has_matching`](crate::declare::subscriber)
        /// uses — so keyexpr intersection (zenoh's `sub.matches(res)` semantics,
        /// symmetric pattern-vs-pattern), not a pattern-vs-literal shortcut.
        fn matches(&self, keyexpr: &str) -> bool {
            declared_intersects(&self.subs, keyexpr)
        }
    }

    /// The router's live routing table: the held faces keyed by the
    /// accept-loop [`FaceId`](../../wz_runtime_tokio/accept_loop/struct.FaceId.html)
    /// value. Single-task by construction (the accept loop holds every face on
    /// one `!Send` task, so the table is wrapped in `Rc<RefCell<…>>` by the
    /// tokio forwarder, never a `Mutex`) — mirroring
    /// [`crate::switchboard::SwitchboardRegistry`]'s `!Sync` contract.
    pub struct RouteTable<R: SessionRuntime, T: TimeSource> {
        faces: HashMap<u64, FaceRoute<R, T>>,
    }

    impl<R: SessionRuntime, T: TimeSource> Default for RouteTable<R, T> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<R: SessionRuntime, T: TimeSource> RouteTable<R, T> {
        /// A new, empty routing table.
        pub fn new() -> Self {
            Self {
                faces: HashMap::new(),
            }
        }

        /// Register a face that reached Established: its send seam enters the
        /// table so other faces can forward to it. Called from the accept
        /// loop's `FaceUp` handling with an [`Arc`] clone of the face's
        /// actions.
        pub fn add_face(&mut self, id: u64, actions: Arc<SessionLinkActions<R, T>>) {
            self.faces.insert(id, FaceRoute::new(actions));
        }

        /// Remove a face that left (peer Close / link loss): it can no longer
        /// be a destination, and its subscriptions are dropped with it. Called
        /// from the accept loop's `FaceDown` handling.
        pub fn remove_face(&mut self, id: u64) {
            self.faces.remove(&id);
        }

        /// Total subscriptions recorded across all faces — the witness the
        /// forwarder's `subscription_count()` passthrough exposes so a test can
        /// assert routing state directly (e.g. that an aliased declare was NOT
        /// recorded), distinct from the observable forward count.
        pub fn subscription_count(&self) -> usize {
            self.faces.values().map(|f| f.subs.len()).sum()
        }

        /// Observe one inbound iteration event from face `src_id`: record any
        /// subscription it declared and forward any Put it published to every
        /// other matching face. Returns the number of forwards emitted (0 for
        /// every non-Push, non-Declare event). The single ingress the tokio
        /// [`FaceForwarder`](../../wz_runtime_tokio/accept_loop/trait.FaceForwarder.html)
        /// threads each face's `drive_session_until_terminal` observer into.
        pub fn observe(&mut self, src_id: u64, event: IterationEvent<'_>) -> usize {
            let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
                messages, reliable, ..
            }) = event
            else {
                return 0;
            };
            let mut forwarded = 0;
            for message in messages {
                match message {
                    NetworkMessage::Declare(declare) => self.record_declare(src_id, declare),
                    NetworkMessage::Push(push) => {
                        forwarded += self.forward_push(src_id, push, *reliable)
                    }
                    _ => {}
                }
            }
            forwarded
        }

        /// Apply an inbound `Declare` from `src_id` to that face's routing
        /// state: a `DeclareSubscriber` adds a subscription, an
        /// `UndeclareSubscriber` removes the one with the matching id. Other
        /// declarations (Queryable / Token / Keyexpr) are not routed in this
        /// atom (see the module scope note).
        fn record_declare(&mut self, src_id: u64, declare: &DeclareOwned) {
            let Some(face) = self.faces.get_mut(&src_id) else {
                return;
            };
            match &declare.body {
                DeclareOwnedVariant::CodecZenohDeclSubscriber(sub) => {
                    // resolve_wireexpr returns an owned String, so the
                    // immutable borrow of `peer_aliases` ends before the
                    // mutable insert into `subs`. An unresolved (aliased,
                    // `id != 0`) keyexpr is dropped with a debug trace rather
                    // than silently — an operator can see why a route never
                    // formed (alias resolution is a later increment).
                    match resolve_wireexpr(&sub.keyexpr.body, &face.peer_aliases) {
                        Some(keyexpr) => {
                            face.subs.insert(sub.id, keyexpr);
                        }
                        None => log::debug!(
                            "RouteTable: face {src_id} declared subscriber id={} on an \
                             unresolved expr-id keyexpr; not recorded (alias resolution \
                             is a later increment)",
                            sub.id
                        ),
                    }
                }
                DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl) => {
                    face.subs.remove(&undecl.id);
                }
                _ => {}
            }
        }

        /// Forward a Put received on `src_id` to every OTHER face whose
        /// subscriptions match its keyexpr. Returns the number of forwards
        /// that the destination send seam accepted.
        fn forward_push(&self, src_id: u64, push: &PushOwned, reliable: bool) -> usize {
            // Resolve the source keyexpr in the source face's alias context.
            // In this atom only a literal (`id == 0`) keyexpr resolves; an
            // aliased one yields None and is not routed yet (module scope).
            let Some(src) = self.faces.get(&src_id) else {
                return 0;
            };
            let Some(keyexpr) = resolve_wireexpr(&push.keyexpr.body, &src.peer_aliases) else {
                log::debug!(
                    "RouteTable: face {src_id} published on an unresolved expr-id keyexpr; \
                     not forwarded (alias resolution is a later increment)"
                );
                return 0;
            };
            // Collect matching destinations first (cloning the Arc send seams)
            // so the table borrow is released before any send — a send only
            // enqueues on the destination's outbound channel and never
            // re-enters the table, but collecting keeps the borrow scope
            // obviously non-overlapping.
            let targets: Vec<Arc<SessionLinkActions<R, T>>> = self
                .faces
                .iter()
                .filter(|(id, _)| **id != src_id)
                .filter(|(_, face)| face.matches(&keyexpr))
                .map(|(_, face)| face.actions.clone())
                .collect();
            let mut count = 0;
            for actions in &targets {
                // Forward verbatim: the source keyexpr is literal, so the
                // cloned Push is decodable by every destination as-is, and the
                // destination's own send seam mints the frame SN. `express` so
                // an open batch window flushes (deliver-now forward).
                let forwarded = NetworkMessage::Push(Box::new(push.clone()));
                if actions
                    .send_network_message(forwarded, reliable, true)
                    .is_ok()
                {
                    count += 1;
                }
            }
            count
        }
    }
}
