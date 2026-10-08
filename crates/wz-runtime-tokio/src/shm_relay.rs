// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! transport-shm -- what a node that FORWARDS a message holds while it routes it.
//!
//! A router that receives a Put whose payload is a shared-memory descriptor does not own the
//! chunk; the publisher's provider does, and the descriptor carries ONE reference taken for the
//! router as its receiver. Upstream's router maps the buffer when the message arrives, writes it
//! again to each link it routes it to (a descriptor with a reference of its own for a link whose
//! peer reads the chunk's protocol, the bytes for any other), and lets the buffer go when the
//! message has been routed
//! (`io/zenoh-transport/src/common/shm/interop.rs` @ `pub fn map_zmsg_to_shmbuf(` on the way in
//! and `pub fn map_zmsg_to_partner<` on the way out).
//!
//! [`ShmRelay`] is that, split where wz's pieces are: [`ShmRelay::open`] holds the chunk of every
//! shared-memory slice of the message about to be routed and returns a [`RelayPass`]; for as long
//! as the pass lives the faces the message is routed to ask [`ShmRelayHolds::held`] for the chunk
//! a descriptor names and send it on by
//! `SessionActions::send_network_message_relayed`; when the pass drops, the references the
//! message arrived with go back, once each. Every descriptor a face sent on carries a reference
//! of its own, so the count a chunk ends a routing pass with is the number of receivers it was
//! sent to, which is what each of them releases.
//!
//! A forwarder that sent the received descriptor on as it came would be sending a reference
//! nobody took: with one receiver the count balances by luck, and with two the second release
//! wraps upstream's plain `fetch_sub` (`commons/zenoh-shm/src/lib.rs` @
//! `unsafe fn dec_ref_count(&self) {`) and the chunk never returns to its provider's pool.

use std::sync::{Arc, Mutex};

use wz_session_core::extshm::{
    decode_shm_descriptor, ShmDescriptor, ShmRelayHolds, ShmResolver, ShmSendHandle,
};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::put_payload::{layout, slice_kind, PutPayload, SLICE_KIND_SHM_PTR};
use wz_session_core::qos::Priority;
use wz_session_core::wire::{PushOwned, PushOwnedVariant};

use crate::session_glue::SessionLinkActions;
use crate::shm_provider::PosixShmResolver;

/// The chunks a forwarder holds for the message it is routing, and the means of holding them.
pub struct ShmRelay {
    resolver: Arc<dyn ShmResolver + Send + Sync>,
    /// The chunks of the passes in progress, oldest first. A pass owns the tail it added.
    held: Mutex<Vec<(ShmDescriptor, ShmSendHandle)>>,
}

impl ShmRelay {
    /// A relay that holds chunks through `resolver`.
    pub fn new(resolver: Arc<dyn ShmResolver + Send + Sync>) -> Self {
        Self {
            resolver,
            held: Mutex::new(Vec::new()),
        }
    }

    /// A relay over the built-in POSIX reader: the one a node that maps POSIX chunks runs.
    pub fn posix() -> Self {
        Self::new(Arc::new(PosixShmResolver))
    }

    /// The serialized descriptor of every shared-memory slice of `push`'s payload, in order. Empty
    /// for a message that carries none, which is nearly every message.
    pub fn shm_slices(push: &PushOwned) -> Vec<&[u8]> {
        let PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
            return Vec::new();
        };
        match layout(put) {
            PutPayload::Inline(_) => Vec::new(),
            PutPayload::Sliced(slices) => slices
                .iter()
                .filter(|slice| slice_kind(slice.kind) == SLICE_KIND_SHM_PTR)
                .map(|slice| sce_forge_runtime::codec::SceByteBuf::as_slice(&slice.bytes))
                .collect(),
        }
    }

    /// Open a routing pass for `push`: hold the chunk each of its shared-memory slices names.
    ///
    /// `may_hold` is asked ONCE, and only when the message carries a shared-memory slice, whether
    /// the link it arrived on negotiated shared memory; `false` refuses the message (`None`) and
    /// opens nothing, because a descriptor from a link that never negotiated is a peer naming a
    /// segment it had no right to name. A message with no such slice opens an empty pass without
    /// asking and without taking the lock, which is nearly every message.
    ///
    /// EVERY slice is offered to the resolver, in order, whatever became of the ones before it,
    /// because a slice that is not offered is a reference nobody gives back. A slice whose chunk
    /// cannot be held (a descriptor that does not parse, a stale or foreign segment) is simply not
    /// in the pass, and a face that is asked for it is answered `None`, which is how the message
    /// comes to be dropped and not sent on as bytes of a descriptor.
    pub fn open(&self, push: &PushOwned, may_hold: impl FnOnce() -> bool) -> Option<RelayPass<'_>> {
        let slices = Self::shm_slices(push);
        if slices.is_empty() {
            return Some(RelayPass {
                relay: self,
                start: 0,
                slices: 0,
            });
        }
        if !may_hold() {
            return None;
        }
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let start = held.len();
        for bytes in &slices {
            if let Some(descriptor) = decode_shm_descriptor(bytes) {
                if let Some(chunk) = self.resolver.hold(&descriptor) {
                    held.push((descriptor, chunk));
                }
            }
        }
        Some(RelayPass {
            relay: self,
            start,
            slices: slices.len(),
        })
    }
}

impl ShmRelay {
    /// Rewrite `push` so that no slice of its payload is a descriptor: each becomes the bytes of
    /// the chunk the pass holds for it, and a Put left with no shared-memory slice is the plain
    /// layout without the marker. For an egress whose receivers can never read a chunk, such as a
    /// multicast group, which negotiates nothing and so is sent bytes whatever a unicast peer
    /// would have been. Takes no reference: nothing is sent that names the chunk.
    ///
    /// `Err` when a descriptor names a chunk the pass holds nothing for; `push` is then untouched
    /// and is not to be sent.
    pub fn into_plain_bytes(
        &self,
        push: &mut PushOwned,
    ) -> Result<(), wz_session_core::put_payload::RelayFault> {
        use wz_session_core::put_payload::{relay_shm_slices, Relayed};
        let PushOwnedVariant::CodecZenohMsgPut(put) = &mut push.body else {
            return Ok(());
        };
        relay_shm_slices(put, |descriptor| {
            let held = self.held(&decode_shm_descriptor(descriptor)?)?;
            Some(Relayed::Bytes(held.bytes().to_vec()))
        })
    }
}

/// What came of sending one message to one face through [`ShmRelay::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySend {
    /// The message left for the face.
    Sent,
    /// A descriptor in the message names a chunk the pass holds nothing for, so nothing was sent:
    /// upstream drops such a message when it is received.
    Dropped,
    /// The face's link refused the message.
    Failed,
}

impl ShmRelay {
    /// Open the pass for a Push that arrived on the face whose session is `actions` (`None` is a
    /// face this forwarder holds no session for, the multicast ingress among them), and
    /// acknowledge each of its shared-memory slices to the sender, as upstream's receiving
    /// transport does once it has mapped them.
    ///
    /// `None` is a Push that carries a descriptor and arrived on a face that never negotiated
    /// shared memory: it is not routed. The acknowledgement is the forwarder's to give because it
    /// has no registry to read the slices, and it goes through the face's own handoff, which holds
    /// none once a registry has taken it, so a slice is never acknowledged twice. A build with the
    /// chunks and no authenticator exchange (no `session-extshm`) has nothing to acknowledge
    /// through.
    pub fn open_inbound(
        &self,
        actions: Option<&SessionLinkActions>,
        push: &PushOwned,
    ) -> Option<RelayPass<'_>> {
        let pass = self.open(push, || actions.is_some_and(|actions| actions.is_shm()))?;
        #[cfg(feature = "session-extshm")]
        if let Some(actions) = actions {
            let band = wz_session_core::put_payload::priority_band(
                push.extensions.as_deref().unwrap_or(&[]),
            );
            for _ in 0..pass.slices() {
                actions.acknowledge_shm_slice(band);
            }
        }
        Some(pass)
    }

    /// Send `msg`, a message this forwarder is routing, to the face whose session is `actions`,
    /// with the shared-memory slices of its payload mapped for what that face's peer can read.
    /// The send of every forwarder's egress, so no message with a descriptor in it leaves without
    /// a reference taken for its receiver (see the module doc).
    pub fn send(
        &self,
        actions: &SessionLinkActions,
        msg: NetworkMessage,
        reliable: bool,
        express: bool,
        priority: Priority,
    ) -> RelaySend {
        match actions.send_network_message_relayed(msg, reliable, express, priority, self) {
            Ok(true) => RelaySend::Sent,
            Ok(false) => RelaySend::Dropped,
            Err(_) => RelaySend::Failed,
        }
    }
}

impl ShmRelayHolds for ShmRelay {
    fn held(&self, descriptor: &ShmDescriptor) -> Option<ShmSendHandle> {
        let held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        held.iter()
            .rev()
            .find(|(held, _)| held == descriptor)
            .map(|(_, chunk)| chunk.clone())
    }
}

/// A routing pass: the chunks of one message, held until it has been routed.
#[must_use = "a pass that is dropped at once holds nothing while the message is routed"]
pub struct RelayPass<'a> {
    relay: &'a ShmRelay,
    start: usize,
    slices: usize,
}

impl RelayPass<'_> {
    /// How many shared-memory slices the message carried, held or not: the number of
    /// acknowledgements its sender is owed.
    pub fn slices(&self) -> usize {
        self.slices
    }
}

impl Drop for RelayPass<'_> {
    fn drop(&mut self) {
        if self.slices == 0 {
            return;
        }
        // Take the chunks out under the lock and drop them outside it: a drop releases a
        // reference, which is a write to a header in another process's segment.
        let released: Vec<_> = {
            let mut held = self.relay.held.lock().unwrap_or_else(|e| e.into_inner());
            let start = self.start.min(held.len());
            held.split_off(start)
        };
        drop(released);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::shm_provider::{reference_state, ReferenceState, ShmBackedPayload};
    use wz_session_core::metadata::PushMetadata;
    use wz_session_core::push_build::build_push_shm_literal;

    /// A descriptor sent the way a publisher sends one: the reference is taken for the receiver and
    /// the owner then lets go of its own, so the one reference left is the receiver's.
    fn sent_by_a_publisher(len: usize) -> (ShmDescriptor, PushOwned) {
        let payload = ShmBackedPayload::alloc(len).expect("alloc");
        let wire = payload.wire_reference();
        let descriptor = wire.descriptor();
        wire.commit();
        let push = build_push_shm_literal("demo/relay", &descriptor, &PushMetadata::default())
            .expect("a Push that carries the descriptor");
        drop(payload);
        (descriptor, push)
    }

    /// The references the chunk's header holds. A chunk the provider has already collected has
    /// none: its collector runs on its own clock and may take the chunk home the moment the last
    /// holder lets go, so `Reclaimed` and `Held(0)` are the same fact and a test must not depend on
    /// which of them it happens to see. A count above zero is never read as reclaimed, so a
    /// reference given back too early still shows.
    fn held_count(descriptor: &ShmDescriptor) -> u32 {
        match reference_state(descriptor).expect("the provider's segment is open") {
            ReferenceState::Held(count) => count,
            ReferenceState::Reclaimed => 0,
        }
    }

    /// The message carries exactly the slices it was built with, and a message that carries none
    /// opens an empty pass.
    #[test]
    fn a_pass_counts_the_shared_memory_slices_of_its_message() {
        let (_, push) = sent_by_a_publisher(64);
        let relay = ShmRelay::posix();
        let pass = relay.open(&push, || true).expect("opened");
        assert_eq!(pass.slices(), 1, "one chunk, one slice");

        let inline = wz_session_core::push_build::build_push_literal_with_meta(
            "demo/relay",
            b"bytes",
            &PushMetadata::default(),
        )
        .expect("an inline Push");
        assert_eq!(
            relay
                .open(&inline, || panic!("an inline Push asks nobody"))
                .expect("opened")
                .slices(),
            0,
            "an inline Push holds nothing"
        );
    }

    /// A pass holds the chunk its message names for as long as it lives, and answers `None` for it
    /// before and after.
    #[test]
    fn a_chunk_is_held_exactly_while_its_pass_lives() {
        let (descriptor, push) = sent_by_a_publisher(64);
        let relay = ShmRelay::posix();
        assert!(relay.held(&descriptor).is_none(), "no pass is open yet");
        {
            let _pass = relay.open(&push, || true).expect("opened");
            assert!(
                relay.held(&descriptor).is_some(),
                "the pass holds the chunk"
            );
        }
        assert!(relay.held(&descriptor).is_none(), "the pass has ended");
    }

    /// THE ACCOUNT. The publisher's descriptor carries one reference; the pass takes it over and a
    /// reservation per receiver adds one. After the pass the count is the number of receivers, and
    /// when each releases it, the chunk is back at zero for its provider to collect.
    #[test]
    fn a_chunk_relayed_to_two_receivers_ends_with_exactly_two_references() {
        let (descriptor, push) = sent_by_a_publisher(64);
        assert_eq!(held_count(&descriptor), 1, "the descriptor's own reference");

        let relay = ShmRelay::posix();
        let pass = relay.open(&push, || true).expect("opened");
        assert_eq!(
            held_count(&descriptor),
            1,
            "holding a chunk takes nothing from it"
        );

        let chunk = relay.held(&descriptor).expect("held");
        let first = chunk.reserve_for_receiver();
        let second = chunk.reserve_for_receiver();
        assert_eq!(held_count(&descriptor), 3, "one reference per reservation");
        first.commit();
        second.commit();
        drop(chunk);
        drop(pass);
        assert_eq!(
            held_count(&descriptor),
            2,
            "the pass gave back the reference the message arrived with; each receiver owns one"
        );

        assert!(crate::shm_provider::PosixShmResolver
            .resolve(&descriptor)
            .is_some());
        assert!(crate::shm_provider::PosixShmResolver
            .resolve(&descriptor)
            .is_some());
        assert_eq!(held_count(&descriptor), 0, "both receivers released theirs");
    }

    /// A reservation whose frame never left gives its reference back, and the hold is unharmed.
    #[test]
    fn a_reservation_that_is_not_committed_gives_its_reference_back() {
        let (descriptor, push) = sent_by_a_publisher(64);
        let relay = ShmRelay::posix();
        let pass = relay.open(&push, || true).expect("opened");
        let chunk = relay.held(&descriptor).expect("held");
        let reservation = chunk.reserve_for_receiver();
        assert_eq!(held_count(&descriptor), 2);
        drop(reservation);
        assert_eq!(held_count(&descriptor), 1, "the send was refused");
        drop(chunk);
        drop(pass);
        assert_eq!(
            held_count(&descriptor),
            0,
            "nothing was relayed, nothing is owed"
        );
    }

    /// A message with no receivers at all still gives back the reference it arrived with: a router
    /// that routes a Put to nobody must not pin the publisher's chunk.
    #[test]
    fn a_message_routed_to_nobody_releases_what_it_arrived_with() {
        let (descriptor, push) = sent_by_a_publisher(64);
        let relay = ShmRelay::posix();
        drop(relay.open(&push, || true));
        assert_eq!(held_count(&descriptor), 0);
    }

    /// A descriptor naming a chunk that is not held is not in the pass.
    #[test]
    fn a_descriptor_whose_chunk_cannot_be_held_is_not_in_the_pass() {
        let (mut descriptor, push) = sent_by_a_publisher(64);
        let relay = ShmRelay::posix();
        let pass = relay.open(&push, || true).expect("opened");
        descriptor.generation = descriptor.generation.wrapping_add(1);
        assert!(
            relay.held(&descriptor).is_none(),
            "another generation is another chunk"
        );
        drop(pass);
    }

    /// For an egress whose receivers can never read a chunk (a multicast group), the Push carries
    /// the chunk's bytes, in the plain layout, and the pass takes no reference for it.
    #[test]
    fn a_push_for_a_receiver_that_cannot_read_chunks_carries_the_chunks_bytes() {
        let mut payload = ShmBackedPayload::alloc(11).expect("alloc");
        payload.write(b"hello relay");
        let wire = payload.wire_reference();
        let descriptor = wire.descriptor();
        wire.commit();
        let mut push = build_push_shm_literal("demo/relay", &descriptor, &PushMetadata::default())
            .expect("a Push that carries the descriptor");
        drop(payload);

        let relay = ShmRelay::posix();
        let pass = relay.open(&push, || true).expect("opened");
        relay
            .into_plain_bytes(&mut push)
            .expect("the chunk is held");
        let PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
            panic!("a Put");
        };
        assert_eq!(
            wz_session_core::put_payload::inline_bytes(put),
            Some(&b"hello relay"[..]),
            "the receiver is sent what the chunk holds, with no marker"
        );
        assert!(
            ShmRelay::shm_slices(&push).is_empty(),
            "nothing in the Push names the chunk any more"
        );
        assert_eq!(held_count(&descriptor), 1, "no reference was taken for it");
        drop(pass);
        assert_eq!(
            held_count(&descriptor),
            0,
            "and the one it arrived with went back"
        );
    }

    /// A descriptor whose chunk no pass holds is not turned into bytes of anything: the Push is
    /// refused and left as it was.
    #[test]
    fn a_push_whose_chunk_is_not_held_is_refused_and_left_alone() {
        let (descriptor, mut push) = sent_by_a_publisher(64);
        let relay = ShmRelay::posix();
        assert!(relay.into_plain_bytes(&mut push).is_err());
        assert_eq!(
            ShmRelay::shm_slices(&push).len(),
            1,
            "the descriptor is still there"
        );
        drop(relay.open(&push, || true));
        assert_eq!(held_count(&descriptor), 0);
    }

    /// A link that never negotiated shared memory is refused before anything is opened: the pass is
    /// not opened, the chunk is not held, and the reference the descriptor carried stays where it
    /// was.
    #[test]
    fn a_message_from_a_link_that_never_negotiated_opens_nothing() {
        let (descriptor, push) = sent_by_a_publisher(64);
        let relay = ShmRelay::posix();
        assert!(
            relay.open(&push, || false).is_none(),
            "the message is refused"
        );
        assert!(relay.held(&descriptor).is_none(), "no chunk was held");
        assert_eq!(held_count(&descriptor), 1, "nothing was touched");
    }

    /// Nested passes release only what they added.
    #[test]
    fn a_pass_releases_only_the_chunks_it_added() {
        let (outer, outer_push) = sent_by_a_publisher(64);
        let (inner, inner_push) = sent_by_a_publisher(64);
        let relay = ShmRelay::posix();
        let outer_pass = relay.open(&outer_push, || true).expect("opened");
        drop(relay.open(&inner_push, || true));
        assert!(
            relay.held(&outer).is_some(),
            "the outer pass still holds its chunk"
        );
        assert!(relay.held(&inner).is_none());
        drop(outer_pass);
    }
}
