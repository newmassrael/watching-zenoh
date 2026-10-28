// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A link JOINED to a peer's session (`transport-multilink`) on the region-hat forwarder.
//!
//! A second or later physical link of a session is not a face of its own: `join_link` shares
//! the first link's session core, and the accept loop tells the forwarder about the link only
//! through `register_joined`. Its inbound frames reach `forward` tagged with the link's OWN
//! face id, which is not in the face table. The aggregate is ONE logical face, as in zenoh, so
//! the forwarder routes such a frame as its session's primary face's; a frame that is not is
//! dropped at the `faces.get` gate, and so is every Put and Declare a peer sends over its
//! second link.
//!
//! Two witnesses. The data one: a Put on the joined link reaches a subscriber, which it does
//! only if the frame was routed as the primary's. The shared-memory one: the slice a Put
//! carries is acknowledged to the peer of the link it arrived on, which is the peer of THAT
//! link and not the session's first one (R3123). Upstream's handoff is a link's
//! (`io/zenoh-transport/src/common/shm/interop.rs` @
//! `pub struct LinkShmHandoffConfig {` holds a receive channel and a transmit channel per
//! link), and the counter a receiver lowers is the one its peer named in the Open message of
//! the link the slice came in on.

use super::*;
use crate::multilink::{join_link, JoinOutcome};
use crate::runtime_impl::TokioRuntime;
use crate::test_fixtures::recording_actions_over;
use wz_runtime_core::runtime::Runtime;
use wz_session_core::link::LinkKind;

fn zid_of(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// A primary link of a peer named `peer`, a second link joined to its session, and the first's
/// face registered in `fwd` as face 0; the joined link's id is 5.
fn a_session_of_two_links(
    fwd: &RouterForwarder,
    peer: u8,
) -> (Arc<SessionLinkActions>, Arc<SessionLinkActions>) {
    let (primary, _) = recording_actions_over(LinkKind::Tcp);
    let (secondary, _) = recording_actions_over(LinkKind::Tcp);
    TokioRuntime::with_mutex_mut(&primary.remote_peer_zid, |s| {
        *s = Some(zid_of(peer).as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&primary.peer_whatami, |s| *s = Some(0b01));
    let key = vec![0x0Au8, 0x0B, 0x0C, 0x0D];
    TokioRuntime::with_mutex_mut(&primary.core.multilink_pubkey, |s| *s = Some(key.clone()));
    TokioRuntime::with_mutex_mut(&secondary.core.multilink_pubkey, |s| *s = Some(key));
    fwd.register(FaceId(0), &primary);
    let JoinOutcome::Joined(joined) = join_link(&primary, &secondary, 2) else {
        panic!("the second link joins the session");
    };
    fwd.register_joined(FaceId(5), FaceId(0), &joined);
    (primary, joined)
}

fn deliver(fwd: &RouterForwarder, on: FaceId, message: NetworkMessage) {
    let outcome = DriverLoopOutcome::FramePayload {
        priority: Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![message],
        has_ext: false,
        extensions: Vec::new(),
    };
    fwd.forward(on, IterationEvent::Poll(&outcome));
}

/// A client subscribes, and a Put arrives on the peer's JOINED link: the client is sent it,
/// as it is sent a Put on the peer's first link.
#[test]
fn a_put_on_a_joined_link_is_routed_as_the_primary_faces() {
    let fwd = RouterForwarder::peer(zid_of(0x01));
    a_session_of_two_links(&fwd, 0xAA);
    let (client, sink) = recording_actions_over(LinkKind::Tcp);
    TokioRuntime::with_mutex_mut(&client.remote_peer_zid, |s| {
        *s = Some(zid_of(0xCC).as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&client.peer_whatami, |s| *s = Some(0b10));
    fwd.register(FaceId(1), &client);
    let subscribe = wz_session_core::declare_build::build_declare_subscriber(1, 0, Some("demo/**"))
        .expect("declare");
    deliver(
        &fwd,
        FaceId(1),
        NetworkMessage::Declare(Box::new(subscribe)),
    );
    sink.reset();

    let put = wz_session_core::push_build::build_push_literal("demo/joined", b"second link")
        .expect("push");
    deliver(&fwd, FaceId(5), NetworkMessage::Push(Box::new(put.clone())));
    assert_eq!(
        sink.frame_count(),
        1,
        "a Put on the joined link reaches the client, as the first link's would"
    );

    // And the link going away takes the mapping with it: the id is no one's again.
    fwd.deregister_joined(FaceId(5));
    sink.reset();
    deliver(&fwd, FaceId(5), NetworkMessage::Push(Box::new(put)));
    assert_eq!(
        sink.frame_count(),
        0,
        "a frame on an id that is no longer joined is dropped at the face table"
    );
}

#[cfg(feature = "session-extshm")]
mod shared_memory {
    use super::*;
    use crate::shm_provider::ShmBackedPayload;
    use std::sync::Mutex;
    use wz_session_core::extshm::{
        encode_shm_init_syn_body, encode_shm_open_syn_body, encode_shm_zbuf_ext, ShmAuthenticator,
        ShmHandoff, ShmHandoffCounters, SHM_PRIORITY_BANDS,
    };

    /// The segment the peer of every link here names in its InitSyn, and the challenge read out
    /// of it.
    const PEER_SEGMENT: u32 = 77;
    const PEER_CHALLENGE: u64 = 0xC0FF_EE00;
    /// The challenge each link's own segment holds, which its peer echoes in its OpenSyn.
    const OWN_CHALLENGE: u64 = 0xBEEF;

    type Log = Arc<Mutex<Vec<&'static str>>>;

    /// A handoff that records whose peer it acknowledges.
    struct Recorder {
        peer: &'static str,
        log: Log,
    }

    impl ShmHandoff for Recorder {
        fn on_rx(&self, _band: usize) {
            self.log.lock().expect("log").push(self.peer);
        }
    }

    /// An authenticator for a link whose peer is `peer`: it reads that peer's segment and opens
    /// a handoff that records `peer`.
    struct PeerAuth {
        peer: &'static str,
        log: Log,
    }

    impl ShmAuthenticator for PeerAuth {
        fn local_segment_id(&self) -> u32 {
            1
        }
        fn local_challenge(&self) -> u64 {
            OWN_CHALLENGE
        }
        fn open_peer_challenge(&self, segment_id: u32) -> Option<u64> {
            (segment_id == PEER_SEGMENT).then_some(PEER_CHALLENGE)
        }
        fn open_peer_handoff(
            &self,
            _peer_segment: u32,
            _counters: &[u16; SHM_PRIORITY_BANDS],
        ) -> Option<Box<dyn ShmHandoff>> {
            Some(Box::new(Recorder {
                peer: self.peer,
                log: Arc::clone(&self.log),
            }))
        }
    }

    /// Establish `actions` as the acceptor of `peer`, which offered shared memory: the session
    /// ends negotiated and holds the handoff opened from the counters `peer` named.
    fn establish(actions: &SessionLinkActions, peer: &'static str, log: &Log) {
        actions.install_shm_auth(Box::new(PeerAuth {
            peer,
            log: Arc::clone(log),
        }));
        actions.set_shm_offer(true);
        actions.negotiate_shm_against_peer(true);
        let init_syn = encode_shm_zbuf_ext(&encode_shm_init_syn_body(PEER_SEGMENT)).expect("fits");
        actions
            .shm_recv_init_syn(&[init_syn])
            .expect("a well-formed InitSyn");
        let open_syn = encode_shm_zbuf_ext(&encode_shm_open_syn_body(
            OWN_CHALLENGE,
            ShmHandoffCounters::PerPriority([1; SHM_PRIORITY_BANDS]),
        ))
        .expect("fits");
        actions.shm_recv_open_syn(&[open_syn]);
        assert!(actions.is_shm(), "{peer}'s link negotiated shared memory");
    }

    /// A Put whose payload is a chunk of shared memory, sent the way a publisher sends one.
    fn a_put_in_shared_memory() -> PushOwned {
        let payload = ShmBackedPayload::alloc(64).expect("alloc");
        let wire = payload.wire_reference();
        let descriptor = wire.descriptor();
        wire.commit();
        drop(payload);
        wz_session_core::push_build::build_push_shm_literal(
            "demo/joined",
            &descriptor,
            &wz_session_core::metadata::PushMetadata::default(),
        )
        .expect("a Put in shared memory")
    }

    /// R3040 -- a NEW establishment on a link withdraws the handoff its last peer gave, so a
    /// registry never keeps writing the counters of a peer the link has moved on from; and
    /// R3123 -- the withdrawal and the update are the LINK's: the session's other links keep
    /// theirs.
    #[test]
    fn a_new_establishment_on_a_link_withdraws_its_handoff_and_leaves_the_other_links_alone() {
        let log: Log = Arc::default();
        let (first, _) = recording_actions_over(LinkKind::Tcp);
        let (second, _) = recording_actions_over(LinkKind::Tcp);
        establish(&first, "first link's peer", &log);
        establish(&second, "second link's peer", &log);
        assert!(
            matches!(first.shm_take_handoff_update(), Some(Some(_))),
            "the first link's peer gave it a handoff"
        );

        let init_syn = encode_shm_zbuf_ext(&encode_shm_init_syn_body(PEER_SEGMENT)).expect("fits");
        first
            .shm_recv_init_syn(&[init_syn])
            .expect("a well-formed InitSyn");
        assert!(
            matches!(first.shm_take_handoff_update(), Some(None)),
            "the next peer of the first link starts with no handoff, and the registry hears it"
        );
        assert!(
            matches!(second.shm_take_handoff_update(), Some(Some(_))),
            "while the second link's handoff, its own, was not touched"
        );
    }

    /// THE POINT. Two links of one session, each with a peer of its own. A Put in shared memory
    /// arrives on each in turn; the acknowledgement of each is owed to the peer of the link it
    /// arrived on, and to nobody else.
    #[test]
    fn a_slice_is_acknowledged_to_the_peer_of_the_link_it_arrived_on() {
        let log: Log = Arc::default();
        let fwd = RouterForwarder::peer(zid_of(0x01));
        let (primary, joined) = a_session_of_two_links(&fwd, 0xAA);
        establish(&primary, "first link's peer", &log);
        establish(&joined, "joined link's peer", &log);

        deliver(
            &fwd,
            FaceId(0),
            NetworkMessage::Push(Box::new(a_put_in_shared_memory())),
        );
        assert_eq!(
            *log.lock().expect("log"),
            ["first link's peer"],
            "a Put on the first link is acknowledged to its peer"
        );

        log.lock().expect("log").clear();
        deliver(
            &fwd,
            FaceId(5),
            NetworkMessage::Push(Box::new(a_put_in_shared_memory())),
        );
        assert_eq!(
            *log.lock().expect("log"),
            ["joined link's peer"],
            "and a Put on the joined link to the joined link's peer, whose counter it is"
        );
    }
}
