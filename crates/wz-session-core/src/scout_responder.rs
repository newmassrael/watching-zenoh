// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The scouting RESPONDER — the half of multicast scouting that makes a node
//! DISCOVERABLE rather than discovering.
//!
//! # What was missing, precisely
//!
//! `scouting_glue` (active mode) and `crate::scout_static` (static mode) are
//! both INITIATOR paths: wz asks who is out there and dials what answers. The
//! mode enum records exactly that — §2.2 lists five states across three modes,
//! and every one of them is a state of a node that is looking. Nothing in wz
//! ever answered a Scout, so a stock zenoh peer running its default
//! `scouting/multicast/listen: true` could not find a wz node at all; it had to
//! be TOLD wz's endpoint with `connect/endpoints`. For a drop-in replacement
//! that is the wrong way round: the existing network is the thing that must not
//! be reconfigured.
//!
//! Note that wz's "passive" mode (§1.4, deferred Phase D+) is NOT this. Passive
//! there means an initiator that re-scouts on a period, with `Cooldown` as its
//! inter-period dwell (§2.2). Answering a Scout is a different axis entirely,
//! which is why it had no name in the mode enum and no sink for the upstream
//! `scouting/multicast/listen` key.
//!
//! # Why this is not a state machine
//!
//! One datagram in, at most one datagram out, no state carried between them.
//! Upstream agrees structurally: `Runtime::responder` is a bare `loop` around
//! `recv_from` with no state of its own (zenoh `net/runtime/orchestrator.rs`
//! :1112-1191). The scouting FSM exists because the INITIATOR has states worth
//! naming (Sending -> AwaitingHello -> resolved / timed out); a responder that
//! grew one would be a machine with a single state.
//!
//! So the decision is a pure function ([`answer_scout`]) and the socket loop is
//! the runtime's (`wz_runtime_tokio::scouting_responder`), the same IO split
//! `scouting_glue` documents: the pure half is testable without a socket, and
//! the reasons for NOT answering are values rather than log lines.
//!
//! # The three gates, and why each one is upstream's
//!
//! 1. **It must be a Scout.** A Hello on the group is another node ANSWERING,
//!    and replying to it would turn one Scout into an unbounded storm as every
//!    responder answered every other's reply. Upstream matches
//!    `ScoutingBody::Scout` and drops everything else (`orchestrator.rs:1154`).
//! 2. **`what` must include our role.** The Scout's `what` is a bitmask over
//!    the API-form role bytes (Router=1, Peer=2, Client=4; `zenoh-codec`
//!    `scouting/scout.rs:48` writes `what & 0b111`), and upstream answers only
//!    `if what.matches(self.whatami())` (`orchestrator.rs:1155`). A client
//!    scouting for routers must not be handed a peer's Hello — it would dial a
//!    node that cannot serve it.
//! 3. **It must not be our own echo.** Upstream compares the source address
//!    against its own unicast sockets (`orchestrator.rs:1143`) and can, because
//!    it SENDS scouts from a different socket than the one it listens on. wz's
//!    `UdpDriver::bind_multicast_v4` socket both sends and receives and sets
//!    `IP_MULTICAST_LOOP`, and a co-located wz scouter additionally joins the
//!    same group on its own `SO_REUSEPORT` socket, so the responder sees its own
//!    process's Scout either way. The gate is therefore the ZID, which wz's
//!    `scout_emit` always sets (`scouting_glue.rs:317-323`).
//!
//!    Upstream's address gate is deliberately NOT ported as a companion, and the
//!    reason is worth stating because the obvious cheap version is WRONG: a
//!    "refuse a datagram whose source port is the group port" rule would refuse
//!    a second wz NODE scouting from its own group socket on another host, which
//!    is exactly the wz-to-wz discovery this exists to enable. What makes the
//!    ZID gate sufficient instead is [`ResponderIdentity::try_new`] refusing an
//!    empty zid: the echo case with nothing to compare cannot be built.
//!
//! # The reply is UNICAST
//!
//! Back to the datagram's source, not to the group
//! (`orchestrator.rs:1168`, `socket.send_to(wbuf.as_slice(), peer)`). This is
//! not an optimisation: a scouting node reads replies on the EPHEMERAL unicast
//! sockets it sent the Scout from (`Runtime::scout`'s recv half iterates
//! `sockets`, `orchestrator.rs:879-885`), so a Hello multicast to the group is
//! not delivered where the asker is listening at all.

use alloc::string::String;
use alloc::vec::Vec;

use wz_codecs::hello::Hello;
use wz_codecs::locator::Locator;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;

use crate::scouting_message::{parse_scouting, ScoutingFrame};

/// Everything a Hello says about this node.
///
/// Owned rather than borrowed because its lifetime is the node's, not one
/// datagram's: the runtime loop builds it once at startup and answers every
/// Scout from it. The locator list is the node's ADVERTISED reachability — the
/// same strings `BoundListener::advertised_locator` hands the linkstate
/// forwarder — so a scouter dials what wz itself chose to publish, and there is
/// one advertise decision in the tree rather than two.
///
/// Fields are private and reached through [`ResponderIdentity::try_new`]
/// because the zid carries an INVARIANT rather than a value: it is the
/// self-echo discriminator (gate 3), and it is also a wire field whose length
/// travels in four bits. A struct literal could set it to a value that defeats
/// one and cannot encode into the other, so the check lives where the value is
/// made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderIdentity {
    version: u8,
    whatami: WhatAmI,
    zid: Vec<u8>,
    locators: Vec<String>,
}

/// Why an identity could not be built. Both arms are about the zid, and both
/// are refusals of a node that could answer but should not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderIdentityError {
    /// A responder with no identity cannot be self-echo-gated: it would answer
    /// its own Scout, and on a loopback-enabled group it would keep doing so.
    /// It also has no encodable Hello — upstream writes `(zid.size() - 1) as u8`
    /// (`zenoh-codec` `scouting/hello.rs:62`), which underflows at zero.
    EmptyZid,
    /// The Hello's flags byte carries `zid_len - 1` in four bits, so 16 is the
    /// longest zid the wire can express — the same bound
    /// `ZenohIdProto::MAX_SIZE` puts on it upstream. Carries the offending
    /// length so the error names the value rather than the rule.
    ZidTooLong {
        /// The length that was offered.
        len: usize,
    },
}

impl core::fmt::Display for ResponderIdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyZid => f.write_str(
                "a scouting responder needs a non-empty zid: it is what \
                 distinguishes another node's Scout from its own echo",
            ),
            Self::ZidTooLong { len } => write!(
                f,
                "zid is {len} bytes; a Hello encodes zid_len-1 in 4 bits, so 16 is the maximum"
            ),
        }
    }
}

impl ResponderIdentity {
    /// The longest zid a Hello's 4-bit length field can express.
    pub const MAX_ZID_LEN: usize = 16;

    /// Build the identity a responder answers with.
    ///
    /// `version` is echoed into every Hello. Upstream answers with its OWN
    /// `zenoh_protocol::VERSION` rather than the Scout's
    /// (`orchestrator.rs:1161`), so it is a property of the node, not of the
    /// question.
    ///
    /// `locators` may be empty. Upstream tolerates that on the receiving side
    /// with a warning ("Received Hello with no locators",
    /// `orchestrator.rs:1102`) and simply does not connect, so an empty list is
    /// an honest "I am here but not dialable" rather than a malformed reply.
    pub fn try_new(
        version: u8,
        whatami: WhatAmI,
        zid: Vec<u8>,
        locators: Vec<String>,
    ) -> Result<Self, ResponderIdentityError> {
        if zid.is_empty() {
            return Err(ResponderIdentityError::EmptyZid);
        }
        if zid.len() > Self::MAX_ZID_LEN {
            return Err(ResponderIdentityError::ZidTooLong { len: zid.len() });
        }
        Ok(Self {
            version,
            whatami,
            zid,
            locators,
        })
    }

    /// The protocol version byte this node answers with.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// This node's role — the `what` gate reads it, and the Hello carries its
    /// 2-bit handshake form.
    pub fn whatami(&self) -> WhatAmI {
        self.whatami
    }

    /// This node's ZID: the Hello's identity field and the self-echo
    /// discriminator. Never empty (see [`Self::try_new`]).
    pub fn zid(&self) -> &[u8] {
        &self.zid
    }

    /// The reachability this node advertises.
    pub fn locators(&self) -> &[String] {
        &self.locators
    }
}

/// Why a datagram on the scouting group produced no Hello.
///
/// A value, not a log line: the runtime loop counts these, and the tests assert
/// on them, so "we did not answer" is distinguishable from "we did not answer
/// for the RIGHT reason". A responder that dropped a well-formed Scout as
/// undecodable and one that dropped it on the `what` gate look identical from
/// the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoutIgnored {
    /// The bytes did not decode in the scouting namespace.
    Undecodable,
    /// A Hello, or a MID this build cannot name. Someone else's answer, or not
    /// a question at all.
    NotAScout,
    /// A well-formed Scout asking for roles this node does not have. Carries
    /// the mask so a caller can say WHICH roles were wanted.
    WhatMismatch {
        /// The Scout's `what` bitmask (API-form: Router=1, Peer=2, Client=4).
        what: u8,
    },
    /// Our own Scout, looped back by `IP_MULTICAST_LOOP`.
    SelfEcho,
}

/// The responder's verdict on one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoutDecision {
    /// Send these bytes back to the datagram's SOURCE address (unicast).
    Answer(Vec<u8>),
    /// Send nothing, for this reason.
    Ignored(ScoutIgnored),
}

/// Decide what to send back for one datagram observed on the scouting group.
///
/// Pure: no clock, no socket, no interior mutability. The caller states the
/// namespace by calling this rather than a transport decoder — the same
/// contract [`crate::scouting_message::parse_scouting`] documents, and for the
/// same reason (`S_MID_SCOUT` and `T_MID_INIT` are the same byte).
pub fn answer_scout(identity: &ResponderIdentity, datagram: &[u8]) -> ScoutDecision {
    let frame = match parse_scouting(datagram) {
        Ok(f) => f,
        Err(_) => return ScoutDecision::Ignored(ScoutIgnored::Undecodable),
    };
    let body = match frame {
        ScoutingFrame::Scout { body, .. } => body,
        _ => return ScoutDecision::Ignored(ScoutIgnored::NotAScout),
    };
    // Gate 3 before gate 2 deliberately: our own Scout's `what` is whatever we
    // are looking FOR, which routinely includes our own role, so the echo would
    // pass the `what` gate and be answered — to ourselves.
    if let Some(zid) = body.zid.as_ref() {
        if zid.as_ref() == identity.zid.as_slice() {
            return ScoutDecision::Ignored(ScoutIgnored::SelfEcho);
        }
    }
    let what = body.what();
    if what & identity.whatami.to_api() == 0 {
        return ScoutDecision::Ignored(ScoutIgnored::WhatMismatch { what });
    }
    ScoutDecision::Answer(hello_datagram(identity))
}

/// Encode this node's Hello as a complete scouting datagram, header included.
///
/// Public because it is also the wire wz publishes about itself: a caller that
/// wants to announce unprompted (a future gossip leg) needs the same bytes, and
/// two encoders of one message is how the `whatami` packing drifted before
/// [`WhatAmI`] existed.
///
/// The `L` header flag and the locator list travel together — upstream sets the
/// flag `if !locators.is_empty()` and writes the list under the same condition
/// (`zenoh-codec` `scouting/hello.rs:50-70`), so a Hello with the flag and no
/// list is a decode failure at the other end rather than an empty list.
pub fn hello_datagram(identity: &ResponderIdentity) -> Vec<u8> {
    let mut hello = Hello::new();
    hello.version = identity.version;
    hello.set_whatami(identity.whatami.to_wire());
    // Neither arithmetic can go wrong: `try_new` refuses an empty zid and one
    // longer than the 4-bit field, which is the whole reason it is a
    // constructor rather than a struct literal.
    hello.set_zid_len_m1((identity.zid.len() - 1) as u8);
    hello.zid = &identity.zid;

    let mut locators = sce_forge_runtime::heapless::Vec::<Locator<'_>, 64>::new();
    for l in &identity.locators {
        // The bound is the codec's declared `sce:max-count`, so overflowing it
        // is not an error to propagate but a list to TRUNCATE: a Hello carrying
        // 64 of a node's locators is still a usable dial hint, while a
        // responder that returned an error would stop answering entirely.
        if locators
            .push(Locator {
                locator_len: l.len() as u64,
                locator: l.as_str(),
            })
            .is_err()
        {
            break;
        }
    }
    let has_locators = !locators.is_empty();
    if has_locators {
        hello.num_locators = Some(locators.len() as u64);
        hello.locators = Some(locators);
    }

    let l_flag = u8::from(has_locators);
    let body = hello.encode_to_vec(l_flag);
    let mut datagram = Vec::with_capacity(1 + body.len());
    let mut header = wire_const::S_MID_HELLO;
    if has_locators {
        header |= wire_const::FLAG_S_HELLO_L;
    }
    datagram.push(header);
    datagram.extend_from_slice(&body);
    datagram
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use wz_codecs::scout::Scout;

    const OUR_ZID: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
    const OUR_LOCATOR: &str = "tcp/127.0.0.1:7447";

    fn identity(whatami: WhatAmI, zid: &[u8], locators: &[&str]) -> ResponderIdentity {
        ResponderIdentity::try_new(
            0x09,
            whatami,
            zid.to_vec(),
            locators.iter().map(|l| l.to_string()).collect(),
        )
        .expect("fixture identity is well-formed")
    }

    fn peer_identity() -> ResponderIdentity {
        identity(WhatAmI::Peer, OUR_ZID, &[OUR_LOCATOR])
    }

    /// A Scout datagram in the shape `scouting_glue::scout_emit` produces, so
    /// the tests below feed the responder the exact bytes a wz initiator puts
    /// on the group. `zid: None` is also what zenoh sends
    /// (`orchestrator.rs:840`), so both foreign shapes are reachable here.
    fn scout_wire(what: u8, zid: Option<&[u8]>) -> Vec<u8> {
        let mut scout = Scout::new();
        scout.version = 0x09;
        scout.set_what(what);
        if let Some(z) = zid {
            scout.set_i(true);
            scout.set_zid_len_m1((z.len() - 1) as u8);
            scout.zid = Some(z);
        }
        let body = scout.encode_to_vec();
        let mut wire = vec![wire_const::S_MID_SCOUT];
        wire.extend_from_slice(&body);
        wire
    }

    fn answered(decision: ScoutDecision) -> Vec<u8> {
        match decision {
            ScoutDecision::Answer(bytes) => bytes,
            ScoutDecision::Ignored(why) => panic!("expected a Hello, got Ignored({why:?})"),
        }
    }

    /// The positive arm — and it asserts the DECODED reply, not that bytes came
    /// back. A responder that answered with the Scout it was handed would pass
    /// a length check and fail this.
    #[test]
    fn a_matching_scout_is_answered_with_this_nodes_hello() {
        let id = peer_identity();
        // ROUTER|PEER, the mask zenoh's peer mode scouts with.
        let reply = answered(answer_scout(&id, &scout_wire(0b011, None)));
        match parse_scouting(&reply).expect("our own Hello must decode") {
            ScoutingFrame::Hello { body, .. } => {
                assert_eq!(body.version, 0x09);
                assert_eq!(
                    body.whatami(),
                    WhatAmI::Peer.to_wire(),
                    "the Hello carries the 2-bit handshake form of our role"
                );
                assert_eq!(body.zid.to_vec(), OUR_ZID);
                let locators = body.locators.as_ref().expect("L flag set => list present");
                assert_eq!(locators.len(), 1);
                assert_eq!(locators[0].locator.as_str(), OUR_LOCATOR);
            }
            other => panic!("the reply is not a Hello: {other:?}"),
        }
    }

    /// THE DISCRIMINATOR for gate 2. A responder that answered everything
    /// passes the test above; only this one separates it from a responder that
    /// reads `what`. Both arms are asserted on ONE identity so the difference is
    /// the Scout's mask and nothing else.
    #[test]
    fn the_what_mask_decides_and_both_arms_are_reachable() {
        let id = peer_identity();
        // CLIENT only: no peer wanted.
        assert_eq!(
            answer_scout(&id, &scout_wire(0b100, None)),
            ScoutDecision::Ignored(ScoutIgnored::WhatMismatch { what: 0b100 }),
        );
        // ROUTER only: still not us.
        assert_eq!(
            answer_scout(&id, &scout_wire(0b001, None)),
            ScoutDecision::Ignored(ScoutIgnored::WhatMismatch { what: 0b001 }),
        );
        // PEER alone: us.
        assert!(matches!(
            answer_scout(&id, &scout_wire(0b010, None)),
            ScoutDecision::Answer(_)
        ));
        // And the same masks against a ROUTER identity flip the verdict, which
        // is what proves the gate reads OUR role rather than a constant.
        let router = identity(WhatAmI::Router, OUR_ZID, &[OUR_LOCATOR]);
        assert!(matches!(
            answer_scout(&router, &scout_wire(0b001, None)),
            ScoutDecision::Answer(_)
        ));
        assert_eq!(
            answer_scout(&router, &scout_wire(0b010, None)),
            ScoutDecision::Ignored(ScoutIgnored::WhatMismatch { what: 0b010 }),
        );
    }

    /// Gate 3. The mask here is `ROUTER|PEER`, which INCLUDES our own role — so
    /// this datagram passes gate 2 and is refused only because it is ours. A
    /// responder without the zid check answers itself and, on a loopback-enabled
    /// group, does so forever.
    #[test]
    fn our_own_scout_looped_back_is_not_answered() {
        let id = peer_identity();
        assert_eq!(
            answer_scout(&id, &scout_wire(0b011, Some(OUR_ZID))),
            ScoutDecision::Ignored(ScoutIgnored::SelfEcho),
        );
        // CONTROL: the same shape from a DIFFERENT node is answered, so the
        // gate is the identity and not the presence of a zid.
        assert!(matches!(
            answer_scout(&id, &scout_wire(0b011, Some(&[0x11, 0x22, 0x33, 0x44]))),
            ScoutDecision::Answer(_)
        ));
    }

    /// Gate 1. A Hello is another node's ANSWER; answering it is how a group
    /// turns one question into a storm.
    #[test]
    fn a_hello_on_the_group_is_not_a_question() {
        let id = peer_identity();
        let someone_elses_hello = hello_datagram(&identity(
            WhatAmI::Peer,
            &[0x11, 0x22, 0x33, 0x44],
            &[OUR_LOCATOR],
        ));
        assert_eq!(
            answer_scout(&id, &someone_elses_hello),
            ScoutDecision::Ignored(ScoutIgnored::NotAScout),
        );
        // A MID this namespace cannot name is also not a question.
        assert_eq!(
            answer_scout(&id, &[0x07, 0, 0, 0]),
            ScoutDecision::Ignored(ScoutIgnored::NotAScout),
        );
    }

    #[test]
    fn a_datagram_that_does_not_decode_is_named_as_such() {
        let id = peer_identity();
        assert_eq!(
            answer_scout(&id, &[]),
            ScoutDecision::Ignored(ScoutIgnored::Undecodable),
        );
        // A Scout header with a truncated body: the MID is right and the rest
        // is not, which is the shape a torn datagram takes.
        assert_eq!(
            answer_scout(&id, &[wire_const::S_MID_SCOUT]),
            ScoutDecision::Ignored(ScoutIgnored::Undecodable),
        );
    }

    /// The `L` flag and the list are one decision, asserted at the BYTE the
    /// remote decoder reads. A Hello with the flag set and no list is what
    /// upstream reads as a decode failure, so the two must never disagree.
    #[test]
    fn the_locator_flag_tracks_the_list() {
        let with = hello_datagram(&peer_identity());
        assert_eq!(
            with[0],
            wire_const::S_MID_HELLO | wire_const::FLAG_S_HELLO_L,
            "a Hello carrying a locator sets L in the header"
        );

        let without = hello_datagram(&identity(WhatAmI::Peer, OUR_ZID, &[]));
        assert_eq!(
            without[0],
            wire_const::S_MID_HELLO,
            "a Hello with no locator must NOT set L"
        );
        match parse_scouting(&without).expect("a locator-less Hello is well-formed") {
            ScoutingFrame::Hello { body, .. } => {
                assert!(body.locators.is_none(), "no L flag => no list decoded");
                assert_eq!(body.zid.to_vec(), OUR_ZID);
            }
            other => panic!("not a Hello: {other:?}"),
        }
    }

    /// The invariant behind gate 3. An empty zid is the identity that CANNOT be
    /// self-echo-gated — the Scout carries none, so there is nothing to compare
    /// — and refusing it at construction is what lets `answer_scout` compare
    /// unconditionally instead of carrying an `is_empty` arm that silently
    /// answered.
    #[test]
    fn an_identity_that_cannot_be_self_echo_gated_is_refused() {
        assert_eq!(
            ResponderIdentity::try_new(0x09, WhatAmI::Peer, vec![], vec![]),
            Err(ResponderIdentityError::EmptyZid),
        );
        // The other end of the same field: 16 bytes is the longest the Hello's
        // 4-bit length can express, so 17 is refused and 16 is not.
        assert_eq!(
            ResponderIdentity::try_new(0x09, WhatAmI::Peer, vec![0xAB; 17], vec![]),
            Err(ResponderIdentityError::ZidTooLong { len: 17 }),
        );
        let longest = ResponderIdentity::try_new(0x09, WhatAmI::Peer, vec![0xAB; 16], vec![])
            .expect("16 bytes is the maximum, not past it");
        // And it ENCODES: the boundary is asserted on the wire, not only on the
        // constructor, because `zid_len_m1` masks to 4 bits and would silently
        // wrap a value the constructor had let through.
        let wire = hello_datagram(&longest);
        assert_eq!(wire[2] >> 4, 15, "zid_len-1 = 15 for a 16-byte zid");
        assert_eq!(&wire[3..19], &[0xABu8; 16]);
    }

    /// The wire layout, pinned against upstream's writer rather than against
    /// our own reader — a round trip through one codec cannot catch a field
    /// order both halves share. `zenoh-codec` `scouting/hello.rs:52-66` writes
    /// header, version, `flags = whatami | (zid_len-1) << 4`, then the zid.
    #[test]
    fn the_hello_body_bytes_are_upstreams_layout() {
        let wire = hello_datagram(&peer_identity());
        assert_eq!(wire[1], 0x09, "version");
        assert_eq!(
            wire[2],
            WhatAmI::Peer.to_wire() | (((OUR_ZID.len() - 1) as u8) << 4),
            "flags = whatami in the low 2 bits, zid_len-1 in the high nibble"
        );
        assert_eq!(
            &wire[3..3 + OUR_ZID.len()],
            OUR_ZID,
            "zid follows the flags"
        );
        // Then the locator list: a VLE count, then each locator as VLE len +
        // bytes. One locator here, so the count byte is 1.
        let after_zid = 3 + OUR_ZID.len();
        assert_eq!(wire[after_zid], 1, "one locator in the list");
        assert_eq!(wire[after_zid + 1], OUR_LOCATOR.len() as u8);
        assert_eq!(
            &wire[after_zid + 2..],
            OUR_LOCATOR.as_bytes(),
            "the locator string is the tail"
        );
    }
}
