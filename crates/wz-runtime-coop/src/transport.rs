// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The refusals of a session's transport: why an endpoint could not be used
//! ([`EndpointRefusal`], [`Refusal`]), and why the transport brought up no link, listener or
//! group for a session ([`TransportRefusal`]); and what the transport reads of a link's session
//! and of a group beside its faces ([`TransportSession`], [`GroupRecord`]). An engine over the
//! faces of [`crate::faces`] answers its program with these refusals, inside its own refusal of
//! an open where the open has reasons of its own (an identity, an arena).

use alloc::vec::Vec;

use wz_session_core::bounded::push_text;
use wz_session_core::caps;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::EventSink;
use wz_session_core::face::{FaceLinkRow, FaceSnapshot};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::locator_directory::LocatorText;
use wz_session_core::policy::KeyWireForm;
use wz_session_core::response_sink::ResponseSink;

use crate::executor::SpawnRefusal;
use crate::faces::{FaceId, FaceSession, HandshakeEnd};
use crate::link_cells::CellRc;
use crate::locator_text::DialRefused;
use crate::session_drive::{LinkOpenError, LinkWait, SessionDatagramLink};
use crate::session_runtime::SessionHandle;
use crate::sync::LockKind;
use crate::ClockSource;

// The transport's state over the session's one reassembly Router, which the engine's builds keep.
// Documented in its own `//!`.
#[cfg(feature = "reassembly")]
mod state;
#[cfg(feature = "reassembly")]
pub use state::{DialRow, DialWalk, FaceStep, TransportFaces, TransportState, WireMaking};

/// An endpoint a session could not use, at its open or at a later dial: the endpoint as it was
/// given, and why.
// Typed and not a text: the C ABIs answer a refusal with a code and never read its words, so the
// formatter is linked only into a program that prints one (`Display`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRefusal {
    /// The endpoint, as the config or the caller states it, at most `MAX_LOCATOR_LEN` bytes of
    /// it; empty when the refusal is the session's and names no endpoint ([`Refusal::LinkLost`]).
    pub endpoint: LocatorText,
    /// Why it could not be used.
    pub why: Refusal,
}

impl EndpointRefusal {
    /// The refusal of `endpoint` for `why`. A refusal is made after the open too (a dial again
    /// that fails), so it keeps the endpoint in a row's length and no memory of the heap: a text
    /// longer than that is kept up to the last whole character that fits. Out of line: every way
    /// an endpoint is refused makes one.
    #[inline(never)]
    pub fn new(endpoint: &str, why: Refusal) -> Self {
        let mut cut = endpoint.len().min(caps::MAX_LOCATOR_LEN);
        while !endpoint.is_char_boundary(cut) {
            cut = cut.saturating_sub(1);
        }
        let mut kept = LocatorText::new();
        // The cut is at most a row's length, so the text before it fits whole. One copy, and not
        // heapless's append of a byte at a time.
        let _ = push_text(&mut kept, endpoint.get(..cut).unwrap_or_default());
        Self {
            endpoint: kept,
            why,
        }
    }
}

/// Why an endpoint could not be used ([`EndpointRefusal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The endpoint does not parse as a locator this build can dial or listen on.
    Locator(DialRefused),
    /// The network opened no link, listener or group for it.
    Link(LinkOpenError),
    /// The handshake ended with a close reason.
    HandshakeClosed(CloseReason),
    /// The handshake ended with no close reason.
    HandshakeEnded,
    /// Nothing answered by the deadline.
    NoAnswerInTime,
    /// The link was lost and the session dials no endpoint again.
    LinkLost,
    /// The endpoint is one to listen on, and this build does not listen.
    ListeningNotBuilt,
    /// The endpoint is a group to join, and this build joins no group.
    GroupsNotBuilt,
    /// The group was joined and its link did not open.
    GroupLinkDidNotOpen,
    /// The session is closed.
    SessionClosed,
    /// The session holds as many faces as `max_faces` admits.
    FacesFull,
    /// The endpoint's text is longer than a row of the session's endpoints, `MAX_LOCATOR_LEN`
    /// bytes.
    TextTooLong,
    /// The group's endpoint is longer than the row a member's link is reported in,
    /// `MAX_GROUP_ENDPOINT_LEN` bytes.
    GroupEndpointTooLong,
}

impl From<HandshakeEnd> for Refusal {
    fn from(end: HandshakeEnd) -> Self {
        match end {
            HandshakeEnd::Closed(reason) => Refusal::HandshakeClosed(reason),
            HandshakeEnd::Ended => Refusal::HandshakeEnded,
            HandshakeEnd::NoAnswerInTime => Refusal::NoAnswerInTime,
        }
    }
}

impl core::fmt::Display for EndpointRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if !self.endpoint.is_empty() {
            write!(f, "{}: ", self.endpoint)?;
        }
        match self.why {
            Refusal::Locator(why) => write!(f, "{why:?}"),
            Refusal::Link(why) => write!(f, "{why:?}"),
            Refusal::HandshakeClosed(reason) => write!(f, "the handshake ended: {reason:?}"),
            Refusal::HandshakeEnded => f.write_str("the handshake ended"),
            Refusal::NoAnswerInTime => f.write_str("no answer in time"),
            Refusal::LinkLost => f.write_str("the link was lost"),
            Refusal::ListeningNotBuilt => f.write_str("listening is not built"),
            Refusal::GroupsNotBuilt => f.write_str("joining a group is not built"),
            Refusal::GroupLinkDidNotOpen => f.write_str("the group's link did not open"),
            Refusal::SessionClosed => f.write_str("the session is closed"),
            Refusal::FacesFull => {
                f.write_str("the session holds as many faces as max_faces admits")
            }
            Refusal::TextTooLong => f.write_str("the endpoint is longer than MAX_LOCATOR_LEN"),
            Refusal::GroupEndpointTooLong => {
                f.write_str("the group endpoint is longer than MAX_GROUP_ENDPOINT_LEN")
            }
        }
    }
}

/// Why a session's transport brought up no link, listener or group, at the session's open or at
/// a later dial or join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportRefusal {
    /// The configuration names no endpoint.
    NoEndpoint,
    /// An endpoint to listen on could not be listened on: it does not parse, the network opens no
    /// listener for its protocol, or the port is taken. The endpoint and the reason.
    Listen(EndpointRefusal),
    /// A group to join could not be: the network joins no group for its endpoint, or the group's
    /// link did not open. The endpoint and the reason.
    Group(EndpointRefusal),
    /// No endpoint could be dialled: each was refused, unreachable or did not complete the
    /// handshake in time. The last endpoint's reason.
    Unreachable(EndpointRefusal),
    /// The platform gave no entropy for a link's cookie key.
    EntropyUnavailable,
    /// The session's runtime had no task for a link's session or a group's.
    NoTask(SpawnRefusal),
}

/// What the transport reads of the session's half of a link beyond what its supervisor asks
/// ([`FaceSession`]): the actions the session sends over the link through, and whether a query
/// the link carried is answered over it. `K` is how the session's runtime locks what it lends.
pub trait TransportSession<C: ClockSource + 'static, K: LockKind = crate::sync::Shared>:
    FaceSession
{
    /// The actions of the link's session.
    fn actions(&self) -> &SessionHandle<C, dyn BoxedLinkDriver, K>;

    /// Whether a query that came in under `generation` came over this link, so that its answer
    /// goes back over it. A session that answers no query names no link for one.
    fn answers_as(&self, generation: u64) -> bool {
        let _ = generation;
        false
    }
}

/// What the session does in the making of each of its links' sessions, in the engine's own types
/// ([`TransportState::make_wire`]): the transport makes the link's actions, its cells and its task;
/// the session tells its tables of the link, puts the link's pump behind its gates, and says what
/// the link's task hands its reads to and what its face keeps of the link.
pub trait LinkCalls<C: ClockSource + 'static, K: LockKind = crate::sync::Shared> {
    /// The gates the session puts a link's pump behind, placed in the link's cell of its table.
    type Gate: SessionDatagramLink + 'static;
    /// What a link's task hands what its session reads to.
    type Dispatch: EventSink + 'static;
    /// The session's half of a link, as its face keeps it.
    type Session;

    /// The link of face `face`, sending through `actions`, made: the session's tables are told of
    /// it before it carries anything. `key_form` is the key-wire form stated for the endpoint the
    /// link was dialled to or taken on, `None` in a build whose nodes share no key ids.
    fn link_made(
        &mut self,
        face: FaceId,
        actions: &SessionHandle<C, dyn BoxedLinkDriver, K>,
        key_form: Option<KeyWireForm>,
    );

    /// The gates over `pump`, the link's one shared handle, whose session sends through
    /// `actions`.
    fn gate(
        &self,
        pump: CellRc<dyn SessionDatagramLink>,
        actions: &SessionHandle<C, dyn BoxedLinkDriver, K>,
    ) -> Self::Gate;

    /// What the task of the link of face `face` hands its reads to, and what the face keeps of the
    /// link: its actions and its gates, placed in their cell.
    fn wire_parts(
        &self,
        face: FaceId,
        actions: SessionHandle<C, dyn BoxedLinkDriver, K>,
        gate: &CellRc<Self::Gate>,
    ) -> (Self::Dispatch, Self::Session);
}

/// What the transport reads of a multicast group a session joined, each a face of its own: the
/// group's face, its input and its time due, its stop, and, where the session asks and answers
/// queries and reports its links, what the group holds of those. A group that does none of them
/// answers as one that holds nothing.
pub trait GroupRecord {
    /// The face the group's tables are in.
    fn id(&self) -> FaceId;

    /// Whether the group's task took a datagram since this was last asked.
    fn took_input(&self) -> bool;

    /// What a read waits on for the group socket's next datagram, while the group's session runs
    /// and its stack gives one.
    fn input(&self) -> Option<LinkWait>;

    /// Whether the group's session runs over a stack that gives no wait for its input, so that it
    /// is looked at on its tick.
    fn unwaited(&self) -> bool;

    /// When the group's session is next due with nothing arriving, in microseconds of the
    /// session's clock; `None` when nothing is.
    fn due_us(&self) -> Option<u64>;

    /// Ask the group's session to stop: at its next step it tells the group it leaves and lets the
    /// group's link go.
    fn stop(&self);

    /// Whether the session asks queries of the group.
    fn asks_queries(&self) -> bool {
        false
    }

    /// Where an answer to a query that came in on the group under `generation` goes, while its
    /// session runs: `None` for a query that came in elsewhere.
    fn answer_sink(&self, generation: u64) -> Option<&dyn ResponseSink> {
        let _ = generation;
        None
    }

    /// Write on the group what the answers to its queries put on its stage outside its step.
    fn write_staged(&self) {}

    /// How many rows of members the group reports.
    fn member_rows(&self) -> usize {
        0
    }

    /// The `at`-th of the rows [`Self::member_rows`] counts.
    fn member_row(&self, at: usize) -> Option<FaceLinkRow> {
        let _ = at;
        None
    }

    /// The members the group holds, each as the transport it is reported as.
    fn member_snapshots(&self) -> Vec<FaceSnapshot> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::ToString;

    /// The endpoint is kept in a row's length, cut at the last whole character that fits, so a
    /// refusal made after the open holds no memory of the heap.
    #[test]
    fn an_endpoint_longer_than_a_row_is_kept_to_its_last_whole_character() {
        let row = caps::MAX_LOCATOR_LEN;
        let mut long = std::string::String::from("udp/");
        while long.len() < row.saturating_sub(1) {
            long.push('1');
        }
        // A two-byte character across the row's end.
        long.push('\u{e9}');
        long.push_str(":7447");
        let kept = EndpointRefusal::new(&long, Refusal::TextTooLong);
        assert_eq!(kept.endpoint.as_str(), &long[..row.saturating_sub(1)]);
        let short = EndpointRefusal::new("udp/1.2.3.4:5", Refusal::LinkLost);
        assert_eq!(short.endpoint.as_str(), "udp/1.2.3.4:5");
    }

    /// A handshake's end reads as the refusal of its endpoint with the same reason.
    #[test]
    fn a_handshake_end_reads_as_its_refusal() {
        assert_eq!(
            Refusal::from(HandshakeEnd::Closed(CloseReason::Generic)),
            Refusal::HandshakeClosed(CloseReason::Generic)
        );
        assert_eq!(Refusal::from(HandshakeEnd::Ended), Refusal::HandshakeEnded);
        assert_eq!(
            Refusal::from(HandshakeEnd::NoAnswerInTime),
            Refusal::NoAnswerInTime
        );
        assert_eq!(
            EndpointRefusal::new("", Refusal::LinkLost).to_string(),
            "the link was lost"
        );
    }

    /// A group that asks and answers no query and reports no link reads as one that holds
    /// nothing of them: no query is asked of it, no answer goes to it, and it reports no member.
    #[test]
    fn a_group_that_states_none_of_its_readings_holds_nothing() {
        struct Bare;
        impl GroupRecord for Bare {
            fn id(&self) -> FaceId {
                7
            }
            fn took_input(&self) -> bool {
                false
            }
            fn input(&self) -> Option<LinkWait> {
                None
            }
            fn unwaited(&self) -> bool {
                true
            }
            fn due_us(&self) -> Option<u64> {
                None
            }
            fn stop(&self) {}
        }
        let group = Bare;
        assert!(!group.asks_queries());
        assert!(group.answer_sink(3).is_none());
        group.write_staged();
        assert_eq!(group.member_rows(), 0);
        assert!(group.member_row(0).is_none());
        assert!(group.member_snapshots().is_empty());
        assert_eq!(group.id(), 7);
    }
}
