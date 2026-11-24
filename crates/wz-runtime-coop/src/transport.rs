// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The refusals of a session's transport: why an endpoint could not be used
//! ([`EndpointRefusal`], [`Refusal`]), and why the transport brought up no link, listener or
//! group for a session ([`TransportRefusal`]). An engine over the faces of [`crate::faces`]
//! answers its program with these, inside its own refusal of an open where the open has reasons
//! of its own (an identity, an arena).

use wz_session_core::caps;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::locator_directory::LocatorText;

use crate::executor::SpawnRefusal;
use crate::faces::HandshakeEnd;
use crate::locator_text::DialRefused;
use crate::session_drive::LinkOpenError;

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
        // The cut is at most a row's length, so the text before it fits whole.
        let _ = kept.push_str(endpoint.get(..cut).unwrap_or_default());
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
}
