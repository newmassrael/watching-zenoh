// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a handshake step does with a handshake message it does not await: the
//! `handshake-stray-message` policy.
//!
//! Each step of a unicast establishment reads one message next: the initiator an InitAck after
//! its InitSyn and an OpenAck after its OpenSyn, the acceptor an InitSyn first and an OpenSyn
//! after its InitAck. Upstream ends the attempt on any other message and closes the link with
//! INVALID (`io/zenoh-transport/src/unicast/establishment/open.rs` @
//! `"Received an invalid message in response to an InitSyn on {}: {:?}",`, and its three
//! siblings in `open.rs` and `accept.rs`; zenoh-pico returns `_Z_ERR_MESSAGE_UNEXPECTED`,
//! `vendor/zenoh-pico/src/transport/unicast/transport.c` @
//! `_Z_ERROR_RETURN(_Z_ERR_MESSAGE_UNEXPECTED);`). That is `fail`. Under `ignore` a message out
//! of its step (a peer repeating an earlier step because its answer was late, or one arriving
//! after the step moved on) is dropped and the step keeps waiting, under the same deadline: the
//! establishment's deadline is armed once for the whole of it and nothing a peer sends moves it.
//!
//! The judgement is the dispatcher's, ahead of the statechart: whether a message is out of its
//! step depends on the policy, which is host state, so the dispatcher pre-classifies as it does
//! for the accept-side admission guards (`sources/session/session_fsm_unicast.scxml`, "Accept-side
//! admission guards"), and a rejection is the machine's existing `framing.error`.

use crate::policy::HandshakeStrayMessage;

/// A message of the unicast establishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMessage {
    /// The initiator's first message.
    InitSyn,
    /// The acceptor's answer to it.
    InitAck,
    /// The initiator's second message, echoing the acceptor's cookie.
    OpenSyn,
    /// The acceptor's answer to it, which ends the establishment.
    OpenAck,
}

/// What the dispatcher does with one handshake message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrayVerdict {
    /// The message is the one the step awaits, or the session is in no handshake step: it goes
    /// on to the checks and the machine as before.
    Pass,
    /// The message is out of its step and the attempt ends (`fail`).
    Reject,
    /// The message is out of its step and is dropped (`ignore`).
    Drop,
}

/// The verdict on `got` in a step that awaits `awaited` (`None` outside the establishment, where
/// this policy says nothing), under `policy`.
pub const fn judge(
    awaited: Option<HandshakeMessage>,
    got: HandshakeMessage,
    policy: HandshakeStrayMessage,
) -> StrayVerdict {
    let Some(awaited) = awaited else {
        return StrayVerdict::Pass;
    };
    if awaited as u8 == got as u8 {
        return StrayVerdict::Pass;
    }
    match policy {
        HandshakeStrayMessage::Fail => StrayVerdict::Reject,
        HandshakeStrayMessage::Ignore => StrayVerdict::Drop,
    }
}

/// Whether a handshake message that reaches an ESTABLISHED session is kept out of the session's
/// liveness and handshake records under `policy`. Upstream drops such a message too, but counts
/// it as traffic from the peer for the lease, as it counts every message; under `ignore` a late
/// Init or Open is not taken as a sign of life and records nothing, since it belongs to an
/// establishment that is over.
pub const fn established_drops_silently(policy: HandshakeStrayMessage) -> bool {
    matches!(policy, HandshakeStrayMessage::Ignore)
}

#[cfg(test)]
mod tests {
    use super::*;
    use HandshakeMessage::{InitAck, InitSyn, OpenAck, OpenSyn};

    const ALL: [HandshakeMessage; 4] = [InitSyn, InitAck, OpenSyn, OpenAck];

    /// The awaited message passes in every step under both values, and outside the
    /// establishment every message passes, since the policy says nothing there.
    #[test]
    fn the_awaited_message_and_any_message_outside_a_handshake_step_pass() {
        for policy in [HandshakeStrayMessage::Fail, HandshakeStrayMessage::Ignore] {
            for message in ALL {
                assert_eq!(judge(Some(message), message, policy), StrayVerdict::Pass);
                assert_eq!(judge(None, message, policy), StrayVerdict::Pass);
            }
        }
    }

    /// Every other message of a step is rejected under `fail`, upstream's, and dropped under
    /// `ignore`: the initiator after its OpenSyn given a repeated InitAck, the acceptor after its
    /// InitAck given a repeated InitSyn, and each pair besides.
    #[test]
    fn a_message_out_of_its_step_is_rejected_under_fail_and_dropped_under_ignore() {
        for awaited in ALL {
            for got in ALL.into_iter().filter(|got| *got != awaited) {
                assert_eq!(
                    judge(Some(awaited), got, HandshakeStrayMessage::Fail),
                    StrayVerdict::Reject,
                    "{awaited:?} given {got:?}"
                );
                assert_eq!(
                    judge(Some(awaited), got, HandshakeStrayMessage::Ignore),
                    StrayVerdict::Drop,
                    "{awaited:?} given {got:?}"
                );
            }
        }
    }

    /// Only `ignore` keeps a late Init or Open out of an established session's lease.
    #[test]
    fn only_ignore_keeps_a_late_handshake_message_out_of_the_lease() {
        assert!(!established_drops_silently(HandshakeStrayMessage::Fail));
        assert!(established_drops_silently(HandshakeStrayMessage::Ignore));
    }
}
