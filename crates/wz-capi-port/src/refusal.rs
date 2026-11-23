// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Why an engine refused a declaration: [`Refusal`].
//!
//! A declaration answers `Result<Id, Refusal>` across the port, so no value of an id means
//! "refused": an id is live whatever its number, and an engine is free to hand out any number,
//! 0 among them (`docs/c-abi-architecture.md`, P10). Each C ABI turns a refusal into its own
//! code in one table of its own; this crate names none, for the reason it names no result code
//! at all (both ABIs typedef their result to `int8_t` and disagree about the values).

use crate::{LinksNotHonoured, StatementNotHonoured};

/// Why an engine refused to declare an entity or to ask a request. By the time it is answered
/// nothing of the call is held, nothing was sent, and the callback the caller handed in has been
/// let go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A table the session holds the entity in, or the key arena its key is kept in, is at the
    /// bound the session was opened with.
    TableFull,
    /// The entity's key is longer than a row of the session holds (`MAX_KEYEXPR_BYTES`).
    KeyTooLong,
    /// The session has handed out every entity id, and the entity needs one.
    NoEntityId,
    /// The session is closed.
    Closed,
    /// This build does not hold the plane the entity is declared on.
    NotBuilt,
    /// The call states what this engine does not carry out (a set of links, the one node a query
    /// is addressed to); taken without it, it would be something the caller did not ask for.
    NotHonoured(StatementNotHonoured),
    /// What the request carries is past what the session's codec can put in one message.
    ExceedsCapacity,
}

impl From<StatementNotHonoured> for Refusal {
    fn from(statement: StatementNotHonoured) -> Self {
        Self::NotHonoured(statement)
    }
}

impl From<LinksNotHonoured> for Refusal {
    fn from(links: LinksNotHonoured) -> Self {
        Self::NotHonoured(links.into())
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::TableFull => "the session holds as many of these as its bounds allow",
            Self::KeyTooLong => "the key is longer than the session holds",
            Self::NoEntityId => "the session has no entity id left",
            Self::Closed => "the session is closed",
            Self::NotBuilt => "this build does not hold the plane the declaration needs",
            Self::NotHonoured(statement) => return core::fmt::Display::fmt(statement, f),
            Self::ExceedsCapacity => "the request is larger than the session's codec carries",
        })
    }
}

impl core::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    /// Each cause reads as a sentence of its own, so an error a caller logs names which one it was.
    #[test]
    fn each_cause_reads_apart() {
        let all = [
            Refusal::TableFull,
            Refusal::KeyTooLong,
            Refusal::NoEntityId,
            Refusal::Closed,
            Refusal::NotBuilt,
            Refusal::NotHonoured(StatementNotHonoured::TargetPeer),
            Refusal::ExceedsCapacity,
        ];
        let texts: Vec<_> = all.iter().map(ToString::to_string).collect();
        for (at, text) in texts.iter().enumerate() {
            assert!(!text.is_empty());
            assert!(
                texts[at + 1..].iter().all(|other| other != text),
                "{text:?} is said twice"
            );
        }
    }

    /// A set of links an engine cannot honour is refused as that statement, by either name.
    #[test]
    fn a_set_of_links_not_honoured_is_that_statement() {
        assert_eq!(
            Refusal::from(LinksNotHonoured),
            Refusal::NotHonoured(StatementNotHonoured::Links)
        );
    }
}
