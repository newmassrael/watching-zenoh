// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The grants a node's declaration states, read when a node of the heap profile starts (decision
//! D16 of `docs/session-lifecycle-intent.md`).
//!
//! A declaration (`docs/target-build-contract.md`, section 5b) names who may command the node as
//! `[[endpoint]]` rows whose `role` is `commander`, each with the `zid` a key proves and the
//! `verbs` it may command, comma-separated. The fixed profile compiles those rows into its image
//! (`scripts/lib/wz_node.py`); this reads the same rows of the same file into the heap profile's
//! policy, so one declaration states the policy of both profiles and the two cannot disagree about
//! who may command a node. Every other row is the fixed profile's and is not read here.

use std::fmt;

use wz_session_core::lifecycle_monitor::{CommanderGrant, GrantError, HeapGrants};

/// The `role` of the rows that grant verbs.
const COMMANDER_ROLE: &str = "commander";

/// Why a declaration states no grants this node can hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclarationError {
    /// The text is not TOML; the parser's own words.
    NotToml(String),
    /// `endpoint` is not an array of tables.
    EndpointsNotTables,
    /// A commander row (counted from zero among the `endpoint` rows) has no `key`, or its value is
    /// not a string.
    MissingKey {
        /// The row.
        row: usize,
        /// The key it lacks.
        key: &'static str,
    },
    /// A commander row states no grant: its zid or one of its verbs does not read.
    Grant {
        /// The row.
        row: usize,
        /// What is wrong with it.
        error: GrantError,
    },
    /// Two commander rows grant the same zid the same verb.
    Repeated,
}

impl fmt::Display for DeclarationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotToml(why) => write!(f, "the declaration is not TOML: {why}"),
            Self::EndpointsNotTables => f.write_str("`endpoint` is not an array of tables"),
            Self::MissingKey { row, key } => {
                write!(f, "endpoint {row}: a commander states `{key}` as a string")
            }
            Self::Grant { row, error } => write!(f, "endpoint {row}: {}", error.words()),
            Self::Repeated => f.write_str(GrantError::Repeated.words()),
        }
    }
}

impl std::error::Error for DeclarationError {}

/// The grants the declaration `text` states: one per commander row, in the order of the rows. A
/// declaration that names no commander grants nothing, and every request to the node is refused.
pub fn commander_grants(text: &str) -> Result<HeapGrants, DeclarationError> {
    let declaration: toml::Table = text
        .parse()
        .map_err(|error: toml::de::Error| DeclarationError::NotToml(error.message().to_owned()))?;
    let rows = match declaration.get("endpoint") {
        None => return Ok(HeapGrants::default()),
        Some(rows) => rows
            .as_array()
            .ok_or(DeclarationError::EndpointsNotTables)?,
    };
    let mut grants = Vec::new();
    for (row, endpoint) in rows.iter().enumerate() {
        let endpoint = endpoint
            .as_table()
            .ok_or(DeclarationError::EndpointsNotTables)?;
        if endpoint.get("role").and_then(toml::Value::as_str) != Some(COMMANDER_ROLE) {
            continue;
        }
        let text_of = |key: &'static str| {
            endpoint
                .get(key)
                .and_then(toml::Value::as_str)
                .ok_or(DeclarationError::MissingKey { row, key })
        };
        let zid = text_of("zid")?;
        // The declaration may space its verbs (`"open, status"`), as the generator reads them.
        let verbs: Vec<&str> = text_of("verbs")?.split(',').map(str::trim).collect();
        let grant = CommanderGrant::parse(&format!("{zid}={}", verbs.join(",")))
            .map_err(|error| DeclarationError::Grant { row, error })?;
        grants.push(grant);
    }
    HeapGrants::new(grants).map_err(|_| DeclarationError::Repeated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::lifecycle_monitor::{
        decide, Channel, Decision, Grounds, Object, Refusal, Request,
    };
    use wz_session_core::lifecycle_node::{Commander, Verb};

    /// The commander rows of a declaration in the shape `deploy/nodes/slot-commander.toml` states
    /// them, beside rows of other roles.
    const DECLARATION: &str = r#"
schema = 1

[node]
id = "slot-commander"
target = "slot"

[[endpoint]]
role = "dial"
locator = "tls/127.0.0.1:17476"

[[endpoint]]
role = "commander"
zid = "a1"
verbs = "status"

[[endpoint]]
role = "commander"
zid = "b2"
verbs = "close, reset"
"#;

    fn zid(text: &str) -> [u8; 16] {
        wz_session_core::credential_identity::zid_from_key_text(text).expect("a zid")
    }

    /// The grants are the commander rows and nothing else, each zid with its own verbs, read as
    /// the generator reads them. Red if a row of another role granted anything, or if a spaced
    /// verb list lost a verb.
    #[test]
    fn the_commander_rows_are_the_grants() {
        let grants = commander_grants(DECLARATION).expect("grants");
        let stated: Vec<_> = grants
            .grants()
            .iter()
            .map(|grant| {
                (
                    grant.commander,
                    [Verb::Open, Verb::Close, Verb::Reset, Verb::Status]
                        .into_iter()
                        .filter(|verb| grant.verbs.has(*verb))
                        .collect::<Vec<_>>(),
                    grant.key.clone(),
                )
            })
            .collect();
        assert_eq!(
            stated,
            [
                (zid("a1"), vec![Verb::Status], None),
                (zid("b2"), vec![Verb::Close, Verb::Reset], None),
            ]
        );
    }

    /// What the declaration grants is what the monitor permits: a listed zid its verbs, another
    /// zid nothing, and nobody shown nothing. Red if the reader's grants were not the policy the
    /// monitor reads.
    #[test]
    fn the_monitor_judges_by_the_declared_grants() {
        fn close(requester: Option<&[u8; 16]>) -> Request<'_> {
            Request {
                subject: Commander::of_requester(requester),
                verb: Verb::Close,
                object: Object {
                    peer: "d4",
                    generation: None,
                    key: Some("@/c3/peer/session/close/d4"),
                },
                channel: Channel::Query,
            }
        }
        let grants = commander_grants(DECLARATION).expect("grants");
        let (b2, a1) = (zid("b2"), zid("a1"));
        assert_eq!(
            decide(&grants, true, &close(Some(&b2))),
            Decision::Permit(Grounds::Granted)
        );
        assert_eq!(
            decide(&grants, true, &close(Some(&a1))),
            Decision::Deny(Refusal::NotListed)
        );
        assert_eq!(
            decide(&grants, true, &close(None)),
            Decision::Deny(Refusal::Unproven)
        );
    }

    /// A declaration that names no commander grants nothing, and one that is not a declaration
    /// is refused by name, the row it stops at included.
    #[test]
    fn a_declaration_without_commanders_grants_nothing_and_a_bad_one_is_refused() {
        assert_eq!(commander_grants("schema = 1\n"), Ok(HeapGrants::default()));
        assert_eq!(
            commander_grants("[[endpoint]]\nrole = \"dial\"\nlocator = \"tcp/127.0.0.1:7447\"\n"),
            Ok(HeapGrants::default())
        );
        assert!(matches!(
            commander_grants("endpoint = ["),
            Err(DeclarationError::NotToml(_))
        ));
        assert_eq!(
            commander_grants("endpoint = 1\n"),
            Err(DeclarationError::EndpointsNotTables)
        );
        let row = |body: &str| {
            format!("[[endpoint]]\nrole = \"dial\"\n\n[[endpoint]]\nrole = \"commander\"\n{body}")
        };
        assert_eq!(
            commander_grants(&row("verbs = \"open\"\n")),
            Err(DeclarationError::MissingKey { row: 1, key: "zid" })
        );
        assert_eq!(
            commander_grants(&row("zid = \"1f\"\n")),
            Err(DeclarationError::MissingKey {
                row: 1,
                key: "verbs"
            })
        );
        assert_eq!(
            commander_grants(&row("zid = \"1f\"\nverbs = \"hold\"\n")),
            Err(DeclarationError::Grant {
                row: 1,
                error: GrantError::UnknownVerb
            })
        );
        assert_eq!(
            commander_grants(&row("zid = \"01f\"\nverbs = \"open\"\n")),
            Err(DeclarationError::Grant {
                row: 1,
                error: GrantError::NotAZid
            })
        );
        let twice = format!(
            "{}\n[[endpoint]]\nrole = \"commander\"\nzid = \"1f\"\nverbs = \"open\"\n",
            row("zid = \"1f\"\nverbs = \"open, close\"\n")
        );
        assert_eq!(commander_grants(&twice), Err(DeclarationError::Repeated));
    }
}
