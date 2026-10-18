// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `scouting` key of a `--sessions` session: a session that answers Scouts.
//!
//! A node that lists nothing in a document is invisible to a scouter, and a
//! harness that launches its peers from a bundle needs them found the way a
//! stock node is found. The key is zenoh's own `scouting/multicast` block, read
//! per session because the Hello a responder answers with names ONE node: its
//! role, its zid and the locators it listens on, all of which are the session's.
//!
//! ```text
//! { name: "inbound", mode: "peer", transport: "unicast",
//!   listen: { endpoints: ["tcp/192.0.2.10:7447"] },
//!   scouting: { multicast: { listen: true,
//!                            address: "224.0.0.224:7446",   // optional
//!                            interface: "eth0",             // optional
//!                            ttl: 1 } } }                   // optional
//! ```
//!
//! * `listen: true` makes the session answer Scouts on the group; `false` is the
//!   same as no `scouting` key. A session that dials answers as a client with no
//!   locator, and one that listens advertises the address it bound, which is what
//!   its own neighbours are told.
//! * `address`, `interface` and `ttl` are zenoh's `scouting/multicast/address`,
//!   `interface` and `ttl`, and select the group the answer is given on.
//! * A multicast-transport session takes no `scouting` key: it already holds a
//!   group of its own, and a Hello for it would name no dialable locator.
//!
//! The validator the other keys are held to knows nothing of this one, so the key
//! is taken out before the shared rules run (see
//! [`crate::sessions_driver::without_local_keys`]) and judged here.

use wz::runtime_tokio::json5::Json5Value;

use crate::args::ScoutSocketArgs;
use crate::sessions::{as_str, field, has, key_set, positive_int, Refusal};

/// The keys the `scouting` block takes.
const SCOUTING_KEYS: &[&str] = &["multicast"];
/// The keys the `scouting.multicast` block takes.
const MULTICAST_KEYS: &[&str] = &["listen", "address", "interface", "ttl"];

/// Every refusal the `scouting` keys of a document earn, by key path.
pub(crate) fn scouting_refusals(doc: &Json5Value) -> Vec<Refusal> {
    let mut out = Vec::new();
    let Json5Value::Object(top) = doc else {
        return out;
    };
    let Some(Json5Value::Array(sessions)) = field(top, "sessions") else {
        return out;
    };
    for (i, session) in sessions.iter().enumerate() {
        let Json5Value::Object(entries) = session else {
            continue;
        };
        if !has(entries, "scouting") {
            continue;
        }
        let path = format!("sessions[{i}].scouting");
        if field(entries, "transport").and_then(as_str) == Some("multicast") {
            out.push(Refusal::new(
                path,
                "a multicast session takes no scouting block; it holds a group of its own",
            ));
            continue;
        }
        block_refusals(&path, field(entries, "scouting"), &mut out);
    }
    out
}

fn block_refusals(path: &str, block: Option<&Json5Value>, out: &mut Vec<Refusal>) {
    let Some(Json5Value::Object(scouting)) = block else {
        out.push(Refusal::new(path, "must be a mapping"));
        return;
    };
    for key in key_set(scouting) {
        if !SCOUTING_KEYS.contains(&key) {
            out.push(Refusal::new(format!("{path}.{key}"), "unknown key"));
        }
    }
    let Some(multicast) = field(scouting, "multicast") else {
        return;
    };
    let path = format!("{path}.multicast");
    let Json5Value::Object(multicast) = multicast else {
        out.push(Refusal::new(path, "must be a mapping"));
        return;
    };
    for key in key_set(multicast) {
        if !MULTICAST_KEYS.contains(&key) {
            out.push(Refusal::new(format!("{path}.{key}"), "unknown key"));
        }
    }
    if has(multicast, "listen") && !matches!(field(multicast, "listen"), Some(Json5Value::Bool(_)))
    {
        out.push(Refusal::new(
            format!("{path}.listen"),
            "must be true or false",
        ));
    }
    if has(multicast, "address") {
        match field(multicast, "address").and_then(as_str) {
            Some(a) if a.parse::<std::net::SocketAddrV4>().is_ok() => {}
            _ => out.push(Refusal::new(
                format!("{path}.address"),
                "must be an <ip>:<port> socket, e.g. 224.0.0.224:7446",
            )),
        }
    }
    if has(multicast, "interface") {
        match field(multicast, "interface").and_then(as_str) {
            Some(i) if !i.is_empty() => {}
            _ => out.push(Refusal::new(
                format!("{path}.interface"),
                "must be an interface name or address; leave the key out for `auto`",
            )),
        }
    }
    if has(multicast, "ttl") {
        let ok = field(multicast, "ttl")
            .and_then(positive_int)
            .is_some_and(|n| u32::try_from(n).is_ok());
        if !ok {
            out.push(Refusal::new(
                format!("{path}.ttl"),
                "must be a positive hop count",
            ));
        }
    }
}

/// The group a session answers Scouts on, or `None` when its document does not
/// ask for the responder. Only called for a document the rules and
/// [`scouting_refusals`] passed.
pub(crate) fn scouting_of(session: &[(String, Json5Value)]) -> Option<ScoutSocketArgs> {
    let Some(Json5Value::Object(scouting)) = field(session, "scouting") else {
        return None;
    };
    let Some(Json5Value::Object(multicast)) = field(scouting, "multicast") else {
        return None;
    };
    if !matches!(field(multicast, "listen"), Some(Json5Value::Bool(true))) {
        return None;
    }
    Some(ScoutSocketArgs {
        address: field(multicast, "address")
            .and_then(as_str)
            .map(str::to_string),
        interface: field(multicast, "interface")
            .and_then(as_str)
            .map(str::to_string),
        ttl: field(multicast, "ttl")
            .and_then(positive_int)
            .and_then(|n| u32::try_from(n).ok()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::read_sessions_document;
    use wz::runtime_tokio::json5;

    fn with_scouting(block: &str) -> String {
        format!(
            r#"{{ sessions: [ {{ name: "a", mode: "peer", transport: "unicast",
                listen: {{ endpoints: ["tcp/127.0.0.1:0"] }}, scouting: {block} }} ] }}"#
        )
    }

    fn refused(text: &str) -> Vec<String> {
        read_sessions_document(text)
            .expect_err("refused")
            .iter()
            .map(|r| r.to_string())
            .collect()
    }

    /// The block a consumer wrote reads into the group it names; `listen: false`
    /// and no block both read as "does not answer".
    #[test]
    fn a_scouting_block_reads_into_the_group_it_names() {
        let plan = read_sessions_document(&with_scouting(
            r#"{ multicast: { listen: true, address: "224.0.0.99:7000", interface: "lo", ttl: 2 } }"#,
        ))
        .expect("passes");
        assert_eq!(
            plan.sessions[0].scouting,
            Some(ScoutSocketArgs {
                address: Some("224.0.0.99:7000".into()),
                interface: Some("lo".into()),
                ttl: Some(2),
            })
        );
        let bare = read_sessions_document(&with_scouting("{ multicast: { listen: true } }"))
            .expect("passes");
        assert_eq!(bare.sessions[0].scouting, Some(ScoutSocketArgs::default()));
        for silent in [
            "{ multicast: { listen: false } }",
            "{}",
            "{ multicast: {} }",
        ] {
            let plan = read_sessions_document(&with_scouting(silent)).expect("passes");
            assert_eq!(plan.sessions[0].scouting, None, "{silent}");
        }
    }

    /// Every refusal names its key path.
    #[test]
    fn a_malformed_scouting_block_is_refused_by_key() {
        let got = refused(&with_scouting(
            r#"{ gossip: {}, multicast: { listen: "yes", address: "224.0.0.224", interface: "", ttl: 0, loss: 1 } }"#,
        ));
        for want in [
            "sessions[0].scouting.gossip: unknown key",
            "sessions[0].scouting.multicast.loss: unknown key",
            "sessions[0].scouting.multicast.listen: must be true or false",
            "sessions[0].scouting.multicast.address: must be an <ip>:<port> socket, \
             e.g. 224.0.0.224:7446",
            "sessions[0].scouting.multicast.interface: must be an interface name or \
             address; leave the key out for `auto`",
            "sessions[0].scouting.multicast.ttl: must be a positive hop count",
        ] {
            assert!(
                got.iter().any(|g| g == want),
                "missing {want:?} in {got:#?}"
            );
        }
        assert_eq!(
            refused(&with_scouting(r#""on""#)),
            vec!["sessions[0].scouting: must be a mapping"]
        );
        assert_eq!(
            refused(&with_scouting(r#"{ multicast: true }"#)),
            vec!["sessions[0].scouting.multicast: must be a mapping"]
        );
    }

    /// A multicast-transport session holds a group of its own and takes no block.
    #[test]
    fn a_multicast_session_takes_no_scouting_block() {
        let got = refused(
            r#"{ sessions: [ { name: "g", mode: "peer", transport: "multicast",
                group: { endpoint: "udp/224.0.0.224:7446" },
                scouting: { multicast: { listen: true } } } ] }"#,
        );
        assert_eq!(
            got,
            vec![
                "sessions[0].scouting: a multicast session takes no scouting block; \
                  it holds a group of its own"
            ]
        );
    }

    /// The key is taken out before the shared rules, which do not know it.
    #[test]
    fn removing_the_local_keys_changes_nothing_else() {
        let with = json5::parse(&with_scouting("{ multicast: { listen: true } }")).expect("parses");
        let without = json5::parse(
            r#"{ sessions: [ { name: "a", mode: "peer", transport: "unicast",
                listen: { endpoints: ["tcp/127.0.0.1:0"] } } ] }"#,
        )
        .expect("parses");
        assert_eq!(crate::sessions_driver::without_local_keys(&with), without);
    }
}
