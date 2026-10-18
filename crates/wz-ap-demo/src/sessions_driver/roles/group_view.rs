// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `group_view`: join the group `group` and print what the view of it shows.
//!
//! A zenoh group has no observer that is not a member: the view is built from
//! the announcements members make, and only a member hears them. This role
//! therefore joins as a member (`member_id` and `lease_ms` mean what they mean
//! for `group_member`) and reports, besides the join, every change of the view.
//!
//! With `size` it also judges the view once: it waits up to `timeout_ms` for the
//! view to hold at least that many members, the local one included, and says
//! whether it did. The events keep being printed after the verdict.
//!
//! The event kinds are the variant names of the group module's own event type.
//! The group module declares `NewLeader` and never emits it, as upstream does:
//! the leader is a query over the view, not an event.
//!
//! The role sits behind the `group` build feature, like `--group-join`.

#[cfg(feature = "group")]
use std::time::Duration;

#[cfg(feature = "group")]
use wz::runtime_tokio::group::{Group, GroupEvent, GroupOptions};

#[cfg(feature = "group")]
use super::group_member::member_of;
use crate::sessions_driver::{Args, Ctx, KeyDef, KeyKind, Play, RoleDef};

/// How long `size` is waited for when the document names no `timeout_ms`.
#[cfg(feature = "group")]
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 3_000;

// `timeout_ms` is optional and not `defaulted`: the rule below must tell a
// timeout the document wrote from one the table filled in, and a defaulted key
// reads the same either way.
pub(crate) static ROLE: RoleDef = RoleDef::gated(
    "group_view",
    &[
        KeyDef::required("group", KeyKind::Text),
        KeyDef::optional("member_id", KeyKind::Text),
        KeyDef::optional("lease_ms", KeyKind::Millis),
        KeyDef::optional("size", KeyKind::Count),
        KeyDef::optional("timeout_ms", KeyKind::Millis),
    ],
    "group",
    cfg!(feature = "group"),
    play,
)
.checked(check);

/// A timeout is the wait for `size`; without one it would be accepted and
/// silently mean nothing.
fn check(args: &Args) -> Vec<(&'static str, String)> {
    if args.int("timeout_ms").is_some() && args.int("size").is_none() {
        vec![(
            "timeout_ms",
            "is the wait for `size` and means nothing without it; name `size` or drop it"
                .to_string(),
        )]
    } else {
        Vec::new()
    }
}

/// The kind and the member of one group event, as the `event` line prints them.
#[cfg(feature = "group")]
fn event_parts(event: &GroupEvent) -> (&'static str, String) {
    match event {
        GroupEvent::Join(member) => ("Join", member.id().to_string()),
        GroupEvent::Leave(id) => ("Leave", id.clone()),
        GroupEvent::LeaseExpired(id) => ("LeaseExpired", id.clone()),
        GroupEvent::NewLeader(id) => ("NewLeader", id.clone()),
    }
}

/// The `view` line for the members of the view, sorted.
#[cfg(feature = "group")]
fn view_line(mut members: Vec<String>) -> String {
    members.sort();
    format!("view size={} members={}", members.len(), members.join(","))
}

#[cfg(feature = "group")]
fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

#[cfg(not(feature = "group"))]
fn play(_ctx: Ctx) -> Play {
    Box::pin(async {})
}

#[cfg(feature = "group")]
async fn run(ctx: Ctx) {
    let group_id = ctx.text("group");
    let member = member_of(ctx.args());
    let id = member.id().to_string();
    // The receiver is installed before the event subscriber is declared, so no
    // event between the join and the first read is lost.
    let (group, mut events) = match Group::join_with_events(
        &ctx.session,
        group_id.clone(),
        member,
        GroupOptions::default(),
    ) {
        Ok(joined) => joined,
        Err(e) => {
            ctx.say.line(&format!("refused group={group_id}: {e:?}"));
            return;
        }
    };
    ctx.say
        .line(&format!("joined group={group_id} member={id}"));

    let wanted = ctx
        .int("size")
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX));
    let timeout = Duration::from_millis(ctx.int("timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS));
    let verdict = async {
        match wanted {
            Some(size) => Some((size, group.wait_for_view_size(size, timeout).await)),
            None => std::future::pending::<Option<(usize, bool)>>().await,
        }
    };
    tokio::pin!(verdict);
    let mut judged = false;
    loop {
        tokio::select! {
            event = events.recv() => {
                // The channel closes only when the group is dropped, which this
                // loop prevents; the arm keeps the loop total.
                let Some(event) = event else { break };
                let (kind, member) = event_parts(&event);
                ctx.say.line(&format!("event kind={kind} member={member}"));
                let members = group.view().iter().map(|m| m.id().to_string()).collect();
                ctx.say.line(&view_line(members));
            }
            result = &mut verdict, if !judged => {
                judged = true;
                match result {
                    Some((size, true)) => ctx.say.line(&format!("view reached size={size}")),
                    Some((size, false)) => ctx
                        .say
                        .line(&format!("view timed out size={size} have={}", group.size())),
                    None => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{read_sessions_document, BuildCapabilities};
    use crate::sessions_driver::{DriverEntry, Value};

    fn doc(role: &str) -> String {
        format!(
            r#"{{ sessions: [ {{ name: "a", mode: "client", transport: "unicast",
            connect: {{ endpoints: ["tcp/127.0.0.1:7447"] }}, driver: [ {role} ] }} ] }}"#
        )
    }

    fn refused(role: &str) -> Vec<String> {
        match read_sessions_document(&doc(role)) {
            Ok(_) => Vec::new(),
            Err(refusals) => refusals.iter().map(|r| r.to_string()).collect(),
        }
    }

    fn entry(role: &str) -> DriverEntry {
        let plan = read_sessions_document(&doc(role)).expect("the document is accepted");
        plan.sessions[0].driver[0].clone()
    }

    #[test]
    fn the_role_is_available_exactly_when_the_feature_is() {
        assert_eq!(ROLE.available, cfg!(feature = "group"));
        assert_eq!(ROLE.feature, Some("group"));
        let this = BuildCapabilities::of_this_build();
        assert_eq!(this.driver_roles.contains(&"group_view"), ROLE.available);
    }

    /// Every key is read as written, and the timeout is not filled in when the
    /// document names none.
    #[test]
    fn the_accepted_document_is_read_into_its_keys() {
        assert_eq!(
            entry(
                r#"{ role: "group_view", group: "g", member_id: "v", lease_ms: 900, size: 2, timeout_ms: 5000, after_ms: 3 }"#
            ),
            DriverEntry {
                word: "group_view",
                after_ms: 3,
                args: Args::of(&[
                    ("group", Value::Text("g".into())),
                    ("member_id", Value::Text("v".into())),
                    ("lease_ms", Value::Int(900)),
                    ("size", Value::Int(2)),
                    ("timeout_ms", Value::Int(5000)),
                ]),
            }
        );
        assert_eq!(
            entry(r#"{ role: "group_view", group: "g", size: 3 }"#).args,
            Args::of(&[("group", Value::Text("g".into())), ("size", Value::Int(3)),])
        );
        assert_eq!(
            entry(r#"{ role: "group_view", group: "g" }"#).args,
            Args::of(&[("group", Value::Text("g".into()))])
        );
    }

    #[test]
    fn a_key_missing_misplaced_or_of_the_wrong_kind_is_refused_by_path() {
        assert_eq!(
            refused(r#"{ role: "group_view", size: 2 }"#),
            vec!["sessions[0].driver[0].group: required, a string"]
        );
        assert_eq!(
            refused(r#"{ role: "group_view", group: "g", payload: "x" }"#),
            vec!["sessions[0].driver[0].payload: not a key of the `group_view` role"]
        );
        assert_eq!(
            refused(r#"{ role: "group_view", group: "g", size: 0 }"#),
            vec!["sessions[0].driver[0].size: must be a positive integer"]
        );
        assert_eq!(
            refused(r#"{ role: "group_view", group: "g", size: 2, timeout_ms: "soon" }"#),
            vec!["sessions[0].driver[0].timeout_ms: must be a positive integer"]
        );
    }

    /// The cross-key rule: a timeout without the size it waits for is refused at
    /// the timeout, and with the size it is accepted.
    #[test]
    fn a_timeout_without_a_size_is_refused_naming_the_key() {
        assert_eq!(
            refused(r#"{ role: "group_view", group: "g", timeout_ms: 500 }"#),
            vec![
                "sessions[0].driver[0].timeout_ms: is the wait for `size` and means nothing \
                 without it; name `size` or drop it"
            ]
        );
        assert!(
            refused(r#"{ role: "group_view", group: "g", size: 2, timeout_ms: 500 }"#).is_empty()
        );
        assert!(refused(r#"{ role: "group_view", group: "g", size: 2 }"#).is_empty());
    }

    /// A build that was made without the feature refuses the role by key path,
    /// naming the feature to build with.
    #[test]
    fn a_build_without_the_feature_refuses_the_role_by_key_path() {
        let plan = read_sessions_document(&doc(r#"{ role: "group_view", group: "g" }"#))
            .expect("the document is accepted");
        let without = BuildCapabilities {
            multicast: false,
            iface: false,
            scouting_responder: false,
            driver_roles: Vec::new(),
            schemes: vec!["tcp"],
        };
        let refusals: Vec<String> = plan
            .build_refusals(&without)
            .iter()
            .map(|r| r.to_string())
            .collect();
        assert_eq!(
            refusals,
            vec![
                "sessions[0].driver[0].role: the `group_view` role needs the `group` build \
                 feature (build: cargo build -p wz-ap-demo --features group)"
            ]
        );
    }

    #[cfg(feature = "group")]
    #[test]
    fn events_are_named_by_the_variants_of_the_event_type() {
        use wz::runtime_tokio::group::Member;
        assert_eq!(
            event_parts(&GroupEvent::Join(Member::new("a"))),
            ("Join", "a".to_string())
        );
        assert_eq!(
            event_parts(&GroupEvent::Leave("b".into())),
            ("Leave", "b".to_string())
        );
        assert_eq!(
            event_parts(&GroupEvent::LeaseExpired("c".into())),
            ("LeaseExpired", "c".to_string())
        );
        assert_eq!(
            event_parts(&GroupEvent::NewLeader("d".into())),
            ("NewLeader", "d".to_string())
        );
    }

    #[cfg(feature = "group")]
    #[test]
    fn the_view_line_lists_the_members_sorted_and_counts_them() {
        assert_eq!(
            view_line(vec!["m2".into(), "m10".into(), "a".into()]),
            "view size=3 members=a,m10,m2"
        );
        assert_eq!(view_line(vec!["only".into()]), "view size=1 members=only");
    }
}
