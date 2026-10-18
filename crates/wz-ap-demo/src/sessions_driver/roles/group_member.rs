// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `group_member`: join the group `group` as member `member_id` and stay one.
//!
//! The member id is the literal a peer prints in its view of the group, so a
//! document can pin it; left out, it is the one `--group-join` uses, which keeps
//! the two ways of joining the same group the same member. `lease_ms` is the
//! member's lease in milliseconds (`--group-lease-secs` counts seconds); left
//! out, the lease is the group module's own default.
//!
//! The membership is held until the session ends: dropping the handle would
//! retract the member's announcements, which is the state a peer's view is
//! meant to show.
//!
//! The role sits behind the `group` build feature, like `--group-join`.

#[cfg(feature = "group")]
use std::time::Duration;

#[cfg(feature = "group")]
use wz::runtime_tokio::group::{Group, GroupOptions, Member};

#[cfg(feature = "group")]
use crate::sessions_driver::Args;
use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

/// The member id a document that names none joins as: the one `--group-join`
/// defaults to.
#[cfg(feature = "group")]
pub(crate) const DEFAULT_MEMBER_ID: &str = "wz-member";

pub(crate) static ROLE: RoleDef = RoleDef::gated(
    "group_member",
    &[
        KeyDef::required("group", KeyKind::Text),
        KeyDef::optional("member_id", KeyKind::Text),
        KeyDef::optional("lease_ms", KeyKind::Millis),
    ],
    "group",
    cfg!(feature = "group"),
    play,
);

/// The member id the entry names, else [`DEFAULT_MEMBER_ID`].
#[cfg(feature = "group")]
pub(crate) fn member_id_of(args: &Args) -> String {
    args.text("member_id")
        .unwrap_or(DEFAULT_MEMBER_ID)
        .to_string()
}

/// The lease the entry names; `None` leaves the group module's default.
#[cfg(feature = "group")]
pub(crate) fn lease_of(args: &Args) -> Option<Duration> {
    args.int("lease_ms").map(Duration::from_millis)
}

/// The member an entry joins as.
#[cfg(feature = "group")]
pub(crate) fn member_of(args: &Args) -> Member {
    let member = Member::new(member_id_of(args));
    match lease_of(args) {
        Some(lease) => member.lease(lease),
        None => member,
    }
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
    let group = ctx.text("group");
    let member = member_of(ctx.args());
    let id = member.id().to_string();
    match Group::join(&ctx.session, group.clone(), member, GroupOptions::default()) {
        Ok(_held) => {
            ctx.say.line(&format!("joined group={group} member={id}"));
            ctx.hold().await;
        }
        // A wildcard or non-canonical id lands here; the debug form names the
        // variant, which is what tells the two apart.
        Err(e) => ctx.say.line(&format!("refused group={group}: {e:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{read_sessions_document, BuildCapabilities};
    use crate::sessions_driver::{Args, DriverEntry, Value};

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
        assert_eq!(this.driver_roles.contains(&"group_member"), ROLE.available);
    }

    /// The keys are read as the document gave them, and a key it left out is
    /// absent: neither default is applied in the arguments.
    #[test]
    fn the_accepted_document_is_read_into_its_keys() {
        assert_eq!(
            entry(
                r#"{ role: "group_member", group: "g/1", member_id: "m1", lease_ms: 4000, after_ms: 9 }"#
            ),
            DriverEntry {
                word: "group_member",
                after_ms: 9,
                args: Args::of(&[
                    ("group", Value::Text("g/1".into())),
                    ("member_id", Value::Text("m1".into())),
                    ("lease_ms", Value::Int(4000)),
                ]),
            }
        );
        assert_eq!(
            entry(r#"{ role: "group_member", group: "g/1" }"#).args,
            Args::of(&[("group", Value::Text("g/1".into()))])
        );
    }

    #[test]
    fn a_key_missing_misplaced_or_of_the_wrong_kind_is_refused_by_path() {
        assert_eq!(
            refused(r#"{ role: "group_member" }"#),
            vec!["sessions[0].driver[0].group: required, a string"]
        );
        assert_eq!(
            refused(r#"{ role: "group_member", group: "g", key: "k" }"#),
            vec!["sessions[0].driver[0].key: not a key of the `group_member` role"]
        );
        // The viewer's keys belong to the viewer.
        assert_eq!(
            refused(r#"{ role: "group_member", group: "g", size: 2 }"#),
            vec!["sessions[0].driver[0].size: not a key of the `group_member` role"]
        );
        assert_eq!(
            refused(r#"{ role: "group_member", group: "g", lease_ms: 0 }"#),
            vec!["sessions[0].driver[0].lease_ms: must be a positive integer"]
        );
        assert_eq!(
            refused(r#"{ role: "group_member", group: "g", member_id: 7 }"#),
            vec!["sessions[0].driver[0].member_id: must be a string"]
        );
    }

    /// A build that was made without the feature refuses the role by key path,
    /// naming the feature to build with.
    #[test]
    fn a_build_without_the_feature_refuses_the_role_by_key_path() {
        let plan = read_sessions_document(&doc(r#"{ role: "group_member", group: "g" }"#))
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
                "sessions[0].driver[0].role: the `group_member` role needs the `group` build \
                 feature (build: cargo build -p wz-ap-demo --features group)"
            ]
        );
    }

    #[cfg(feature = "group")]
    #[test]
    fn the_member_id_and_lease_default_as_the_one_shot_join_does() {
        let bare = entry(r#"{ role: "group_member", group: "g" }"#).args;
        assert_eq!(member_id_of(&bare), "wz-member");
        assert_eq!(lease_of(&bare), None);
        let named =
            entry(r#"{ role: "group_member", group: "g", member_id: "m2", lease_ms: 1500 }"#).args;
        assert_eq!(member_id_of(&named), "m2");
        assert_eq!(lease_of(&named), Some(Duration::from_millis(1500)));
        assert_eq!(member_of(&named).id(), "m2");
    }
}
