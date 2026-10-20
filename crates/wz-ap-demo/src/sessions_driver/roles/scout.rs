// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `scout`: ask the scouting group who is there and print every answer, dialling
//! nobody.
//!
//! The one-shot `--scout` mode resolves ONE locator and opens a session at it.
//! This role only observes: it sends one Scout for the roles `what` names, keeps
//! the window open for `timeout_ms`, and says one line per Hello that came back,
//! so a harness can see which nodes of a network answer and as what.
//!
//! `address`, `interface` and `ttl` are zenoh's `scouting/multicast/address`,
//! `interface` and `ttl`, with the meaning and the spelling they have in a
//! session's `scouting.multicast` block (`sessions_scouting`).
//!
//! ```text
//! { role: "scout", what: "router,peer", address: "224.0.0.224:7446",
//!   interface: "eth0", ttl: 1, timeout_ms: 3000 }
//! ```
//!
//! Lines: `started what=<list> group=<ip>:<port>`, then one
//! `hello zid=<hex> whatami=<role> locators=<a;b>` per Hello (`none` when the
//! node advertised no locator) and `done hellos=<n>` once the window ends.

#[cfg(feature = "scouting-active")]
use std::net::{IpAddr, Ipv4Addr};
#[cfg(feature = "scouting-active")]
use std::time::Duration;

#[cfg(feature = "scouting-active")]
use wz::runtime_tokio::runtime_impl::TokioTime;
#[cfg(feature = "scouting-active")]
use wz::runtime_tokio::scouting_fanout::{
    bind_scout_sockets, scout_interface_addresses, ScoutFanOut,
};
#[cfg(feature = "scouting-active")]
use wz::runtime_tokio::scouting_glue::{
    drive_scouting_until_resolved, new_scouting_engine, ScoutOutcome, ScoutParams, ScoutedHello,
    ScoutingActions,
};
#[cfg(feature = "scouting-active")]
use wz::runtime_tokio::UdpDriver;

#[cfg(feature = "scouting-active")]
use crate::args::ScoutSocketArgs;
#[cfg(feature = "scouting-active")]
use crate::sessions_driver::Say;
use crate::sessions_driver::{Args, Ctx, KeyDef, KeyKind, Play, RoleDef};

/// How long the window collects Hellos when the document names no `timeout_ms`.
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 3_000;

/// The roles a Scout asks for when the document names no `what`: what a client
/// looks for (zenoh's `scouting/multicast/autoconnect.client`).
#[cfg(feature = "scouting-active")]
const DEFAULT_WHAT: &str = "router,peer";

/// The group a Scout goes to when the document names no `address`: zenoh's own
/// default, the one the one-shot `--scout` and the responder join.
#[cfg(feature = "scouting-active")]
const DEFAULT_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
#[cfg(feature = "scouting-active")]
const DEFAULT_PORT: u16 = 7446;

/// How often the window's new Hellos are looked for while it runs. It also paces
/// the window's own deadline check, so it bounds how late `done` can be.
#[cfg(feature = "scouting-active")]
const TICK_MS: u64 = 50;

/// The roles a Scout can ask for and the bit each takes in its `what` mask
/// (`WhatAmIMatcher`: router 0b001, peer 0b010, client 0b100).
const ROLE_BITS: [(&str, u8); 3] = [("router", 0b001), ("peer", 0b010), ("client", 0b100)];

const WHAT_EXPECTED: &str = "expected a comma-separated list of router, peer or client";

pub(crate) static ROLE: RoleDef = RoleDef::gated(
    "scout",
    &[
        KeyDef::optional("what", KeyKind::Text),
        KeyDef::optional("address", KeyKind::Text),
        KeyDef::optional("interface", KeyKind::Text),
        KeyDef::optional("ttl", KeyKind::Count),
        KeyDef::defaulted("timeout_ms", KeyKind::Millis, DEFAULT_TIMEOUT_MS),
    ],
    "scouting-active",
    cfg!(feature = "scouting-active"),
    play,
)
.checked(check);

/// The Scout's `what` mask for a comma-separated list of roles, or why the list
/// is refused. An empty word is refused too: `router,,peer` is a typo, and a
/// Scout that silently asked for fewer roles finds fewer nodes with nothing to
/// say why.
fn what_mask(list: &str) -> Result<u8, String> {
    let mut mask = 0u8;
    for word in list.split(',') {
        let word = word.trim();
        match ROLE_BITS.iter().find(|(name, _)| *name == word) {
            Some((_, bit)) => mask |= *bit,
            None if word.is_empty() => return Err(format!("an empty word; {WHAT_EXPECTED}")),
            None => return Err(format!("`{word}` is not a role; {WHAT_EXPECTED}")),
        }
    }
    Ok(mask)
}

/// The roles of a `what` mask in a fixed order, comma-separated.
#[cfg(feature = "scouting-active")]
fn what_list(mask: u8) -> String {
    ROLE_BITS
        .iter()
        .filter(|(_, bit)| mask & *bit != 0)
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(",")
}

/// The rules beyond a key's kind. The three socket keys are judged as the
/// session's `scouting.multicast` block and `--scout-addr` judge them, so one
/// spelling means one thing wherever it is written.
fn check(args: &Args) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if let Some(list) = args.text("what") {
        if let Err(why) = what_mask(list) {
            out.push(("what", why));
        }
    }
    if let Some(address) = args.text("address") {
        if address.parse::<std::net::SocketAddrV4>().is_err() {
            out.push((
                "address",
                "must be an <ip>:<port> socket, e.g. 224.0.0.224:7446".to_string(),
            ));
        }
    }
    if args.text("interface").is_some_and(str::is_empty) {
        out.push((
            "interface",
            "must be an interface name or address; leave the key out for `auto`".to_string(),
        ));
    }
    if args.int("ttl").is_some_and(|n| u32::try_from(n).is_err()) {
        out.push(("ttl", "must be a positive hop count".to_string()));
    }
    out
}

#[cfg(feature = "scouting-active")]
fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

#[cfg(not(feature = "scouting-active"))]
fn play(_ctx: Ctx) -> Play {
    Box::pin(async {})
}

/// The sockets of one window: the Scout leaves by every multicast-capable
/// interface and each Hello comes back to the socket its Scout left from, as in
/// zenoh (one unicast socket per interface) and in the survey of the C ABI.
///
/// A build that cannot enumerate interfaces, and a document that names one
/// `interface`, ask on one socket pinned as the document says. That socket is
/// never the group socket: a Hello is unicast to the asker's source port, and a
/// source port shared with another scouting node on the host (the responder
/// binds the group port too) would hand the Hello to whichever socket the kernel
/// picks. The group socket only listens.
#[cfg(feature = "scouting-active")]
async fn bind_window(
    group: Ipv4Addr,
    port: u16,
    socket: &ScoutSocketArgs,
) -> Result<ScoutFanOut, String> {
    let group_ip = IpAddr::V4(group);
    let locals = if socket.interface.is_some() {
        Vec::new()
    } else {
        scout_interface_addresses().unwrap_or_default()
    };
    let (mut ask, refused) = bind_scout_sockets(group_ip, port, &locals, socket.ttl).await;
    if ask.is_empty() {
        let one = UdpDriver::bind_multicast_tx(group_ip, port, socket.as_socket_config())
            .await
            .map_err(|e| format!("could not open a scouting socket: {e}"))?;
        ask.push(one);
    }
    let listening = UdpDriver::bind_scouting_group(group_ip, port, socket.as_socket_config())
        .await
        .ok();
    ScoutFanOut::over_optional(listening, ask, refused)
        .map(|(driver, _shape)| driver)
        .ok_or_else(|| "no socket to scout with".to_string())
}

/// One Hello as a line.
#[cfg(feature = "scouting-active")]
fn hello_line(hello: &ScoutedHello) -> String {
    let locators = if hello.locators.is_empty() {
        "none".to_string()
    } else {
        hello.locators.join(";")
    };
    format!(
        "hello zid={} whatami={} locators={locators}",
        wz::runtime_tokio::zid_hex::zid_to_zenoh_hex(&hello.zid),
        hello.whatami.map_or("unknown", |w| w.to_str()),
    )
}

/// Say the Hellos recorded since the last call, and return how many have been
/// said. The window records them as they arrive and only returns at its end, so
/// a harness waiting on a line sees each Hello when it came.
#[cfg(feature = "scouting-active")]
fn report(say: &Say, hellos: &[ScoutedHello], said: usize) -> usize {
    for hello in hellos.iter().skip(said) {
        say.line(&hello_line(hello));
    }
    hellos.len()
}

#[cfg(feature = "scouting-active")]
async fn run(ctx: Ctx) {
    let what = ctx.args().text("what").unwrap_or(DEFAULT_WHAT);
    let mask = match what_mask(what) {
        Ok(mask) => mask,
        Err(why) => {
            ctx.say.line(&format!("refused what={what}: {why}"));
            return;
        }
    };
    let socket = ScoutSocketArgs {
        address: ctx.args().text("address").map(str::to_string),
        interface: ctx.args().text("interface").map(str::to_string),
        ttl: ctx.int("ttl").and_then(|n| u32::try_from(n).ok()),
    };
    let (group, port) = socket.group_and_port(DEFAULT_GROUP, DEFAULT_PORT);
    let mut driver = match bind_window(group, port, &socket).await {
        Ok(driver) => driver,
        Err(why) => {
            ctx.say
                .line(&format!("refused group={group}:{port}: {why}"));
            return;
        }
    };
    let actions = ScoutingActions::new(ScoutParams {
        what: mask,
        zid: ctx.session.zid().to_vec(),
        timeout_ms: ctx.int("timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS),
        // The survey arm: every node of the window is reported, not the first.
        exit_on_first: false,
    });
    let mut engine = new_scouting_engine(&actions);
    let clock = TokioTime::new();
    ctx.say.line(&format!(
        "started what={} group={group}:{port}",
        what_list(mask)
    ));
    let window =
        drive_scouting_until_resolved(&mut driver, &actions, &mut engine, &clock, None, TICK_MS);
    tokio::pin!(window);
    let mut said = 0;
    let outcome = loop {
        tokio::select! {
            outcome = &mut window => break outcome,
            () = tokio::time::sleep(Duration::from_millis(TICK_MS)) => {
                said = report(&ctx.say, &actions.scouted_hellos(), said);
            }
        }
    };
    said = report(&ctx.say, &actions.scouted_hellos(), said);
    if let ScoutOutcome::LinkLost(cause) = outcome {
        ctx.say.line(&format!("lost the scouting link: {cause:?}"));
    }
    ctx.say.line(&format!("done hellos={said}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{read_sessions_document, BuildCapabilities};
    use crate::sessions_driver::{all_words, available_words, Value};

    fn with_role(role: &str) -> String {
        format!(
            r#"{{ sessions: [ {{ name: "a", mode: "client", transport: "unicast",
                connect: {{ endpoints: ["tcp/127.0.0.1:7447"] }}, driver: [ {role} ] }} ] }}"#
        )
    }

    fn refused(role: &str) -> Vec<String> {
        read_sessions_document(&with_role(role))
            .expect_err("refused")
            .iter()
            .map(|r| r.to_string())
            .collect()
    }

    fn args_of(role: &str) -> Args {
        let plan = read_sessions_document(&with_role(role)).expect("accepted");
        plan.sessions[0].driver[0].args.clone()
    }

    /// The keys read into what the document wrote; the window is the only key with
    /// a default.
    #[test]
    fn the_accepted_forms_read_into_their_keys() {
        assert_eq!(
            args_of(
                r#"{ role: "scout", what: "client,peer", address: "224.0.0.99:7000",
                    interface: "lo", ttl: 2, timeout_ms: 500 }"#
            ),
            Args::of(&[
                ("what", Value::Text("client,peer".into())),
                ("address", Value::Text("224.0.0.99:7000".into())),
                ("interface", Value::Text("lo".into())),
                ("ttl", Value::Int(2)),
                ("timeout_ms", Value::Int(500)),
            ])
        );
        assert_eq!(
            args_of(r#"{ role: "scout" }"#),
            Args::of(&[("timeout_ms", Value::Int(DEFAULT_TIMEOUT_MS))])
        );
    }

    /// Every word of `what` is a role, in any order and with any spacing; an
    /// unknown or empty word is refused, whatever else is in the list.
    #[test]
    fn what_is_a_list_of_roles() {
        assert_eq!(what_mask("router,peer"), Ok(0b011));
        assert_eq!(what_mask("client"), Ok(0b100));
        assert_eq!(what_mask(" peer , router,peer"), Ok(0b011));
        assert_eq!(what_mask("router,peer,client"), Ok(0b111));
        for (list, why) in [
            ("satellite", "`satellite` is not a role"),
            ("router,gateway", "`gateway` is not a role"),
            ("", "an empty word"),
            ("router,,peer", "an empty word"),
            ("peer,", "an empty word"),
        ] {
            assert_eq!(
                what_mask(list),
                Err(format!("{why}; {WHAT_EXPECTED}")),
                "{list:?}"
            );
        }
    }

    /// Each refusal names its key; a key the role does not take, and a key of
    /// another role, are refused as for every role.
    #[test]
    fn a_malformed_scout_is_refused_by_key() {
        assert_eq!(
            refused(r#"{ role: "scout", what: "router,satellite" }"#),
            vec![format!(
                "sessions[0].driver[0].what: `satellite` is not a role; {WHAT_EXPECTED}"
            )]
        );
        assert_eq!(
            refused(r#"{ role: "scout", what: "" }"#),
            vec![format!(
                "sessions[0].driver[0].what: an empty word; {WHAT_EXPECTED}"
            )]
        );
        assert_eq!(
            refused(r#"{ role: "scout", address: "224.0.0.224", interface: "", ttl: 4294967296 }"#),
            vec![
                "sessions[0].driver[0].address: must be an <ip>:<port> socket, e.g. \
                 224.0.0.224:7446"
                    .to_string(),
                "sessions[0].driver[0].interface: must be an interface name or address; \
                 leave the key out for `auto`"
                    .to_string(),
                "sessions[0].driver[0].ttl: must be a positive hop count".to_string(),
            ]
        );
        assert_eq!(
            refused(r#"{ role: "scout", what: 3, ttl: 0, timeout_ms: 0 }"#),
            vec![
                "sessions[0].driver[0].what: must be a string",
                "sessions[0].driver[0].ttl: must be a positive integer",
                "sessions[0].driver[0].timeout_ms: must be a positive integer",
            ]
        );
        assert_eq!(
            refused(r#"{ role: "scout", key: "d/q" }"#),
            vec!["sessions[0].driver[0].key: not a key of the `scout` role"]
        );
        assert_eq!(
            refused(r#"{ role: "get", key: "d/q", what: "peer" }"#),
            vec!["sessions[0].driver[0].what: not a key of the `get` role"]
        );
    }

    /// The role is played exactly when the build has `scouting-active`; a build
    /// without it is refused at the role's own key and says which feature it needs.
    #[test]
    fn the_role_needs_the_scouting_active_build() {
        assert_eq!(ROLE.feature, Some("scouting-active"));
        assert_eq!(ROLE.available, cfg!(feature = "scouting-active"));
        assert_eq!(
            available_words().contains(&"scout"),
            cfg!(feature = "scouting-active")
        );
        let plan =
            read_sessions_document(&with_role(r#"{ role: "scout" }"#)).expect("passes the rules");
        let without = BuildCapabilities {
            multicast: true,
            iface: true,
            scouting_responder: true,
            access_multicast: true,
            driver_roles: all_words().into_iter().filter(|w| *w != "scout").collect(),
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
                "sessions[0].driver[0].role: the `scout` role needs the `scouting-active` \
                 build feature (build: cargo build -p wz-ap-demo --features scouting-active)"
            ]
        );
    }

    /// A Hello says its zid in zenoh's printed form and its locators joined by
    /// `;`, `none` when it advertised none, and `unknown` for a role no bit names.
    #[cfg(feature = "scouting-active")]
    #[test]
    fn a_hello_is_one_line() {
        let hello = ScoutedHello {
            version: 9,
            whatami: None,
            zid: vec![0x01, 0xdd],
            locators: vec!["tcp/192.0.2.1:7447".into(), "udp/192.0.2.1:7447".into()],
        };
        assert_eq!(
            hello_line(&hello),
            "hello zid=dd01 whatami=unknown locators=tcp/192.0.2.1:7447;udp/192.0.2.1:7447"
        );
        let bare = ScoutedHello {
            locators: Vec::new(),
            ..hello
        };
        assert_eq!(
            hello_line(&bare),
            "hello zid=dd01 whatami=unknown locators=none"
        );
    }

    /// The echoed list is in a fixed order whatever order the document wrote.
    #[cfg(feature = "scouting-active")]
    #[test]
    fn the_started_list_is_in_a_fixed_order() {
        assert_eq!(what_list(0b011), "router,peer");
        assert_eq!(what_list(0b111), "router,peer,client");
        assert_eq!(what_list(0b100), "client");
        assert_eq!(
            what_mask("client,router").map(what_list),
            Ok("router,client".to_string())
        );
    }
}
