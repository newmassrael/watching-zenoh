// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The scouting DRIVE both C ABIs' `z_scout` runs.
//!
//! ## Why it is here
//!
//! `z_scout` exists in zenoh-pico's ABI and in zenoh-c's, with different
//! argument types and different config spellings — but the thing between those
//! two shims is identical: bind the multicast group, drive the scouting FSM in
//! cycles until the caller's budget is spent, and report each DISTINCT peer
//! once. That middle is what lives here, expressed over
//! [`ScoutedHello`](wz_runtime_tokio::scouting_glue::ScoutedHello), which is
//! already an ABI-neutral type.
//!
//! Nothing here has a `z_` in its name, per this crate's contract; the ABI
//! crates map a hello onto their own `z_owned_hello_t`.
//!
//! ## Cycles, not one long window
//!
//! The scouting FSM RESOLVES a cycle as soon as it discovers a peer, so a single
//! window would return after the FIRST Hello and a second responder on the same
//! group would never be reported. Re-entering keeps collecting until the budget
//! is spent, which is what makes `z_scout` a SURVEY rather than a first-answer
//! lookup.
//!
//! ## Distinct by ZID, not by arrival
//!
//! Every cycle re-scouts and a live responder answers each Scout, so the
//! registry records the same peer once per cycle. A cursor over the recorded
//! list therefore reports one peer N times. The real `z_scout` binary prints ONE
//! line for one responder, so delivery is keyed on the zid — a peer that changes
//! its advertised locators mid-scout is still one peer.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use wz_runtime_tokio::scouting_glue::ScoutedHello;

/// zenoh's default scouting multicast locator.
pub const MULTICAST_LOCATOR_DEFAULT: &str = "udp/224.0.0.224:7446";
/// The default scouting budget, in milliseconds (pico
/// `Z_CONFIG_SCOUTING_TIMEOUT_DEFAULT`, `config.h.in:141`).
pub const SCOUTING_TIMEOUT_DEFAULT_MS: u64 = 1000;
/// The default `what` mask (pico `Z_CONFIG_SCOUTING_WHAT_DEFAULT`,
/// `config.h.in:149`) = ROUTER|PEER.
pub const SCOUTING_WHAT_DEFAULT: u8 = 0x03;
/// The protocol version byte wz announces in its Scout.
pub const SCOUT_PROTO_VERSION: u8 = 0x09;
/// One discovery cycle. The budget is spent across repeated cycles, so this is
/// the granularity at which new hellos surface, not the total.
pub const SCOUT_CYCLE_MS: u64 = 1000;
/// The scouting drive-loop tick.
pub const SCOUT_TICK_MS: u64 = 50;

/// Parse a `udp/ADDR:PORT` multicast locator.
pub fn parse_multicast_locator(locator: &str) -> Option<(Ipv4Addr, u16)> {
    let rest = locator.strip_prefix("udp/")?;
    let (addr, port) = rest.rsplit_once(':')?;
    Some((addr.parse().ok()?, port.parse().ok()?))
}

/// Parse a hex zid, most-significant-first, up to 16 bytes.
pub fn parse_hex_zid(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.is_empty() || text.len() % 2 != 0 || text.len() > 32 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks(2) {
        let hex = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(hex, 16).ok()?);
    }
    Some(out)
}

/// A fresh random zid for a scout that has none configured.
///
/// Random rather than all-zeros: a peer may read an all-zero zid as "unset" and
/// answer differently, so a scout with no configured identity announces one it
/// could plausibly open a session with.
pub fn fresh_scout_zid() -> Vec<u8> {
    let mut zid = [0u8; 16];
    if getrandom::getrandom(&mut zid).is_err() {
        // Entropy is unavailable only in a profile that cannot open a session
        // either; a fixed non-zero pattern still scouts.
        zid = [0xA5; 16];
    }
    zid.to_vec()
}

/// Drive scouting for `budget_ms`, invoking `on_hello` once per DISTINCT peer.
///
/// Returns how many peers were delivered. A bind failure is 0 rather than an
/// error: both ABIs' `z_scout` reports success and simply finds nothing, which
/// is also what a scout onto a group with no responders does.
pub fn run_scout(
    group: Ipv4Addr,
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
    mut on_hello: impl FnMut(&ScoutedHello),
) -> usize {
    use wz_runtime_tokio::scouting_glue::{
        drive_scouting_until_resolved, new_scouting_engine, ScoutParams, ScoutingActions,
    };
    use wz_runtime_tokio::UdpDriver;

    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    else {
        return 0;
    };

    runtime.block_on(async move {
        // `None`: the scouting group is deliberately NOT interface-narrowed — a
        // discovery beacon must reach every interface a peer could answer on.
        let Ok(mut driver) = UdpDriver::bind_multicast_v4(group, port, None).await else {
            return 0;
        };
        let actions = ScoutingActions::new(ScoutParams {
            version: SCOUT_PROTO_VERSION,
            what,
            zid,
            timeout_ms: SCOUT_CYCLE_MS,
        });
        let mut engine = new_scouting_engine(&actions);
        let clock = wz_runtime_tokio::runtime_impl::TokioTime::new();
        let started = Instant::now();
        let budget = Duration::from_millis(budget_ms);
        let mut delivered = 0usize;
        let mut seen_zids: HashSet<Vec<u8>> = HashSet::new();

        while started.elapsed() < budget {
            let _ = drive_scouting_until_resolved(
                &mut driver,
                &actions,
                &mut engine,
                &clock,
                None,
                SCOUT_TICK_MS,
            )
            .await;
            for hello in actions.scouted_hellos() {
                if !seen_zids.insert(hello.zid.clone()) {
                    continue;
                }
                on_hello(&hello);
                delivered += 1;
            }
        }
        delivered
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The locator grammar, including the two shapes that must be REJECTED
    /// rather than silently defaulted — a scout onto a mis-parsed group finds
    /// nothing and looks like a network problem.
    #[test]
    fn the_multicast_locator_grammar_is_exact() {
        assert_eq!(
            parse_multicast_locator(MULTICAST_LOCATOR_DEFAULT),
            Some((Ipv4Addr::new(224, 0, 0, 224), 7446))
        );
        assert!(parse_multicast_locator("tcp/224.0.0.224:7446").is_none());
        assert!(parse_multicast_locator("udp/224.0.0.224").is_none());
        assert!(parse_multicast_locator("").is_none());
    }

    /// A zid is hex, EVEN-length and at most 16 bytes; anything else is `None`
    /// so the caller falls back to a fresh one rather than scouting as a
    /// truncated identity.
    #[test]
    fn a_zid_parses_only_as_even_length_hex_within_sixteen_bytes() {
        assert_eq!(parse_hex_zid("0a0b"), Some(vec![0x0a, 0x0b]));
        assert!(parse_hex_zid("0a0").is_none());
        assert!(parse_hex_zid("zz").is_none());
        assert!(parse_hex_zid(&"ab".repeat(17)).is_none());
        assert_eq!(fresh_scout_zid().len(), 16);
    }
}
