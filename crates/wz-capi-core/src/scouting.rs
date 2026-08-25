// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The scouting DRIVE both C ABIs' `z_scout` runs.
//!
//! ## Why it is here
//!
//! `z_scout` exists in zenoh-pico's ABI and in zenoh-c's, with different
//! argument types and different config spellings — but the thing between those
//! two shims is identical: bind the multicast group, drive the scouting FSM
//! for the caller's budget, and report each peer as it answers. That middle is
//! what lives here, expressed over
//! [`ScoutedHello`](wz_runtime_tokio::scouting_glue::ScoutedHello), which is
//! already an ABI-neutral type.
//!
//! Nothing here has a `z_` in its name, per this crate's contract; the ABI
//! crates map a hello onto their own `z_owned_hello_t`.
//!
//! ## One window, the survey arm
//!
//! `ScoutParams::exit_on_first` is `false` here — pico's `_z_scout` passes
//! exactly that (`src/net/primitives.c:81`), so its loop keeps reading until
//! the budget expires and every responder reaches the closure. The window IS
//! the caller's budget, and one Scout goes out for it.
//!
//! This module used to re-enter whole scouting CYCLES instead, because the
//! statechart left `AwaitingHello` on the first Hello, and then had to key
//! delivery on the zid to suppress the duplicate answers its own re-scouting
//! provoked. The FSM carries the survey arm now, so both are gone: a peer that
//! answers twice is delivered twice, which is what upstream's
//! `_z_hello_slist_t` drain does.
//!
//! ## When and in what order the closure is called
//!
//! Both are upstream's, and both are easy to get wrong in wz's favour — see
//! `deliver_in_upstream_order` (private; a code span, not an intra-doc link,
//! because the target does not exist in the public rustdoc). Upstream calls
//! the closure AFTER the window
//! (`_z_scout_inner` returns a list; only then is it drained) and in REVERSE
//! arrival order (the list is built by prepending). A per-Hello, arrival-order
//! delivery would be nicer and would still be a divergence.

use std::net::Ipv4Addr;

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
/// One discovery cycle, for a caller that wants a FIRST-ANSWER lookup rather
/// than a survey and re-enters until it gets one (the `wz-ap-demo` `--scout`
/// path). `z_scout` does not use it: its window is the caller's whole budget.
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

/// Hand the window's peers to `on_hello` in UPSTREAM'S DELIVERY ORDER, which is
/// the REVERSE of arrival, and return how many were delivered.
///
/// This is not a detail — it is observable through both ABIs. `_z_scout_inner`
/// accumulates with `_z_hello_slist_push_empty`, which PREPENDS
/// (`collections/list.c:287-295`), and `_z_scout` then drains from the head
/// (`net/primitives.c:81-90`). So a pico program's closure sees the LAST
/// responder first. wz's accumulator is a `Vec` in arrival order — the useful
/// order for everything else in this tree — so the reversal lives here, at the
/// one seam where upstream's contract is being imitated, rather than in the
/// accumulator where it would be a strange rule with no reason attached.
///
/// Delivery happens AFTER the window for the same reason: upstream's callback
/// is not called from inside the scouting loop. `_z_scout_inner` returns a list
/// and only then is it drained, so a pico program prints nothing for the whole
/// budget and then everything at once. Firing per-Hello would be a divergence
/// in wz's favour, which is still a divergence.
fn deliver_in_upstream_order(
    hellos: &[ScoutedHello],
    mut on_hello: impl FnMut(&ScoutedHello),
) -> usize {
    for hello in hellos.iter().rev() {
        on_hello(hello);
    }
    hellos.len()
}

/// Drive scouting for `budget_ms`, then invoke `on_hello` once per peer that
/// answered, in `deliver_in_upstream_order` — after the window, last responder
/// first, which is what both ABIs' `z_scout` does.
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
    on_hello: impl FnMut(&ScoutedHello),
) -> usize {
    use wz_runtime_tokio::scouting_glue::{
        drive_scouting_until_resolved, new_scouting_engine, ScoutParams, ScoutingActions,
    };
    use wz_runtime_tokio::{McastSocketConfig, UdpDriver};

    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    else {
        return 0;
    };

    let hellos = runtime.block_on(async move {
        // `None`: the scouting group is deliberately NOT interface-narrowed — a
        // discovery beacon must reach every interface a peer could answer on.
        let Ok(mut driver) =
            UdpDriver::bind_multicast_v4(group, port, McastSocketConfig::default()).await
        else {
            return Vec::new();
        };
        let actions = ScoutingActions::new(ScoutParams {
            version: SCOUT_PROTO_VERSION,
            what,
            zid,
            // The caller's whole budget IS the window: upstream hands its
            // `timeout` straight to `__z_scout_loop`'s `while elapsed <
            // period` (`src/session/scout.c:60-63`).
            timeout_ms: budget_ms,
            // The survey arm — report every responder, do not stop at one.
            exit_on_first: false,
        });
        let mut engine = new_scouting_engine(&actions);
        let clock = wz_runtime_tokio::runtime_impl::TokioTime::new();

        let _ = drive_scouting_until_resolved(
            &mut driver,
            &actions,
            &mut engine,
            &clock,
            None,
            SCOUT_TICK_MS,
        )
        .await;
        actions.scouted_hellos()
    });
    deliver_in_upstream_order(&hellos, on_hello)
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

    fn hello(zid: u8) -> ScoutedHello {
        ScoutedHello {
            version: 0x09,
            whatami: None,
            zid: vec![zid],
            locators: Vec::new(),
        }
    }

    /// Both ABIs' `z_scout` hands its closure the LAST responder first, because
    /// upstream's accumulator is built by PREPENDING
    /// (`_z_hello_slist_push_empty`, `collections/list.c:287-295`) and `_z_scout`
    /// drains from the head (`net/primitives.c:81-90`).
    ///
    /// wz records in arrival order, so this seam is the only place the two
    /// orders meet. Three peers, not two: a two-element reversal is also a swap,
    /// a rotation, and a sort — three tells them apart.
    #[test]
    fn the_closure_sees_the_last_responder_first() {
        let recorded = [hello(0xA1), hello(0xB2), hello(0xC3)];
        let mut seen = Vec::new();
        let n = deliver_in_upstream_order(&recorded, |h| seen.push(h.zid[0]));
        assert_eq!(n, 3, "every recorded peer is delivered");
        assert_eq!(
            seen,
            vec![0xC3, 0xB2, 0xA1],
            "reverse arrival order — upstream's slist is newest-first"
        );
    }

    /// The empty window delivers nothing and says so, which is the count both
    /// ABIs' `z_scout` uses to decide between upstream's "Did not find any zenoh
    /// process." and "Dropping scout results." lines.
    #[test]
    fn an_empty_window_delivers_nothing() {
        let mut seen = 0usize;
        assert_eq!(deliver_in_upstream_order(&[], |_| seen += 1), 0);
        assert_eq!(seen, 0);
    }
}
