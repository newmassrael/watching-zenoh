// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! [`ScoutedHello`], which is
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
//! `deliver_in_upstream_order` (the session's, re-exported below). Upstream calls
//! the closure AFTER the window
//! (`_z_scout_inner` returns a list; only then is it drained) and in REVERSE
//! arrival order (the list is built by prepending). A per-Hello, arrival-order
//! delivery would be nicer and would still be a divergence.

use std::net::IpAddr;

use wz_runtime_tokio::scouting_glue::ScoutedHello;

// The locator grammar, the defaults and the delivery order of a scouting window are the session's
// (`wz_session_core::scouting_host`): the cooperative host reads the same ones. Re-exported here
// so the paths of the two C ABIs stay.
pub use wz_session_core::scouting_host::{
    deliver_in_upstream_order, parse_multicast_locator, MULTICAST_LOCATOR_DEFAULT,
    SCOUTING_TIMEOUT_DEFAULT_MS, SCOUTING_WHAT_DEFAULT, SCOUT_TICK_MS,
};

/// One discovery cycle, for a caller that wants a FIRST-ANSWER lookup rather
/// than a survey and re-enters until it gets one (the `wz-ap-demo` `--scout`
/// path). `z_scout` does not use it: its window is the caller's whole budget.
pub const SCOUT_CYCLE_MS: u64 = 1000;

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

/// Drive scouting for `budget_ms`, then invoke `on_hello` once per peer that
/// answered, in `deliver_in_upstream_order` — after the window, last responder
/// first, which is what both ABIs' `z_scout` does.
///
/// Returns how many peers were delivered. A bind failure is 0 rather than an
/// error: both ABIs' `z_scout` reports success and simply finds nothing, which
/// is also what a scout onto a group with no responders does.
pub fn run_scout(
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
    on_hello: impl FnMut(&ScoutedHello),
) -> usize {
    // The survey arm — report every responder, do not stop at one.
    let hellos = scout_window(group, port, what, zid, budget_ms, false);
    deliver_in_upstream_order(&hellos, on_hello)
}

/// Scout for `budget_ms` and answer the FIRST node that replies, or `None` when none does in
/// the window: zenoh-pico's open-time lookup, which `_z_open` runs when its config names no
/// locator (`vendor/zenoh-pico/src/net/session.c` @
/// `_z_hello_slist_t *hellos = _z_scout_inner(what, *zid, &mcast_locator, timeout, true);`).
/// The `true` is `exit_on_first`: the window ends at the first Hello, which is this function's
/// whole answer. A bind failure is `None`, as a window nobody answers is.
pub fn scout_first(
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
) -> Option<ScoutedHello> {
    scout_window(group, port, what, zid, budget_ms, true)
        .into_iter()
        .next()
}

/// One scouting window: bind the group, send one Scout, and collect the Hellos that answer
/// within `budget_ms`, in arrival order, ending at the first when `exit_on_first`.
fn scout_window(
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
    exit_on_first: bool,
) -> Vec<ScoutedHello> {
    use wz_runtime_tokio::scouting_fanout::{
        bind_scout_sockets, scout_interface_addresses, ScoutFanOut,
    };
    use wz_runtime_tokio::scouting_glue::{
        drive_scouting_until_resolved, new_scouting_engine, ScoutParams, ScoutingActions,
    };
    use wz_runtime_tokio::{McastSocketConfig, UdpDriver};

    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    else {
        return Vec::new();
    };

    runtime.block_on(async move {
        // `None`: the scouting group is deliberately NOT interface-narrowed — a
        // discovery beacon must reach every interface a peer could answer on.
        //
        // The group socket is an EXTRA receive member and not a condition of the
        // window: neither reference binds one to scout (upstream's `scout` receives on
        // its per-interface sockets alone, `zenoh/src/api/scouting.rs` @
        // `Runtime::bind_ucast_port(iface, multicast_ttl).ok()`), so a window
        // whose group socket cannot be bound goes on with the ask sockets, and is empty
        // only when there is nothing to ask or listen with.
        let group_socket =
            UdpDriver::bind_scouting_group(group, port, McastSocketConfig::default())
                .await
                .ok();
        // R2611 — and that sentence is only true if the Scout LEAVES by every
        // one of them, which one socket on the default route does not do. pico's
        // `z_scout` opens a link per interface when the config names none
        // (`vendor/zenoh-pico/src/session/scout.c` @
        // `_z_udp_unicast_interface_iterator_next(&iter)`), and this is the same
        // window, so it asks the same way. A build that cannot enumerate or
        // cannot pin offers nothing and the group socket asks alone, which is
        // the pre-R2611 behaviour kept as a floor.
        let locals = scout_interface_addresses().unwrap_or_default();
        let (ask, refused) = bind_scout_sockets(group, port, &locals, None).await;
        // The shape `over` returns is REPORTED by `over` itself, at the one
        // place that knows it — this crate carries no logger, and a value
        // dropped here would make "the survey found nothing" and "the Scout
        // left by one interface of four" the same observation to everyone
        // downstream.
        let Some((mut driver, _shape)) = ScoutFanOut::over_optional(group_socket, ask, refused)
        else {
            return Vec::new();
        };
        let actions = ScoutingActions::new(ScoutParams {
            what,
            zid,
            // The caller's whole budget IS the window: upstream hands its
            // `timeout` straight to `__z_scout_loop`'s `while elapsed <
            // period` (`src/session/scout.c:60-63`).
            timeout_ms: budget_ms,
            exit_on_first,
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scout with no configured id announces a fresh sixteen-byte one. Reading
    /// a configured id is [`crate::drive::ConfiguredZid`]'s, and the reading
    /// that used to sit here (per byte, in written order, even length only) was
    /// the reverse of zenoh's and refused text zenoh accepts.
    #[test]
    fn a_fresh_scout_zid_is_sixteen_bytes() {
        assert_eq!(fresh_scout_zid().len(), 16);
    }
}
