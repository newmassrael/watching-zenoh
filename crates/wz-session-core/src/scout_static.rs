// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311eq — static scouting mode: host-side locator synthesis.
//!
//! Static mode is scouting expressed as *absent* (docs/scouting-fsm.md
//! §2.4.3). When `deploy.scouting.mode == static` the scouting FSM is
//! never instantiated — codegen elides the scout link, the scout/hello
//! codecs, and the scout buffer pool (§2.4.3 reason #2). Instead the host
//! synthesizes the peer locator list directly from `deploy.connect[]` at
//! startup: zenoh-pico's `_z_locators_by_config`
//! (`~/zenoh-pico/src/net/session.c:87-118`) returns the explicit
//! `connect=` list verbatim and `_z_locators_by_scout` is never called.
//!
//! This module is the wz analog of that bypass, and is therefore *not*
//! gated on `scouting-active` (which gates the active-mode FSM in
//! `wz-runtime-tokio::scouting_glue`): a static-only deploy compiles the
//! active FSM out entirely and reaches session-open through
//! [`synth_static_locators`] alone. It is a pure, runtime-agnostic value
//! transform — no codec, no socket, no FSM — so it sits in
//! `wz-session-core` alongside [`crate::scout_params`].
//!
//! R311ih — the synthesis is **no-alloc-capable**: it builds onto the
//! [`crate::bounded`] seam ([`StaticLocators`] =
//! `BoundedVec<BoundedString<N>, M>`) rather than `Vec<String>`, so it
//! composes on the no-alloc MCU profile — the profile where static mode
//! is most valuable (§2.4.3 reason #2 SRAM elision). The synth is generic
//! over `S: AsRef<str>` (AP `&[String]` / MCU `&[&str]`). Only the
//! deploy-string mode parser [`ScoutingMode::from_deploy_str`] stays
//! `alloc`-gated (a host / build-time helper; on MCU the mode is a
//! compile-time codegen constant).
//!
//! The synthesized locators feed the same downstream consumer as the
//! active mode's discovered locator (the session FSM `Init -> LinkOpening`
//! path, docs/scouting-fsm.md §2.4.3 "Interaction with links.udp_session"
//! + §307-308): only the *trigger* differs between modes, not the
//! locator handoff. Synthesized locators carry no peer `zid` — the
//! scouting-time zid is advisory and the session handshake derives the
//! authoritative identity itself (§2 "Why zid=NULL is OK on synthesized
//! events"), so a config-sourced locator simply omits it.

use crate::bounded::{BoundedString, BoundedVec};
use crate::caps;

/// Owned static-scouting locator list — the bounded-seam output of
/// [`synth_static_locators`]. One [`BoundedString`] per configured peer,
/// capacity [`caps::MAX_STATIC_CONNECT`]. Backs onto `alloc::Vec` on AP
/// (capacity advisory) and `heapless::Vec` on the no-alloc MCU backing
/// (capacity hard), per [`crate::bounded`] — so static-mode discovery
/// composes on the no-alloc profile where static mode matters most
/// (docs/scouting-fsm.md §2.4.3 reason #2 SRAM elision).
pub type StaticLocators =
    BoundedVec<BoundedString<{ caps::MAX_LOCATOR_LEN }>, { caps::MAX_STATIC_CONNECT }>;

/// Deploy-time scouting mode discriminator (docs/scouting-fsm.md §2.4).
///
/// MVP enum is `{Active, Static}`; `passive` is deferred to Phase D+
/// (OQ-W23) and parses to [`ScoutingModeError::PassiveDeferred`] rather
/// than a silent fallback, so a deploy that requests it fails loudly
/// instead of degrading to a different mode.
///
/// R311ih — `alloc`-gated: the deploy-string parser is a host / build-time
/// helper (on MCU the scouting mode is a compile-time constant the
/// codegen reads from `deploy.scouting.mode`, never a runtime parse), and
/// the [`ScoutingModeError::Unknown`] diagnostic carries the offending
/// string. The runtime synthesis [`synth_static_locators`] below stays
/// no-alloc. Keeping the parser alloc-only avoids dragging an owned-string
/// error onto the no-alloc backing for a path the MCU runtime never takes.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoutingMode {
    /// Multicast Scout/Hello discovery FSM
    /// (`wz-runtime-tokio::scouting_glue`, gated `scouting-active`).
    Active,
    /// Scouting bypass — locators come from `deploy.connect[]` verbatim
    /// via [`synth_static_locators`]; no FSM is instantiated.
    Static,
}

/// Why a `deploy.scouting.mode` string did not map to a [`ScoutingMode`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoutingModeError {
    /// `mode: passive` is a valid future value but is deferred to
    /// Phase D+ (OQ-W23); it is not in the MVP enum.
    PassiveDeferred,
    /// The string is not one of `active` / `passive` / `static`.
    Unknown(alloc::string::String),
}

#[cfg(feature = "alloc")]
impl ScoutingMode {
    /// Parse a `deploy.scouting.mode` field value. Accepts the three
    /// documented spellings; `passive` is rejected as deferred (not
    /// silently mapped), and any other value is [`ScoutingModeError::Unknown`].
    pub fn from_deploy_str(s: &str) -> Result<Self, ScoutingModeError> {
        use alloc::string::ToString;
        match s {
            "active" => Ok(ScoutingMode::Active),
            "static" => Ok(ScoutingMode::Static),
            "passive" => Err(ScoutingModeError::PassiveDeferred),
            other => Err(ScoutingModeError::Unknown(other.to_string())),
        }
    }
}

/// Synthesize the static-mode peer locator list from `deploy.connect[]`.
///
/// Returns the configured locators verbatim into the bounded-seam
/// [`StaticLocators`] — the wz analog of zenoh-pico's
/// `_z_locators_by_config` returning the `connect=` list as given
/// (docs/scouting-fsm.md §2.4.3). Generic over `S: AsRef<str>` so both
/// profiles feed it natively: AP passes `&[String]` (deploy YAML), the
/// no-alloc MCU passes `&[&str]` (a `static` config array) — neither
/// allocates here.
///
/// Surrounding whitespace is trimmed and blank entries dropped (config
/// hygiene — an empty list item is not a locator). No locator-grammar
/// validation is performed: reachability / well-formedness surfaces at
/// session-open as the static-mode diagnostic ("the configured locators
/// are wrong / unreachable", §2.4.3 reason #1), the session layer's
/// concern. Each returned string is one peer the session FSM dials, in
/// deploy order (zenoh-pico opens the first then `_z_new_peer`s the rest,
/// `session.c:157-189`).
///
/// Capacity (no-alloc backing only): a locator longer than
/// [`caps::MAX_LOCATOR_LEN`] is skipped (the no-alloc `push_str` rejects
/// it atomically, leaving no partial write), and the output stops at
/// [`caps::MAX_STATIC_CONNECT`] entries. Both are deploy-authoring bounds
/// a future `deploy.yaml` -> caps codegen step enforces at build time
/// (the §2.6 hard-error model); on the `alloc` AP backing the bounds are
/// advisory and never trigger.
pub fn synth_static_locators<S: AsRef<str>>(connect: &[S]) -> StaticLocators {
    let mut out = StaticLocators::new();
    for raw in connect {
        let trimmed = raw.as_ref().trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut locator: BoundedString<{ caps::MAX_LOCATOR_LEN }> = BoundedString::new();
        if locator.push_str(trimmed).is_err() {
            // Over-long locator: deploy-authoring bound exceeded on the
            // no-alloc backing. Skip rather than truncate (a truncated
            // locator would dial the wrong peer).
            continue;
        }
        if out.push(locator).is_err() {
            // connect[] exceeds MAX_STATIC_CONNECT on the no-alloc
            // backing — stop at the declared capacity.
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn mode_parses_active_and_static() {
        assert_eq!(
            ScoutingMode::from_deploy_str("active"),
            Ok(ScoutingMode::Active)
        );
        assert_eq!(
            ScoutingMode::from_deploy_str("static"),
            Ok(ScoutingMode::Static)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn mode_passive_is_deferred_not_silent() {
        assert_eq!(
            ScoutingMode::from_deploy_str("passive"),
            Err(ScoutingModeError::PassiveDeferred)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn mode_unknown_is_reported_verbatim() {
        use alloc::string::ToString;
        assert_eq!(
            ScoutingMode::from_deploy_str("gossip"),
            Err(ScoutingModeError::Unknown("gossip".to_string()))
        );
    }

    #[test]
    fn synth_returns_connect_list_verbatim_in_order() {
        // `&str` input — the no-alloc MCU `static` config array shape.
        let connect = ["udp/192.168.1.10:7447", "tcp/192.168.1.11:7447"];
        let out = synth_static_locators(&connect);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], "udp/192.168.1.10:7447");
        assert_eq!(out[1], "tcp/192.168.1.11:7447");
    }

    #[test]
    fn synth_trims_whitespace_and_drops_blank_entries() {
        let connect = ["  udp/127.0.0.1:7447  ", "", "   ", "tcp/127.0.0.1:7448"];
        let out = synth_static_locators(&connect);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], "udp/127.0.0.1:7447");
        assert_eq!(out[1], "tcp/127.0.0.1:7448");
    }

    #[test]
    fn synth_empty_connect_yields_empty() {
        let empty: [&str; 0] = [];
        assert!(synth_static_locators(&empty).is_empty());
    }

    #[test]
    fn synth_accepts_owned_string_input_on_alloc() {
        // AP feeds `&[String]` (deploy YAML); String: AsRef<str>, so the
        // generic synth takes it without a separate overload.
        #[cfg(feature = "alloc")]
        {
            use alloc::string::ToString;
            use alloc::vec;
            let connect = vec!["tcp/127.0.0.1:7448".to_string()];
            let out = synth_static_locators(&connect);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0], "tcp/127.0.0.1:7448");
        }
    }
}
