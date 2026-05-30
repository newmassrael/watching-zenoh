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
//! [`synth_static_locators`] alone. It is a pure, runtime-agnostic
//! value transform (alloc only — no codec, no socket, no FSM), so it sits
//! in `wz-session-core` alongside [`crate::scout_params`] and is usable
//! on the MCU static-deploy profile as well as the AP one.
//!
//! The synthesized locators feed the same downstream consumer as the
//! active mode's discovered locator (the session FSM `Init -> LinkOpening`
//! path, docs/scouting-fsm.md §2.4.3 "Interaction with links.udp_session"
//! + §307-308): only the *trigger* differs between modes, not the
//! locator handoff. Synthesized locators carry no peer `zid` — the
//! scouting-time zid is advisory and the session handshake derives the
//! authoritative identity itself (§2 "Why zid=NULL is OK on synthesized
//! events"), so a config-sourced locator simply omits it.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Deploy-time scouting mode discriminator (docs/scouting-fsm.md §2.4).
///
/// MVP enum is `{Active, Static}`; `passive` is deferred to Phase D+
/// (OQ-W23) and parses to [`ScoutingModeError::PassiveDeferred`] rather
/// than a silent fallback, so a deploy that requests it fails loudly
/// instead of degrading to a different mode.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoutingModeError {
    /// `mode: passive` is a valid future value but is deferred to
    /// Phase D+ (OQ-W23); it is not in the MVP enum.
    PassiveDeferred,
    /// The string is not one of `active` / `passive` / `static`.
    Unknown(String),
}

impl ScoutingMode {
    /// Parse a `deploy.scouting.mode` field value. Accepts the three
    /// documented spellings; `passive` is rejected as deferred (not
    /// silently mapped), and any other value is [`ScoutingModeError::Unknown`].
    pub fn from_deploy_str(s: &str) -> Result<Self, ScoutingModeError> {
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
/// Returns the configured locators verbatim — this is the wz analog of
/// zenoh-pico's `_z_locators_by_config` returning the `connect=` list as
/// given (docs/scouting-fsm.md §2.4.3). Surrounding whitespace is trimmed
/// and blank entries are dropped (config hygiene — an empty YAML list
/// item is not a locator), but no locator-grammar validation is performed
/// here: reachability / well-formedness surfaces at session-open as the
/// static-mode diagnostic ("the configured locators are wrong /
/// unreachable", §2.4.3 reason #1), which is the session layer's concern,
/// not this synthesis step's.
///
/// Each returned string is one peer the session FSM will dial, in deploy
/// order (zenoh-pico opens the first then `_z_new_peer`s the rest,
/// `session.c:157-189`).
pub fn synth_static_locators(connect: &[String]) -> Vec<String> {
    connect
        .iter()
        .map(|locator| locator.trim())
        .filter(|locator| !locator.is_empty())
        .map(|locator| locator.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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

    #[test]
    fn mode_passive_is_deferred_not_silent() {
        assert_eq!(
            ScoutingMode::from_deploy_str("passive"),
            Err(ScoutingModeError::PassiveDeferred)
        );
    }

    #[test]
    fn mode_unknown_is_reported_verbatim() {
        assert_eq!(
            ScoutingMode::from_deploy_str("gossip"),
            Err(ScoutingModeError::Unknown("gossip".to_string()))
        );
    }

    #[test]
    fn synth_returns_connect_list_verbatim_in_order() {
        let connect = vec![
            "udp/192.168.1.10:7447".to_string(),
            "tcp/192.168.1.11:7447".to_string(),
        ];
        assert_eq!(
            synth_static_locators(&connect),
            vec![
                "udp/192.168.1.10:7447".to_string(),
                "tcp/192.168.1.11:7447".to_string(),
            ]
        );
    }

    #[test]
    fn synth_trims_whitespace_and_drops_blank_entries() {
        let connect = vec![
            "  udp/127.0.0.1:7447  ".to_string(),
            "".to_string(),
            "   ".to_string(),
            "tcp/127.0.0.1:7448".to_string(),
        ];
        assert_eq!(
            synth_static_locators(&connect),
            vec![
                "udp/127.0.0.1:7447".to_string(),
                "tcp/127.0.0.1:7448".to_string(),
            ]
        );
    }

    #[test]
    fn synth_empty_connect_yields_empty() {
        assert!(synth_static_locators(&[]).is_empty());
    }
}
