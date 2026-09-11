// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// The resolved static-mode deploy config: BOTH halves of the deploy, kept
/// apart — the wz analog of what pico's `_z_locators_by_config` fills in
/// (`vendor/zenoh-pico/src/net/session.c` @
/// `static z_result_t _z_locators_by_config(_z_config_t *config, _z_string_svec_t *listen_locators,`).
///
/// # Why the halves are two fields and not one list
///
/// pico hands its caller TWO svecs and keeps them two all the way down:
/// `_z_open_locators` dispatches on the node's mode and passes
/// `(listen_locator, connect_locators)` to `_z_open_locators_peer`, which
/// binds the first and dials every member of the second (`session.c` @
/// `z_result_t _z_open_locators_peer(_z_session_rc_t *zn, _z_string_t *listen_locator,`).
/// The peer arm needs both AT ONCE — the listen endpoint is the primary
/// transport and the connect list becomes the peer set — so a shape that can
/// only carry one of them cannot express that arm at all.
///
/// This type used to be exactly that shape: one flat `locators` list plus an
/// exclusive `StaticRole` (Open XOR Listen). The role decided which half
/// survived resolution, so the other was gone by the time any vehicle saw the
/// config, and "listen AND connect" was unrepresentable rather than merely
/// unimplemented. R2570 replaced it with the two fields upstream itself keeps,
/// so gaining a multi-peer vehicle is a new CONSUMER of this type rather than
/// a change to it.
pub struct StaticConfig {
    /// `deploy.listen`, post-hygiene — the endpoint to BIND and accept on.
    /// `None` when the key is absent or blank.
    ///
    /// One endpoint, not a list, because that is pico's own bound: it refuses
    /// a multi-member listen set outright (`session.c` @
    /// `_Z_ERROR("Multiple listen locators are not supported in zenoh-pico");`).
    pub listen: Option<BoundedString<{ caps::MAX_LOCATOR_LEN }>>,
    /// `deploy.connect[]`, post-hygiene, in deploy order — the locators to
    /// DIAL, exactly what [`synth_static_locators`] yields.
    pub connect: StaticLocators,
}

impl StaticConfig {
    /// Whether this config forces the node's `whatami` to `WhatAmI::Peer`.
    ///
    /// pico's listen arm does two things, not one: it places the listen
    /// endpoint AND calls `_zp_config_insert(config, Z_CONFIG_MODE_KEY,
    /// Z_CONFIG_MODE_PEER)` (`session.c` @
    /// `_zp_config_insert(config, Z_CONFIG_MODE_KEY, Z_CONFIG_MODE_PEER);`),
    /// overriding whatever `mode=` the config carried — a listening node is a
    /// peer by construction, because pico's default is `Z_WHATAMI_CLIENT`
    /// (`_z_config_get_mode`) and a client does not accept. pico enforces the
    /// same rule from the other side: `_z_open_locators` refuses a listen
    /// endpoint in client mode (`session.c` @
    /// `_Z_ERROR("Listen locators are not supported in client mode");`).
    ///
    /// A *method* rather than a second field so the two effects cannot drift
    /// apart: they are one fact about the config, read twice.
    pub const fn forces_peer_mode(&self) -> bool {
        self.listen.is_some()
    }
}

impl core::fmt::Debug for StaticConfig {
    /// Hand-written because [`StaticLocators`] is a
    /// [`BoundedVec`](crate::bounded::BoundedVec), which derives nothing on
    /// either backing; it derefs to a slice of
    /// [`BoundedString`], which does implement `Debug`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticConfig")
            .field("listen", &self.listen)
            .field("connect", &&self.connect[..])
            .finish()
    }
}

/// Why a `deploy.listen` + `deploy.connect[]` pair did not resolve, or why a
/// vehicle refused the resolved config.
///
/// Deliberately carries no owned string, unlike the `alloc`-gated
/// `ScoutingModeError` above: this vocabulary is consumed on the no-alloc
/// runtime path, not by the deploy-string parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticConfigError {
    /// Both `listen=` and a non-empty `connect=` were configured, and the
    /// vehicle asked to bring the deploy up serves only ONE of them.
    ///
    /// This is pico's own answer under `Z_FEATURE_UNICAST_PEER == 0`:
    /// `_z_open_locators_peer` refuses exactly this pair (`session.c` @
    /// `_Z_ERROR("Multiple connect locators, or combined listen and connect locators, require peer support");`),
    /// because serving both halves needs the multi-peer path that the feature
    /// gates. Refusing LOUDLY is the point: silently honouring one half and
    /// dropping the other is how a deploy comes up listening on a locator
    /// nobody dials.
    ///
    /// R2570 moved the PRODUCER of this variant. It used to be raised by
    /// [`resolve_static_config`] — a pure transform rendering a CAPABILITY
    /// verdict, which is why gaining the capability could not change the
    /// answer. It is raised by the single-session vehicle now, which is the
    /// thing that actually cannot serve both halves; the multi-peer vehicle
    /// takes the same config and brings up both.
    ListenWithConnect,
    /// `listen=` is longer than [`caps::MAX_LOCATOR_LEN`] and cannot be
    /// carried on the no-alloc backing.
    ///
    /// A REFUSAL rather than the skip [`synth_static_locators`] applies to an
    /// over-long connect entry, and the asymmetry is deliberate: there are N
    /// connect entries and dropping one leaves the deploy's shape intact,
    /// while there is exactly one listen endpoint and dropping it turns a
    /// listening node into a dial-only one. Same deploy-authoring bound, and
    /// the same reason a truncation is never an option — a truncated endpoint
    /// binds the wrong socket.
    ///
    /// Unreachable on the `alloc` AP backing, where the bound is advisory.
    ListenTooLong,
}

/// Resolve `deploy.listen` + `deploy.connect[]` into both halves of the
/// static deploy — the wz analog of zenoh-pico's `_z_locators_by_config`
/// (`vendor/zenoh-pico/src/net/session.c` @
/// `static z_result_t _z_locators_by_config(_z_config_t *config, _z_string_svec_t *listen_locators,`).
///
/// The result is LOSSLESS: every configured half survives resolution, in the
/// shape upstream keeps it, and no arm of the deploy is discarded here.
/// Deciding WHICH halves a given vehicle can bring up is that vehicle's
/// judgement — [`StaticConfigError::ListenWithConnect`] is raised by the
/// single-session opener, which serves one — and this transform reports the
/// config it was handed either way.
///
/// | `listen=` | `connect=` | result | pico |
/// |---|---|---|---|
/// | absent | non-empty | `listen: None` + the connect list | `key = CONNECT`, dispatched by mode |
/// | present | empty | the endpoint + an empty connect list | `key = LISTEN`, `mode = peer` |
/// | present | non-empty | BOTH, for the vehicle to judge | peer arm binds then dials; `UNICAST_PEER == 0` refuses |
/// | absent | empty | `None` + an empty list | early `return _Z_RES_OK`, empty svecs |
///
/// The last row is why the empty case is not an error here: pico returns OK
/// with empty svecs and the caller renders the verdict (`_z_open_locators`
/// @ `_Z_ERROR("No listen or connect locators configured");`). Static mode is
/// scouting expressed as absent, so wz has nothing to fall through to and the
/// session layer turns the empty config into its "configured locators are
/// wrong / unreachable" diagnostic — but that judgement belongs to the
/// session layer, not to this transform.
///
/// Hygiene matches [`synth_static_locators`] on both inputs: surrounding
/// whitespace is trimmed and a blank `listen=` is treated as absent, because
/// an empty config value is not an endpoint.
///
/// Generic over `S: AsRef<str>` for the same reason
/// [`synth_static_locators`] is — AP feeds `&[String]`, the no-alloc MCU
/// feeds `&[&str]` — and allocates nothing beyond what that synth does.
///
/// # Errors
///
/// [`StaticConfigError::ListenTooLong`] when the `listen=` endpoint exceeds
/// the bounded-seam locator capacity. That is the ONLY refusal this transform
/// renders, and it is about the INPUT not fitting the declared bounds rather
/// than about what any vehicle can serve.
pub fn resolve_static_config<S: AsRef<str>>(
    listen: Option<&str>,
    connect: &[S],
) -> Result<StaticConfig, StaticConfigError> {
    let connect_locators = synth_static_locators(connect);
    // Blank / whitespace-only `listen=` is an absent one (config hygiene,
    // the rule `synth_static_locators` already applies to every entry).
    let listen = listen.map(str::trim).filter(|s| !s.is_empty());

    let Some(listen) = listen else {
        return Ok(StaticConfig {
            listen: None,
            connect: connect_locators,
        });
    };

    let mut endpoint: BoundedString<{ caps::MAX_LOCATOR_LEN }> = BoundedString::new();
    if endpoint.push_str(listen).is_err() {
        return Err(StaticConfigError::ListenTooLong);
    }
    Ok(StaticConfig {
        listen: Some(endpoint),
        connect: connect_locators,
    })
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

    // ── the `listen=` half of `_z_locators_by_config`. Each test pins ONE
    //    arm of that function; a resolution that collapsed the arms would
    //    pass some and fail the rest, which is what makes them
    //    discriminators rather than one assertion spelled six ways.

    #[test]
    fn resolve_connect_only_keeps_the_connect_list_and_no_listen() {
        // pico: `listen == NULL` -> the CONNECT svec is filled and the LISTEN
        // one stays empty.
        let connect = ["tcp/127.0.0.1:7447", "udp/127.0.0.1:7448"];
        let resolved = resolve_static_config(None, &connect).expect("connect-only resolves");
        assert!(resolved.listen.is_none());
        assert_eq!(resolved.connect.len(), 2);
        assert_eq!(resolved.connect[0], "tcp/127.0.0.1:7447");
        assert_eq!(resolved.connect[1], "udp/127.0.0.1:7448");
    }

    #[test]
    fn resolve_listen_only_keeps_the_endpoint_and_an_empty_connect() {
        // pico: `listen != NULL && connect == NULL` -> the LISTEN svec holds
        // the endpoint and `mode=peer` is inserted.
        let empty: [&str; 0] = [];
        let resolved =
            resolve_static_config(Some("tcp/0.0.0.0:7447"), &empty).expect("listen-only resolves");
        assert_eq!(
            resolved.listen.as_ref().map(BoundedString::as_str),
            Some("tcp/0.0.0.0:7447")
        );
        assert!(resolved.connect.is_empty());
    }

    #[test]
    fn resolve_listen_with_connect_keeps_both_halves() {
        // THE arm the old shape could not express. pico's peer bring-up
        // consumes both at once — bind the listen endpoint, then dial every
        // connect member as a peer — so a resolution that dropped either half
        // makes that vehicle unreachable no matter what it can do.
        //
        // A vehicle that serves only one half still refuses this config; that
        // refusal is `StaticConfigError::ListenWithConnect`, and it is raised
        // where the limit is rather than here.
        let connect = ["tcp/127.0.0.1:7447", "tcp/127.0.0.1:7449"];
        let resolved =
            resolve_static_config(Some("tcp/0.0.0.0:7448"), &connect).expect("both halves resolve");
        assert_eq!(
            resolved.listen.as_ref().map(BoundedString::as_str),
            Some("tcp/0.0.0.0:7448")
        );
        assert_eq!(resolved.connect.len(), 2);
        assert_eq!(resolved.connect[0], "tcp/127.0.0.1:7447");
        assert_eq!(resolved.connect[1], "tcp/127.0.0.1:7449");
    }

    #[test]
    fn resolve_neither_is_empty_on_both_halves_not_an_error() {
        // pico: neither set -> early `return _Z_RES_OK` with EMPTY svecs, and
        // the CALLER renders the verdict. The empty config is a fact this
        // transform reports, not a verdict it renders.
        let empty: [&str; 0] = [];
        let resolved = resolve_static_config(None, &empty).expect("neither is not an error");
        assert!(resolved.listen.is_none());
        assert!(resolved.connect.is_empty());
    }

    #[test]
    fn resolve_treats_a_blank_listen_as_absent() {
        // Config hygiene, the rule the connect entries already obey: an empty
        // value is not an endpoint. So a blank listen must NOT place a listen
        // half, and must not disturb the connect one either.
        let connect = ["tcp/127.0.0.1:7447"];
        let resolved =
            resolve_static_config(Some("   "), &connect).expect("blank listen is absent");
        assert!(resolved.listen.is_none());
        assert_eq!(resolved.connect.len(), 1);
        assert_eq!(resolved.connect[0], "tcp/127.0.0.1:7447");
    }

    #[test]
    fn resolve_trims_the_listen_endpoint() {
        let empty: [&str; 0] = [];
        let resolved =
            resolve_static_config(Some("  tcp/0.0.0.0:7447 "), &empty).expect("listen resolves");
        assert_eq!(
            resolved.listen.as_ref().map(BoundedString::as_str),
            Some("tcp/0.0.0.0:7447")
        );
    }

    #[test]
    fn resolve_listen_with_an_all_blank_connect_has_no_connect_half() {
        // Post-hygiene, a connect list of nothing but blanks is not a connect
        // list — the rule `synth_static_locators` already applies per entry.
        // It is pinned separately because it is what a vehicle's
        // listen-plus-connect refusal is decided on: this config must NOT
        // read as "both halves" to the vehicle that serves one.
        let connect = ["", "   "];
        let resolved = resolve_static_config(Some("tcp/0.0.0.0:7447"), &connect)
            .expect("an all-blank connect is not a connect");
        assert_eq!(
            resolved.listen.as_ref().map(BoundedString::as_str),
            Some("tcp/0.0.0.0:7447")
        );
        assert!(resolved.connect.is_empty());
    }

    #[test]
    fn listen_forces_peer_mode_and_connect_only_does_not() {
        // pico's listen arm does TWO things: it places the endpoint AND
        // inserts `mode=peer`. This pins the second one separately, so a
        // resolution that placed the endpoint while leaving the node a client
        // — pico's default — still fails.
        let empty: [&str; 0] = [];
        let listening =
            resolve_static_config(Some("tcp/0.0.0.0:7447"), &empty).expect("listen resolves");
        assert!(listening.forces_peer_mode());
        let dialing = resolve_static_config(None, &["tcp/127.0.0.1:7447"]).expect("connect-only");
        assert!(!dialing.forces_peer_mode());
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
