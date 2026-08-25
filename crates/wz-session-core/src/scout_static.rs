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

/// Which half of the transport a static deploy config asks for — the wz
/// analog of zenoh-pico's `peer_op` out-parameter, set by
/// `_z_locators_by_config` (`vendor/zenoh-pico/src/net/session.c:87-118`)
/// and consumed by `_z_open_inner` -> `_z_new_transport`.
///
/// pico initialises `peer_op` to `_Z_PEER_OP_LISTEN` in `_z_open`
/// (`session.c:160`) and only the *no*-`listen=` arm overwrites it with
/// `_Z_PEER_OP_OPEN`, so "listen" is the default the connect list opts out
/// of rather than a mode a config opts into. [`resolve_static_config`]
/// reproduces that polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticRole {
    /// `connect=` only — dial the configured locators. pico's
    /// `_Z_PEER_OP_OPEN` (`session.c:103`, the `listen == NULL` arm).
    Open,
    /// `listen=` present — bind that endpoint and accept on it. pico's
    /// `_Z_PEER_OP_LISTEN`, which also flips the node's `whatami`
    /// (see [`Self::forces_peer_mode`]).
    Listen,
}

impl StaticRole {
    /// Whether this role forces the node's `whatami` to `WhatAmI::Peer`.
    ///
    /// pico's listen arm does two things, not one: it places the listen
    /// endpoint AND calls `_zp_config_insert(config, Z_CONFIG_MODE_KEY,
    /// Z_CONFIG_MODE_PEER)` (`session.c:96` and `:110`), overriding
    /// whatever `mode=` the config carried — a listening node is a peer by
    /// construction, because pico's default is `Z_WHATAMI_CLIENT`
    /// (`_z_config_get_mode`, `session.c:122`) and a client does not
    /// accept. This is a *method* rather than a second field on
    /// [`StaticConfig`] so the two effects cannot drift apart: they are one
    /// fact about the role, read twice.
    pub const fn forces_peer_mode(self) -> bool {
        matches!(self, StaticRole::Listen)
    }
}

/// The resolved static-mode deploy config: which half of the transport to
/// bring up, and the locator list to bring it up on.
///
/// The wz analog of what pico's `_z_locators_by_config` hands back to
/// `_z_open` — the `locators` svec plus the `peer_op` out-param — reshaped
/// from two out-parameters into one returned value so the pair cannot be
/// read apart. Produced by [`resolve_static_config`].
pub struct StaticConfig {
    /// Dial or accept. See [`StaticRole`].
    pub role: StaticRole,
    /// The locators, post-hygiene, in the order the session layer consumes
    /// them.
    ///
    /// For [`StaticRole::Open`] this is `deploy.connect[]` verbatim, exactly
    /// what [`synth_static_locators`] yields. For [`StaticRole::Listen`] it
    /// holds the single `listen=` endpoint — pico places listen at index 0
    /// and appends the connect tail as additional peers, but only under
    /// `Z_FEATURE_UNICAST_PEER == 1`; wz has no `_z_new_peer` analog yet, so
    /// it is the `#else` arm of that `#if` (see
    /// [`StaticConfigError::ListenWithConnect`]). The field stays a LIST
    /// rather than collapsing to one string precisely so gaining that analog
    /// appends a tail here instead of changing this type.
    pub locators: StaticLocators,
}

impl core::fmt::Debug for StaticConfig {
    /// Hand-written because [`StaticLocators`] is a
    /// [`BoundedVec`](crate::bounded::BoundedVec), which derives nothing on
    /// either backing; it derefs to a slice of
    /// [`BoundedString`], which does implement `Debug`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticConfig")
            .field("role", &self.role)
            .field("locators", &&self.locators[..])
            .finish()
    }
}

/// Why a `deploy.listen` + `deploy.connect[]` pair did not resolve.
///
/// Deliberately carries no owned string, unlike the `alloc`-gated
/// `ScoutingModeError` above: this one is produced by the runtime resolution
/// [`resolve_static_config`], which stays no-alloc, not by the
/// deploy-string parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticConfigError {
    /// Both `listen=` and a non-empty `connect=` were configured.
    ///
    /// This is pico's own answer under `Z_FEATURE_UNICAST_PEER == 0`:
    /// `_z_locators_by_config` returns `_Z_ERR_GENERIC` for exactly this
    /// pair (`vendor/zenoh-pico/src/net/session.c:107-108`), because
    /// serving both halves needs the `_z_new_peer` multi-peer path that the
    /// feature gates. wz is that build shape — `open_session_static` opens
    /// exactly one session and has no `_z_new_peer` analog — so refusing is
    /// parity, and refusing LOUDLY is the point: silently honouring one half
    /// and dropping the other is how a deploy comes up listening on a
    /// locator nobody dials.
    ListenWithConnect,
}

/// Resolve `deploy.listen` + `deploy.connect[]` into the transport half to
/// bring up and the locators to bring it up on — the wz analog of
/// zenoh-pico's `_z_locators_by_config`
/// (`vendor/zenoh-pico/src/net/session.c:87-118`).
///
/// The four outcomes, each one arm of that function:
///
/// | `listen=` | `connect=` | result | pico |
/// |---|---|---|---|
/// | absent | non-empty | [`StaticRole::Open`] over the connect list | `*peer_op = _Z_PEER_OP_OPEN`, `key = CONNECT` |
/// | present | empty | [`StaticRole::Listen`] over the one endpoint | `key = LISTEN`, `mode = peer` |
/// | present | non-empty | [`StaticConfigError::ListenWithConnect`] | `_Z_ERROR_RETURN(_Z_ERR_GENERIC)` |
/// | absent | empty | [`StaticRole::Open`] over an empty list | early `return _Z_RES_OK`, empty svec |
///
/// The last row is why the empty case is not an error here: pico returns OK
/// with an empty list and `_z_open` then falls through to *scouting*
/// (`session.c:187-201`). Static mode is scouting expressed as absent, so wz
/// has nothing to fall through to and the session layer turns the empty list
/// into its "configured locators are wrong / unreachable" diagnostic — but
/// that judgement belongs to the session layer, not to this pure transform,
/// which reports the config it was handed.
///
/// Hygiene matches [`synth_static_locators`] on both inputs: surrounding
/// whitespace is trimmed and a blank `listen=` is treated as absent, because
/// an empty config value is not an endpoint. One documented consequence:
/// the `ListenWithConnect` refusal is decided on the POST-hygiene connect
/// list, so `listen=... ` plus a `connect=` of nothing but blanks resolves to
/// `Listen` rather than erroring. pico tests the raw `_z_config_get` pointer
/// and would error; wz cannot, having already defined a blank entry as not a
/// locator, and erroring on a list it is about to discard would be refusing a
/// conflict that does not exist.
///
/// Generic over `S: AsRef<str>` for the same reason
/// [`synth_static_locators`] is — AP feeds `&[String]`, the no-alloc MCU
/// feeds `&[&str]` — and allocates nothing beyond what that synth does.
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
            role: StaticRole::Open,
            locators: connect_locators,
        });
    };

    if !connect_locators.is_empty() {
        return Err(StaticConfigError::ListenWithConnect);
    }

    let mut endpoint: BoundedString<{ caps::MAX_LOCATOR_LEN }> = BoundedString::new();
    if endpoint.push_str(listen).is_err() {
        // Over-long listen endpoint on the no-alloc backing: the same
        // deploy-authoring bound `synth_static_locators` enforces per entry,
        // and the same answer — skip rather than truncate, since a truncated
        // endpoint binds the wrong socket. The empty list that results is the
        // session layer's "configured locators are wrong" diagnostic.
        return Ok(StaticConfig {
            role: StaticRole::Listen,
            locators: StaticLocators::new(),
        });
    }
    let mut locators = StaticLocators::new();
    // MAX_STATIC_CONNECT >= 1 on every profile, so this push cannot fail;
    // the result is consumed rather than unwrapped to keep the no-alloc
    // backing's capacity surface honest.
    let _ = locators.push(endpoint);
    Ok(StaticConfig {
        role: StaticRole::Listen,
        locators,
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
    fn resolve_connect_only_is_open_over_the_connect_list() {
        // pico: `listen == NULL` -> `*peer_op = _Z_PEER_OP_OPEN`, key =
        // CONNECT (session.c:103, :116).
        let connect = ["tcp/127.0.0.1:7447", "udp/127.0.0.1:7448"];
        let resolved = resolve_static_config(None, &connect).expect("connect-only resolves");
        assert_eq!(resolved.role, StaticRole::Open);
        assert_eq!(resolved.locators.len(), 2);
        assert_eq!(resolved.locators[0], "tcp/127.0.0.1:7447");
        assert_eq!(resolved.locators[1], "udp/127.0.0.1:7448");
    }

    #[test]
    fn resolve_listen_only_is_listen_over_the_one_endpoint() {
        // pico: `listen != NULL && connect == NULL` -> key = LISTEN
        // (session.c:105-106), so the locator list is the listen endpoint.
        let empty: [&str; 0] = [];
        let resolved =
            resolve_static_config(Some("tcp/0.0.0.0:7447"), &empty).expect("listen-only resolves");
        assert_eq!(resolved.role, StaticRole::Listen);
        assert_eq!(resolved.locators.len(), 1);
        assert_eq!(resolved.locators[0], "tcp/0.0.0.0:7447");
    }

    #[test]
    fn resolve_listen_with_connect_is_refused_not_silently_halved() {
        // pico: both set, no `_z_new_peer` -> `_Z_ERROR_RETURN(_Z_ERR_GENERIC)`
        // (session.c:107-108). The failure this pins is the SILENT one: a
        // resolution that dropped either half would return Ok here.
        let connect = ["tcp/127.0.0.1:7447"];
        // `.err()` rather than comparing the whole Result: StaticConfig holds
        // a BoundedVec, which implements no PartialEq on either backing, and
        // a derive here would exist only to serve this one assertion.
        assert_eq!(
            resolve_static_config(Some("tcp/0.0.0.0:7448"), &connect).err(),
            Some(StaticConfigError::ListenWithConnect)
        );
    }

    #[test]
    fn resolve_neither_is_open_over_an_empty_list_not_an_error() {
        // pico: neither set -> early `return _Z_RES_OK` with an EMPTY svec
        // (session.c:90-92), which `_z_open` reads as "now scout". The empty
        // list is a fact this transform reports, not a verdict it renders.
        let empty: [&str; 0] = [];
        let resolved = resolve_static_config(None, &empty).expect("neither is not an error");
        assert_eq!(resolved.role, StaticRole::Open);
        assert!(resolved.locators.is_empty());
    }

    #[test]
    fn resolve_treats_a_blank_listen_as_absent() {
        // Config hygiene, the rule the connect entries already obey: an empty
        // value is not an endpoint. So a blank listen must NOT flip the role,
        // and must not collide with a real connect list either.
        let connect = ["tcp/127.0.0.1:7447"];
        let resolved =
            resolve_static_config(Some("   "), &connect).expect("blank listen is absent");
        assert_eq!(resolved.role, StaticRole::Open);
        assert_eq!(resolved.locators.len(), 1);
        assert_eq!(resolved.locators[0], "tcp/127.0.0.1:7447");
    }

    #[test]
    fn resolve_trims_the_listen_endpoint() {
        let empty: [&str; 0] = [];
        let resolved =
            resolve_static_config(Some("  tcp/0.0.0.0:7447 "), &empty).expect("listen resolves");
        assert_eq!(resolved.locators[0], "tcp/0.0.0.0:7447");
    }

    #[test]
    fn resolve_listen_with_an_all_blank_connect_is_listen() {
        // The ONE documented divergence from pico, which tests the raw
        // `_z_config_get` pointer and would error. wz decides the refusal on
        // the post-hygiene list, because it has already defined a blank entry
        // as not a locator — erroring on a list it is about to discard would
        // refuse a conflict that does not exist.
        let connect = ["", "   "];
        let resolved = resolve_static_config(Some("tcp/0.0.0.0:7447"), &connect)
            .expect("an all-blank connect is not a connect");
        assert_eq!(resolved.role, StaticRole::Listen);
        assert_eq!(resolved.locators[0], "tcp/0.0.0.0:7447");
    }

    #[test]
    fn listen_forces_peer_mode_and_open_does_not() {
        // pico's listen arm does TWO things: it places the endpoint AND
        // inserts `mode=peer` (session.c:96, :110). This pins the second one
        // separately, so a resolution that placed the endpoint while leaving
        // the node a client — pico's default, `session.c:122` — still fails.
        assert!(StaticRole::Listen.forces_peer_mode());
        assert!(!StaticRole::Open.forces_peer_mode());
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
