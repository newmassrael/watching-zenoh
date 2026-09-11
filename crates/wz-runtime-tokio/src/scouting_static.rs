// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2570 — static mode's MULTI-PEER bring-up: the whole deploy as faces.
//!
//! # The arm this module is
//!
//! zenoh-pico dispatches a static deploy on the node's mode
//! (`vendor/zenoh-pico/src/net/session.c` @
//! `z_result_t _z_open_locators(_z_session_rc_t *zn, const _z_string_svec_t *listen_locators,`):
//!
//! - CLIENT — `_z_open_locators_client` walks the `connect=` list and the
//!   first locator that opens becomes THE transport. That arm is
//!   [`open_session_static`](crate::session_open::open_session_static), and it
//!   is complete: one session over one link is what a client is.
//! - PEER — `_z_open_locators_peer` binds the optional `listen=` endpoint as
//!   the primary transport, opens the first reachable `connect=` member if
//!   there is no listen half, and then adds EVERY remaining configured locator
//!   to the same transport's peer set (`session.c` @
//!   `z_result_t ret = _z_add_peers(&_Z_RC_IN_VAL(zn)->_tp, zid, &pending_peers, config, connect_exit_on_failure);`,
//!   which opens each through `vendor/zenoh-pico/src/transport/manager.c` @
//!   `z_result_t _z_new_peer(_z_transport_t *zt, const _z_id_t *session_id, const _z_string_t *locator,`).
//!
//! This module is the PEER arm. It had no wz counterpart: the whole
//! `scouting-static` runtime surface was the single-session opener, so a
//! peer-mode deploy naming three locators held one of them and dropped the
//! rest — the residual the `scouting-static` atom carried.
//!
//! # Why it produces SOURCES rather than a session
//!
//! wz's multi-peer transport is the peer-mesh face loop
//! ([`peer_loop`](crate::accept_loop::peer_loop)): bind once, dial the
//! configured set, hold every link that reaches Established as a face and
//! drive them all on one task. That is what pico's `_z_transport_unicast_t`
//! with its peer list IS, in wz's shape — several links, one node identity,
//! one dispatch — so the peer arm of a static deploy is not a second transport
//! implementation, it is a static deploy reaching the loop that already exists.
//!
//! A loop cannot be RETURNED, though: it runs until shutdown and its lifecycle,
//! forwarder and event sink belong to the host. So this module hands back the
//! two [`FaceSources`](crate::accept_loop::FaceSources) fields the DEPLOY
//! decides — the bound listener and the resolved dial set — and the host places
//! them in the `FaceSources` it was going to build anyway. Every other field of
//! that struct is the node's (its offer, its retry cadence, its multicast and
//! reconcile planes), which is why this returns those two and not a whole
//! `FaceSources` it would have to invent defaults for.
//!
//! # Gating
//!
//! `scouting-static` (it reads the static deploy) AND `routing-peer` (it feeds
//! the mesh loop, and `BoundListener` + the dial set are only useful to that
//! loop). The same pairing `scouting_autoconnect` has and for the same reason:
//! a build with the first and not the second could resolve a deploy and would
//! have nowhere to bring it up.

use std::io;

use wz_codecs::whatami::WhatAmI;
use wz_session_core::locator::AnyLocator;
use wz_session_core::scout_static::{resolve_static_config, StaticConfigError};

use crate::session_open::{
    bind_endpoint_with_config, resolve_mesh_dial_target, AcceptConfig, BoundListener,
    DialTargetError,
};

/// The two [`FaceSources`](crate::accept_loop::FaceSources) fields a static
/// deploy decides, brought up and resolved — what
/// [`static_peer_sources`] hands back.
///
/// A named struct rather than a tuple because a caller places these into a
/// struct whose OTHER eleven fields are also a listener list and a locator
/// list's neighbours: `sources.listeners` says which one where `sources.0`
/// would not.
pub struct StaticPeerSources {
    /// The bound `listen=` endpoint, or empty when the deploy configures none.
    ///
    /// At most one, which is pico's own bound on the listen half
    /// (`vendor/zenoh-pico/src/net/session.c` @
    /// `_Z_ERROR("Multiple listen locators are not supported in zenoh-pico");`).
    /// A `Vec` regardless because that is
    /// [`FaceSources::listeners`](crate::accept_loop::FaceSources::listeners)'
    /// type, and an empty one is its documented "accept nothing" — a dial-only
    /// peer, expressible without inventing a listener.
    pub listeners: Vec<BoundListener>,
    /// EVERY `connect=` member, resolved to the numeric locator the mesh loop
    /// dials — the whole peer set, in deploy order, not the first one that
    /// happens to answer.
    ///
    /// This is the field the atom's residual was about. The loop dials each
    /// member and holds each that reaches Established, so a three-locator
    /// deploy ends up holding three faces where the single-session opener held
    /// one.
    pub dial_targets: Vec<AnyLocator>,
}

impl core::fmt::Debug for StaticPeerSources {
    /// Hand-written because [`BoundListener`] derives nothing — it holds live
    /// sockets, which have no useful rendering. The COUNTS are what a
    /// bring-up diagnostic is about anyway ("how many halves came up"), and the
    /// dial set renders in full because each member is a configured value the
    /// operator can check against their deploy.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticPeerSources")
            .field("listeners", &self.listeners.len())
            .field("dial_targets", &self.dial_targets)
            .finish()
    }
}

/// Why a static deploy could not be brought up as a peer face set.
///
/// Every variant carries what the operator configured, because each one is a
/// STARTUP diagnostic: a deploy that names an endpoint this node cannot serve
/// must say which endpoint and why, not come up half-honoured. That is the
/// same judgement [`FaceSources::dial_targets`](crate::accept_loop::FaceSources::dial_targets)
/// records for its own refusal — the loop warns and drops, because by then the
/// node is running; here the node has not started yet, so the answer is to
/// refuse.
#[derive(Debug)]
pub enum StaticPeerError {
    /// The `listen=` / `connect=` pair did not resolve.
    BadStaticConfig(StaticConfigError),
    /// The node announces [`WhatAmI::Client`], and a client has no peer set.
    ///
    /// pico's own dispatch: `_z_open_locators` sends a client to
    /// `_z_open_locators_client` — one transport, first Established wins — and
    /// refuses a client that configures a listen endpoint outright
    /// (`vendor/zenoh-pico/src/net/session.c` @
    /// `_Z_ERROR("Listen locators are not supported in client mode");`).
    /// [`open_session_static`](crate::session_open::open_session_static) is
    /// that arm; this one is not a substitute for it.
    ClientMode,
    /// Neither half is configured, so there is nothing to bring up — pico's
    /// `_z_open_locators` @
    /// `_Z_ERROR("No listen or connect locators configured");`.
    ///
    /// Static mode is scouting expressed as absent, so unlike pico there is no
    /// discovery to fall through to: an empty deploy is the whole answer.
    NothingConfigured,
    /// The `listen=` endpoint did not bind. Carries the endpoint as configured
    /// beside the OS error, because "address in use" without the address is
    /// not a diagnostic.
    Bind {
        /// The `listen=` value as configured.
        endpoint: String,
        /// What the bind seam answered.
        source: io::Error,
    },
    /// A `connect=` member is not a mesh-dialable target — malformed,
    /// unresolvable, or one of the endpoint shapes with no pre-handshake
    /// identity. The inner error carries the operator's own string.
    BadDialTarget(DialTargetError),
}

/// Bring up a static deploy as a peer face SET — the wz analog of pico's
/// `_z_open_locators_peer` (`vendor/zenoh-pico/src/net/session.c` @
/// `z_result_t _z_open_locators_peer(_z_session_rc_t *zn, _z_string_t *listen_locator,`).
///
/// Binds the `listen=` endpoint if there is one and resolves every `connect=`
/// member, then hands both back for
/// [`peer_loop`](crate::accept_loop::peer_loop) to hold. The loop's own
/// establishment is what corresponds to pico's `_z_add_peers`: each dial that
/// reaches Established becomes a held face, and the ones that do not are
/// re-dialed on the loop's schedule rather than abandoning the deploy.
///
/// # Two divergences from pico, both stated rather than hidden
///
/// - pico designates ONE locator the primary transport and the rest peers on
///   it; wz holds every face the same way, because `face_drive_loop` has no
///   primary ("a held face is a held face" —
///   [`accept_loop`](crate::accept_loop)'s own module doc). The observable
///   difference is on failure: losing pico's primary tears the session down,
///   losing a wz face leaves the others up.
/// - pico's peer arm returns only once the primary is open, and reports
///   `_Z_ERR_TRANSPORT_OPEN_FAILED` when neither half came up. This returns as
///   soon as the sockets are BOUND and the targets RESOLVED, because the loop
///   that dials has not started yet. Reachability is therefore the loop's
///   report (a face that never comes up), not this function's — the same split
///   the single-session opener draws between [`AcceptConfig`] material and
///   `NoReachableLocator`.
///
/// # Errors
///
/// [`StaticPeerError`], one variant per refusal, each naming the configured
/// value it refused. A deploy is brought up whole or not at all: a `connect=`
/// member this node cannot dial fails the call rather than being dropped from
/// the set, because a peer set silently missing a member is the defect this
/// whole module exists to close.
pub async fn static_peer_sources<S: AsRef<str>>(
    listen: Option<&str>,
    connect: &[S],
    whatami: WhatAmI,
    accept_cfg: &AcceptConfig,
) -> Result<StaticPeerSources, StaticPeerError> {
    if whatami == WhatAmI::Client {
        return Err(StaticPeerError::ClientMode);
    }
    let resolved =
        resolve_static_config(listen, connect).map_err(StaticPeerError::BadStaticConfig)?;
    if resolved.listen.is_none() && resolved.connect.is_empty() {
        return Err(StaticPeerError::NothingConfigured);
    }

    let mut listeners = Vec::new();
    if let Some(endpoint) = resolved.listen.as_ref() {
        let endpoint = endpoint.as_str();
        log::info!("wz static deploy: binding listen endpoint {endpoint:?} (peer mode)");
        let bound = bind_endpoint_with_config(endpoint, accept_cfg)
            .await
            .map_err(|source| StaticPeerError::Bind {
                endpoint: endpoint.to_string(),
                source,
            })?;
        listeners.push(bound);
    }

    // EVERY member, resolved at configuration time — the name lookup a DNS
    // target needs happens here, where blocking is free, and never inside the
    // loop. `resolve_mesh_dial_target` is the shared resolver, so a static
    // deploy reads the same grammar a `--connect` flag does and refuses the
    // same endpoint shapes for the same stated reason.
    let mut dial_targets = Vec::with_capacity(resolved.connect.len());
    for locator in resolved.connect.iter() {
        let target = resolve_mesh_dial_target(locator.as_str())
            .await
            .map_err(StaticPeerError::BadDialTarget)?;
        dial_targets.push(target);
    }

    log::info!(
        "wz static deploy: peer face set — {} listener(s), {} dial target(s)",
        listeners.len(),
        dial_targets.len()
    );
    Ok(StaticPeerSources {
        listeners,
        dial_targets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mode dispatch, pinned on the arm that must NOT reach here. A client
    /// has one transport; routing it into the peer face set would give it a
    /// mesh it cannot announce.
    #[tokio::test]
    async fn a_client_is_refused_because_a_client_has_no_peer_set() {
        let connect = ["tcp/127.0.0.1:7447"];
        let err = static_peer_sources(None, &connect, WhatAmI::Client, &AcceptConfig::default())
            .await
            .expect_err("a client has no peer set");
        assert!(
            matches!(err, StaticPeerError::ClientMode),
            "expected ClientMode, got {err:?}"
        );
    }

    /// An empty deploy is refused rather than brought up as a node that
    /// neither listens nor dials — pico's "No listen or connect locators
    /// configured".
    #[tokio::test]
    async fn an_empty_deploy_is_refused_not_brought_up_silent() {
        let empty: [&str; 0] = [];
        let err = static_peer_sources(None, &empty, WhatAmI::Peer, &AcceptConfig::default())
            .await
            .expect_err("an empty deploy has nothing to bring up");
        assert!(
            matches!(err, StaticPeerError::NothingConfigured),
            "expected NothingConfigured, got {err:?}"
        );
    }

    /// A `connect=` member with no pre-handshake identity fails the WHOLE
    /// deploy. The discriminator is that the GOOD member is present too: a
    /// resolution that dropped the bad one and kept the good one would return
    /// `Ok` here, which is exactly the silent half-honouring this module
    /// exists to refuse.
    #[tokio::test]
    async fn one_undialable_member_refuses_the_whole_deploy() {
        let connect = ["tcp/127.0.0.1:7447", "serial//dev/ttyUSB0#baudrate=115200"];
        let err = static_peer_sources(None, &connect, WhatAmI::Peer, &AcceptConfig::default())
            .await
            .expect_err("a serial endpoint has no pre-handshake identity");
        assert!(
            matches!(
                err,
                StaticPeerError::BadDialTarget(DialTargetError::UnsupportedScheme { .. })
            ),
            "expected BadDialTarget(UnsupportedScheme), got {err:?}"
        );
    }

    /// EVERY configured locator becomes a dial target, in deploy order — the
    /// claim the single-session opener cannot make, since it returns after the
    /// first that reaches Established.
    #[tokio::test]
    async fn every_connect_member_becomes_a_dial_target_in_deploy_order() {
        let connect = [
            "tcp/127.0.0.1:7447",
            "tcp/127.0.0.1:7448",
            "tcp/127.0.0.1:7449",
        ];
        let sources = static_peer_sources(None, &connect, WhatAmI::Peer, &AcceptConfig::default())
            .await
            .expect("a dial-only peer deploy resolves");
        assert!(
            sources.listeners.is_empty(),
            "no listen= was configured, so the loop accepts nothing"
        );
        let ports: Vec<u16> = sources
            .dial_targets
            .iter()
            .map(|t| match t {
                AnyLocator::Ip(p) => p.addr.port(),
                other => panic!("expected a numeric target, got {other:?}"),
            })
            .collect();
        assert_eq!(
            ports,
            vec![7447, 7448, 7449],
            "the whole connect list survives, in deploy order"
        );
    }

    /// `listen=` AND `connect=` together — the pair the single-session opener
    /// refuses as `ListenWithConnect`, brought up whole here. This is the arm
    /// pico gates behind `Z_FEATURE_UNICAST_PEER`, and the reason the resolved
    /// config had to stop discarding one of its halves.
    #[tokio::test]
    async fn listen_and_connect_are_both_brought_up() {
        let connect = ["tcp/127.0.0.1:7447", "tcp/127.0.0.1:7448"];
        let sources = static_peer_sources(
            Some("tcp/127.0.0.1:0"),
            &connect,
            WhatAmI::Peer,
            &AcceptConfig::default(),
        )
        .await
        .expect("a listen+connect peer deploy resolves");
        assert_eq!(
            sources.listeners.len(),
            1,
            "the listen endpoint is bound, not dropped"
        );
        assert_eq!(
            sources.dial_targets.len(),
            2,
            "the connect list is dialed, not dropped"
        );
    }

    /// A `listen=` that cannot bind names the endpoint it failed on. Bound
    /// twice on the same concrete port so the second attempt is deterministic.
    #[tokio::test]
    async fn a_listen_that_cannot_bind_names_the_endpoint() {
        let held = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("hold a port");
        let addr = held.local_addr().expect("addr");
        let empty: [&str; 0] = [];
        let err = static_peer_sources(
            Some(&format!("tcp/{addr}")),
            &empty,
            WhatAmI::Peer,
            &AcceptConfig::default(),
        )
        .await
        .expect_err("the port is already held");
        let StaticPeerError::Bind { endpoint, .. } = err else {
            panic!("expected Bind, got {err:?}");
        };
        assert_eq!(endpoint, format!("tcp/{addr}"));
    }
}
