// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a configuration document means for an open, as a value: the [`OpenPlan`].
//!
//! Opening a session from a zenoh configuration is three separate things, and they used to be one
//! function of the C ABI:
//!
//! 1. **Reading** the document: which role the node takes, which endpoints it dials and binds,
//!    how long and how often it tries, what its links offer at the handshake, which identity and
//!    which security it holds. This is a function of the document and of what the build carries.
//! 2. **Refusing** the documents the open cannot carry out, each refusal naming the key that
//!    caused it ([`OpenRefusal::key`]).
//! 3. **Running** the open: sockets, threads, clocks.
//!
//! This module is the first two. [`OpenPlan::resolve`] performs no network, thread or clock work;
//! the only I/O it does is reading the credential and certificate files the document names, which
//! is where an unreadable one is refused. Its result is a plain value that can be compared and
//! described ([`OpenPlan::describe`]), so the reading is testable without a socket and the same
//! for every client of the engine: the C ABI maps a refusal to `z_result_t`, a Rust API maps it to
//! its own error, and neither re-reads a key.
//!
//! The third part is [`OpenArguments::run`], which hands the plan to this engine's
//! [`open_blocking`]. Decisions that belong to an ABI and not to the document (the transmit
//! model, whether a read task runs, who runs the callbacks of a local delivery, how faces are
//! driven, the shared-memory reader) are the caller's [`AbiChoices`] and join the plan only at
//! [`OpenPlan::into_arguments`], so the plan itself is the same for every ABI.
//!
//! The refusals are produced in a fixed order, which is the order the C ABI has always answered
//! in: a document that would be refused for two reasons reports the earlier. The order is held by
//! the characterization table in `wz-capi-c` (`tests/open_refusals.rs`).

use wz_runtime_tokio::accept_bounds::AcceptBounds;
use wz_runtime_tokio::node_clock::TimestampingEnabled;
use wz_runtime_tokio::policy::{SessionPolicy, SnResolution};
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::session::LocalDeliveryDrain;
use wz_runtime_tokio::session_glue::{KeepAliveConf, LinkRxConf, TxQueueConf, WhatAmI};
use wz_runtime_tokio::session_open::{SessionOffer, TransportMode};
use wz_runtime_tokio::startup_phase::PhasePolicy;
use wz_runtime_tokio::zenoh_config::{
    default_listen_endpoint, honours_config_key, ZenohConfigIngest, ZenohNodeConfig,
    UNHONOURED_READER_GAP, UNHONOURED_UPSTREAM_CONFIG_KEYS, UPSTREAM_INERT_CONFIG_KEYS,
    WZ_EXTENSION_CONFIG_KEYS,
};
#[cfg(feature = "routing-namespace")]
use wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr;

use crate::drive::{
    names_a_group, open_blocking, CapiTlsConfig, ConfiguredZid, DialPhase, FaceDrive,
    GroupDeclarations, GroupJoin, GroupProfile, ListenPhase, OpenError, OpenStance, SessionState,
    DEFAULT_BATCH_SIZE, DEFAULT_LEASE_MS,
};
use crate::faces::OpenShmClients;
use crate::gossip::GossipPolicy;
use crate::node_auth::NodeAuth;
use crate::node_policy::NodePolicy;
#[cfg(feature = "scout")]
use crate::scouting_node::ScoutingPlan;

/// The mode a node dials as, from the `mode` key it states.
///
/// Default PEER, which is zenoh's own default when the key is absent
/// (`commons/zenoh-config/src/defaults.rs` @ `pub const mode: WhatAmI = WhatAmI::Peer;`).
/// It said CLIENT until R2948 while claiming to match zenoh, and a config that named no mode
/// dialled with a client's one-attempt budget where zenoh-c's peer keeps trying behind the open.
///
/// A build without the `peer` feature has no peer role to default to, so a config that names no
/// mode is the client's there; one that names `peer` or `router` is still read as such, and is
/// refused by [`OpenPlan::resolve`] as a role the build does not have.
///
/// The role is read before the document because several keys are mode-dependent upstream: the
/// document is rendered or parsed for the role the node dials as.
pub fn dial_role(mode: Option<&str>) -> WhatAmI {
    match mode {
        Some("client") => WhatAmI::Client,
        Some("router") => WhatAmI::Router,
        Some("peer") => WhatAmI::Peer,
        _ if cfg!(feature = "peer") => WhatAmI::Peer,
        _ => WhatAmI::Client,
    }
}

/// What the engine does with one key of a configuration document.
///
/// Every leaf key of a zenoh configuration is in exactly one of three states (decision D6 of
/// `docs/zenoh-api-on-the-engine.md`), kept beside the lists of the runtime's reader that say it
/// ([`key_state`]). The plan reports the keys a document states that are not [`Self::Mapped`]
/// ([`OpenPlan::ignored`]), and what an open does with them is its client's: the C ABI accepts them,
/// as the reference library's own C binding accepts a key it does nothing with, and the Rust API
/// refuses the ones that are [`Self::Unmapped`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    /// The engine acts on the key.
    Mapped,
    /// Upstream itself does nothing with the key (it declares and serialises it and no code reads it,
    /// or it parses and discards it), so stating it changes nothing here either.
    Inert,
    /// Upstream acts on the key and this engine does not yet: stating it with a value other than its
    /// default asks for something that will not happen.
    Unmapped,
}

/// The state of the key `path` (`transport/link/tx/threads`), or `None` for a key no list of the
/// runtime's reader knows: one a bump of the pinned upstream added, which has no state until it is
/// given one, and which a test over the default configuration fails on until then.
pub fn key_state(path: &str) -> Option<KeyState> {
    if honours_config_key(path) {
        Some(KeyState::Mapped)
    } else if UPSTREAM_INERT_CONFIG_KEYS.contains(&path) || WZ_EXTENSION_CONFIG_KEYS.contains(&path)
    {
        Some(KeyState::Inert)
    } else if UNHONOURED_UPSTREAM_CONFIG_KEYS.contains(&path)
        || UNHONOURED_READER_GAP.contains(&path)
        || INLINE_CERTIFICATE_KEYS.contains(&path)
    {
        Some(KeyState::Unmapped)
    } else {
        None
    }
}

/// The five keys that give a certificate or a key of the `tls/` and `quic/` links inline, base64
/// encoded, where the keys `tls_of` reads name a file.
///
/// Upstream declares them as options with no default, so a running zenohd's resolved configuration
/// does not carry them and the lists of the runtime's reader, which are adjudicated against that
/// resolved configuration, do not name them; they are named here, so that stating one is refused as
/// an instruction the engine does not carry out and not taken for a key nobody has a state for.
pub const INLINE_CERTIFICATE_KEYS: &[&str] = &[
    "transport/link/tls/root_ca_certificate_base64",
    "transport/link/tls/listen_private_key_base64",
    "transport/link/tls/listen_certificate_base64",
    "transport/link/tls/connect_private_key_base64",
    "transport/link/tls/connect_certificate_base64",
];

/// Whether `path` is not a leaf but a section that holds keys with a state (`gateway`, which holds
/// `gateway/south`): the configuration lists a section as a key when it is an option that holds
/// nothing, and such a key has no state of its own.
pub fn is_section_of_keys_with_a_state(path: &str) -> bool {
    let prefix = format!("{path}/");
    [
        wz_runtime_tokio::zenoh_config::HONOURED_CONFIG_KEYS,
        UPSTREAM_INERT_CONFIG_KEYS,
        WZ_EXTENSION_CONFIG_KEYS,
        UNHONOURED_UPSTREAM_CONFIG_KEYS,
        UNHONOURED_READER_GAP,
        INLINE_CERTIFICATE_KEYS,
    ]
    .iter()
    .any(|list| list.iter().any(|key| key.starts_with(&prefix)))
}

/// The endpoint lists the caller's own reading of the configuration states, before the document is
/// consulted.
///
/// The C ABI keeps its configuration as a flat store of keys and reads `connect/endpoints` and
/// `listen/endpoints` from it; a caller that reads both from the document hands them over the same
/// way. An empty `listen` states nothing, and the plan then asks the document, and then the role's
/// default (see [`OpenPlan::resolve`]). `connect` is dialled as stated and has no default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatedEndpoints {
    /// `connect/endpoints`, in the order stated: each is dialled on its own schedule.
    pub connect: Vec<String>,
    /// `listen/endpoints`, in the order stated, or empty when the caller read none.
    pub listen: Vec<String>,
}

/// Why a document cannot be opened. Each refusal names the key that caused it, and none is a
/// fallback: a document that asked for something the open cannot do is never run as if it had not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenRefusal {
    /// The document could not be rendered, or [`ZenohNodeConfig`]'s reader refused it (a key zenoh
    /// does not have, two keys that cannot both be nested, a value out of range). Reported after
    /// every refusal that needs no document, which is where the C ABI has always reported it.
    DocumentUnreadable,
    /// An authentication or traffic-policy mechanism the document names cannot be held: a
    /// credential file that cannot be read or holds no user, a user without a password, an
    /// identity that cannot be loaded, a policy the compiler refuses, or a build without the
    /// mechanism. A node told to demand credentials that starts and admits everyone is worse than
    /// one that does not start.
    Security,
    /// A certificate or key file `transport/link/tls` names cannot be read.
    TlsMaterial,
    /// `id` is not text zenoh accepts as an identity. A config that named an identity and got
    /// another would be a silent fallback.
    ZenohId,
    /// Both `transport/unicast/qos` and `transport/unicast/lowlatency` are enabled: upstream's
    /// transport manager refuses them when it is built (`'qos' and 'lowlatency' options are
    /// incompatible`).
    QosWithLowlatency,
    /// Multicast scouting is configured with a group this host cannot scout on.
    Scouting,
    /// The document asks for a listener or a role other than the client's, in a build without the
    /// `peer` feature.
    RoleNotInBuild,
    /// The document enables a clock for this role, in a build without `timestamping`.
    TimestampingNotInBuild,
    /// The gossip target for this role names `client`, which upstream refuses at open
    /// (`"client" is not allowed as gossip target`).
    GossipTarget,
    /// A client with no endpoint to dial and no scouting to find one (zenoh's `start_client` bails
    /// "No peer specified and multicast scouting deactivated!").
    NothingToDial,
    /// A peer or a router is told to dial a multicast group, which upstream refuses
    /// (`Forbidden multicast endpoint in connect list!`).
    GroupInConnect,
    /// A client's only endpoints are multicast groups, which no unicast link can dial.
    NoDialableEndpoint,
    /// The document states a `namespace` the open cannot carry out: it is not a key expression a
    /// prefix can be (it holds a wildcard, or is empty), or the build has no `routing-namespace`.
    /// A session told to prefix every key it publishes that opens and does not is worse than one
    /// that does not open: its keys leave unprefixed and nothing says so.
    Namespace,
}

impl OpenRefusal {
    /// The configuration key or keys the refusal is about, as a zenoh user writes them.
    pub const fn key(self) -> &'static str {
        match self {
            Self::DocumentUnreadable => "(the configuration document)",
            Self::Security => "transport/auth, access_control, low_pass_filter, downsampling",
            Self::TlsMaterial => "transport/link/tls",
            Self::ZenohId => "id",
            Self::QosWithLowlatency => "transport/unicast/qos, transport/unicast/lowlatency",
            Self::Scouting => "scouting/multicast",
            Self::RoleNotInBuild => "mode, listen/endpoints",
            Self::TimestampingNotInBuild => "timestamping/enabled",
            Self::GossipTarget => "scouting/gossip/target",
            Self::NothingToDial => "connect/endpoints, scouting/multicast/enabled",
            Self::GroupInConnect | Self::NoDialableEndpoint => "connect/endpoints",
            Self::Namespace => "namespace",
        }
    }
}

/// How a session's bind phase treats an endpoint it cannot bind: `listen/timeout_ms` and
/// `listen/exit_on_failure` over upstream's listen defaults, which are the same for every role
/// (no retry, and a failure fails the open), paced by `listen/retry`.
///
/// R3089 -- the bind twin of [`dial_phase`], read from the same document. R3076 read only the
/// exit value; the budget and the schedule were read by the node config and used by no C session.
fn listen_phase_of(node: &ZenohNodeConfig) -> ListenPhase {
    let default = PhasePolicy::LISTEN_DEFAULT;
    ListenPhase {
        policy: PhasePolicy {
            budget: node.listen_timeout_ms.unwrap_or(default.budget),
            exit_on_failure: node
                .listen_exit_on_failure
                .unwrap_or(default.exit_on_failure),
        },
        schedule: node.listen_retry.unwrap_or(RetryPolicy::ZENOH_DEFAULT),
    }
}

/// How the dial keeps trying, read from the config the way a zenoh node reads it.
///
/// `connect/timeout_ms` and `connect/exit_on_failure` are mode-dependent upstream, and so are
/// their defaults: a client makes ONE attempt, a peer or router retries without bound. Both are
/// resolved for the role this session DIALS as, which is why the document is read with that role
/// stated. `connect/retry` paces the attempts and falls back to upstream's 1s / 2s / 4s.
fn dial_phase(node: &ZenohNodeConfig, whatami: WhatAmI) -> DialPhase {
    let default = PhasePolicy::connect_default_for(whatami);
    let schedule = node.connect_retry.unwrap_or(RetryPolicy::ZENOH_DEFAULT);
    DialPhase {
        policy: PhasePolicy {
            budget: node.connect_timeout_ms.unwrap_or(default.budget),
            exit_on_failure: node
                .connect_exit_on_failure
                .unwrap_or(default.exit_on_failure),
        },
        schedule,
        // R2948 — zenoh re-dials a lost session's endpoints on the same
        // `connect/retry` block, with no budget.
        redial: Some(schedule),
        // R2950 — a peer's open waits `scouting/delay` for its background
        // endpoints unless `open/return_conditions/connect_scouted` is false;
        // upstream's defaults are 500 ms and true.
        start_window: node
            .open_connect_scouted
            .unwrap_or(true)
            .then(|| std::time::Duration::from_millis(node.scouting_delay_ms.unwrap_or(500))),
        // R3125 -- and a router's open is held for the same delay in full, unconditionally
        // (`start_router` sleeps it), where a peer's ends when its start conditions are met.
        router_hold: std::time::Duration::from_millis(node.scouting_delay_ms.unwrap_or(500)),
    }
}

/// What this session's links offer at their handshake, read from its config the way zenoh's
/// transport manager reads it, WITHOUT the shared-memory half (see [`OpenPlan::shared_memory`]).
///
/// Upstream builds the unicast half from three keys
/// (`io/zenoh-transport/src/unicast/manager.rs` @
/// `self = self.qos(*config.transport().unicast().qos().enabled());`, the lowlatency line after
/// it, and the compression line behind `transport_compression`, which zenoh-c's default build
/// carries). Both the dialling and the accepting side read the same manager config, so one value
/// serves both.
///
/// The defaults are upstream's, and QoS is ON: an unconfigured zenoh-c session offers it. A
/// session that offered nothing — what this ABI did until R2970 — agreed on no QoS with another
/// zenoh-c session, where two real ones do.
///
/// QoS and lowlatency together are refused, as upstream's manager refuses them when it is built,
/// which is inside `zenoh::open` and so reaches a caller as an open failure.
fn session_offer(node: &ZenohNodeConfig) -> Result<SessionOffer, OpenRefusal> {
    let mode = match (node.qos, node.lowlatency) {
        (true, true) => return Err(OpenRefusal::QosWithLowlatency),
        (true, false) => TransportMode::Qos,
        (false, true) => TransportMode::LowLatency,
        (false, false) => TransportMode::Universal,
    };
    Ok(SessionOffer::universal()
        .with_mode(mode)
        .with_compression(node.compression))
}

/// The endpoint this session listens on: the one its config states, or, when the config says
/// nothing about `listen/endpoints`, the one a zenoh node of its role binds on its own.
///
/// R3071 -- before this a session with no stated listener bound nothing, though a real peer binds
/// `tcp/[::]:0` and a real router `tcp/[::]:7447` (`default_listen_endpoint`, MEASURED against a
/// running zenohd at R2091b), so a node that scouts could answer and be found and still hand its
/// finder nothing to dial. A key the config NAMES suppresses the default, as an explicitly empty
/// list does on the real library, and so does a mode table that names no row for this role. A
/// client has no default, and its absence is the instruction.
///
/// R3076 -- EVERY endpoint the config states, in its order, and not the first of them: the real
/// library binds each (MEASURED with two tcp endpoints, a client connected to either is accepted,
/// and wz bound only the first). A key stated as a mode table is the row for this node's role,
/// which the reader resolved; a table with no row for it states nothing for it.
fn listen_endpoints(
    stated: Vec<String>,
    ingest: Option<&ZenohConfigIngest>,
    whatami: WhatAmI,
) -> Vec<String> {
    if !stated.is_empty() {
        return stated;
    }
    if let Some(ingest) = ingest {
        if ingest.named.contains(&"listen/endpoints") {
            return ingest.config.listen.clone();
        }
        if ingest.stated_for_other_modes.contains(&"listen/endpoints") {
            return Vec::new();
        }
    }
    default_listen_endpoint(whatami)
        .map(str::to_owned)
        .into_iter()
        .collect()
}

/// The largest batch zenoh puts on a multicast link, whatever its config states
/// (`commons/zenoh-protocol/src/transport/mod.rs` @ `pub const MULTICAST: BatchSize = 8_192;`).
const ZENOH_MULTICAST_BATCH: u16 = 8_192;

/// Open-debt item 913 — what a zenoh session's JOIN advertises on a group, as zenoh's multicast
/// transport fills it (`io/zenoh-transport/src/multicast/transport.rs` @
/// `join_interval: self.manager.config.multicast.join_interval,`, beside the batch capped at
/// `batch_size::MULTICAST`): the link lease of `transport/link/tx/lease`, the beacon interval of
/// `transport/multicast/join_interval`, the default resolution of both sequence numbers and
/// request ids (32 bits; the build's `sn-resolution` policy states another width of the
/// sequence number), the session's batch size held to the multicast cap (the UDP link's own
/// MTU is above it on every target zenoh names), and per-priority conduits when
/// `transport/multicast/qos/enabled` asks for them.
fn zenoh_group_profile(
    node: &ZenohNodeConfig,
    batch_size: u16,
    sn_resolution: SnResolution,
) -> GroupProfile {
    // The 2-bit code of a 32-bit resolution, zenoh's default for the request id.
    const BITS_32: u8 = 0x02;
    GroupProfile {
        lease_ms: node.lease_ms,
        join_interval_ms: node.multicast_join_interval_ms,
        seq_num_res: sn_resolution.wire_code(),
        req_id_res: BITS_32,
        batch_size: batch_size.min(ZENOH_MULTICAST_BATCH),
        is_qos: node.multicast_qos,
    }
}

/// The authentication and the traffic policy a config asks the node to hold, or an
/// [`OpenRefusal::Security`] for a config that names a security mechanism (authentication or
/// access control) this build cannot hold.
///
/// A config that names a security mechanism is never opened as if it did not.
///
///   * `transport/auth/usrpwd/dictionary_file` makes the node a responder over that dictionary;
///     a file that cannot be read, or that holds no user, fails the open.
///   * `transport/auth/usrpwd/user` and `password` make the node an initiator that presents
///     them when it dials; one stated without the other fails the open. A build without
///     `auth_usrpwd` cannot hold either, so there a config that states any of the three keys
///     fails the open.
///   * `transport/auth/pubkey/*` names the node's RSA identity, presented to the peers it dials
///     and asked of the peers it accepts (`NodeAuth::with_pubkey_config`); an identity that
///     cannot be loaded fails the open. A build without `auth_pubkey` cannot hold one, so there
///     a config that states any of the four keys fails the open.
///   * `access_control`, `low_pass_filter` and `downsampling` are compiled into the node's
///     traffic policy and enforced on every face in both directions; a subtree the compiler
///     refuses (a policy naming a rule that does not exist) fails the open, as zenoh's start
///     does. A disabled `access_control` and an absent filter state no policy at all. A build
///     without `interceptors` cannot hold a policy, so there a config that enables
///     `access_control` or states a filter or a downsampling rule fails the open.
fn node_security_of(node: &ZenohNodeConfig) -> Result<(Option<NodeAuth>, NodePolicy), OpenRefusal> {
    #[cfg(not(feature = "auth_pubkey"))]
    if node.pubkey_public_key_pem.is_some()
        || node.pubkey_private_key_pem.is_some()
        || node.pubkey_public_key_file.is_some()
        || node.pubkey_private_key_file.is_some()
    {
        return Err(OpenRefusal::Security);
    }
    #[cfg(not(feature = "auth_usrpwd"))]
    if node.usrpwd_dictionary_file.is_some()
        || node.usrpwd_user.is_some()
        || node.usrpwd_password.is_some()
    {
        return Err(OpenRefusal::Security);
    }
    #[cfg(feature = "auth_usrpwd")]
    let auth = NodeAuth::from_usrpwd_config(
        node.usrpwd_dictionary_file.as_deref(),
        node.usrpwd_user.as_deref(),
        node.usrpwd_password.as_ref(),
    )
    .map_err(|_| OpenRefusal::Security)?;
    #[cfg(not(feature = "auth_usrpwd"))]
    let auth: Option<NodeAuth> = None;
    #[cfg(feature = "auth_pubkey")]
    let auth = NodeAuth::with_pubkey_config(auth, node.pubkey_pem_config())
        .map_err(|_| OpenRefusal::Security)?;
    #[cfg(feature = "interceptors")]
    let policy = NodePolicy::from_node_config(node).map_err(|_| OpenRefusal::Security)?;
    #[cfg(not(feature = "interceptors"))]
    let policy = {
        // A build without the interceptors cannot hold a traffic policy, and a node told to
        // enforce one that starts and enforces nothing is worse than one that does not start.
        if !node.low_pass_filter.is_empty()
            || !node.downsampling.is_empty()
            || node.access_control.enabled
        {
            return Err(OpenRefusal::Security);
        }
        NodePolicy::default()
    };
    Ok((auth, policy))
}

/// The certificate material a config's `transport/link/tls` keys name, read for the `tls/` and
/// `quic/` links of the session.
///
/// `root_ca_certificate` is what a dial verifies its peer against (with none, the public roots),
/// and `listen_certificate` with `listen_private_key` is what a listener presents. Each is a path,
/// read here, at the open: upstream reads the files when it first makes a link of that kind, so a
/// path that cannot be read fails this open where upstream's would fail only once such a link
/// was made, which is the direction a security setting fails in on this surface. A dial checks
/// the name it dials against the peer's certificate, which is upstream's behaviour when
/// `verify_name_on_connect` is left unstated; the reader does not read that key, nor the mutual
/// TLS ones, so a session never presents a client certificate.
#[cfg(any(feature = "transport_tls", feature = "transport_quic"))]
fn tls_of(node: &ZenohNodeConfig) -> std::io::Result<CapiTlsConfig> {
    use wz_runtime_tokio::tls_config::read_pem_file;
    let read = |path: Option<&String>| path.map(read_pem_file).transpose();
    Ok(CapiTlsConfig {
        root_ca_pem: read(node.tls_root_ca.as_ref())?,
        verify_name_on_connect: true,
        connect_cert_pem: None,
        connect_key_pem: None,
        listen_cert_pem: read(node.tls_listen_certificate.as_ref())?,
        listen_key_pem: read(node.tls_listen_private_key.as_ref())?,
        require_client_auth: false,
    })
}

/// A build with neither certificate-bearing link has nothing to read the material for: a `tls/`
/// or `quic/` endpoint is refused by the runtime as a scheme it does not have.
#[cfg(not(any(feature = "transport_tls", feature = "transport_quic")))]
fn tls_of(_node: &ZenohNodeConfig) -> std::io::Result<CapiTlsConfig> {
    Ok(CapiTlsConfig::default())
}

/// The files [`tls_of`] and [`node_security_of`] read, under the same features as they read
/// them: a build without a mechanism refuses its keys instead of reading their files.
fn files_read_by_resolve(node: &ZenohNodeConfig) -> Vec<String> {
    #[allow(unused_mut)]
    let mut out: Vec<String> = Vec::new();
    #[cfg(any(feature = "transport_tls", feature = "transport_quic"))]
    out.extend(
        [
            &node.tls_root_ca,
            &node.tls_listen_certificate,
            &node.tls_listen_private_key,
        ]
        .into_iter()
        .flatten()
        .cloned(),
    );
    #[cfg(feature = "auth_usrpwd")]
    out.extend(node.usrpwd_dictionary_file.iter().cloned());
    #[cfg(feature = "auth_pubkey")]
    out.extend(
        [&node.pubkey_public_key_file, &node.pubkey_private_key_file]
            .into_iter()
            .flatten()
            .cloned(),
    );
    #[cfg(not(any(
        feature = "transport_tls",
        feature = "transport_quic",
        feature = "auth_usrpwd",
        feature = "auth_pubkey"
    )))]
    let _ = node;
    out
}

/// The `transport/shared_memory` keys a document states, whatever the build does with them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShmKeys {
    /// `transport/shared_memory/enabled`: whether the node offers shared memory where the build
    /// carries that axis. Upstream's default is on.
    pub enabled: bool,
    /// `transport/shared_memory/transport_optimization/enabled`: whether the session's own
    /// provider serves the transport.
    pub transport_optimization: bool,
    /// The transport optimization's pool size in bytes.
    pub pool_size: u64,
}

/// What a configuration document means for an open. See the module documentation.
pub struct OpenPlan {
    /// The role the node dials as. The roles are a set at run time (a peer that lists endpoints
    /// both listens and dials); this is the one the dial phase and the defaults are read for.
    pub role: WhatAmI,
    /// The unicast endpoints dialled, each on its own schedule.
    pub connect: Vec<String>,
    /// The unicast endpoints bound.
    pub listen: Vec<String>,
    /// The multicast groups joined, each one face to every member beside the unicast ones.
    pub groups: Vec<GroupJoin>,
    /// How the dial keeps trying.
    pub dial: DialPhase,
    /// What an endpoint that cannot be bound does to the open.
    pub listen_phase: ListenPhase,
    /// The batch size the session ADVERTISES: `transport/link/tx/batch_size`, which the peer's own
    /// is negotiated down against (the smaller wins) and a frame past which is sent as fragments.
    /// A config that states none is zenoh's default.
    pub batch_size: u16,
    /// The lease the session ADVERTISES, in milliseconds: `transport/link/tx/lease`, the one its
    /// groups' Joins already carried. A config that states none is zenoh's default.
    pub lease_ms: u64,
    /// How often the session's keepalive speaks on an idle link: `transport/link/tx/keep_alive`
    /// keepalives in the session's own lease, as upstream divides it. A config that states none
    /// is zenoh's default.
    pub keep_alive: KeepAliveConf,
    /// The width of the sequence numbers the session advertises, unicast and in a group's Join:
    /// the build's `sn-resolution` policy, 32 bits unless it states another.
    pub sn_resolution: SnResolution,
    /// How long an inbound link gets to complete its handshake and how many get it at once:
    /// `transport/unicast/accept_timeout` and `accept_pending`. A config that states none is
    /// upstream's ten seconds and a hundred.
    pub accept: AcceptBounds,
    /// What the session's links rejoin from fragments: `transport/link/rx/max_message_size`. A
    /// config that states none is zenoh's default.
    pub link_rx: LinkRxConf,
    /// What the links offer at the handshake, without shared memory.
    pub offer: SessionOffer,
    /// The `transport/shared_memory` keys. Facts about the document; whether they reach the
    /// handshake offer and the groups' transports is the build's, stated in [`AbiChoices`], and
    /// the session's own provider is built from them by the ABI that has one.
    pub shm: ShmKeys,
    /// The identity the document states for the session, if it states one.
    pub zid: Option<ConfiguredZid>,
    /// R3064 -- the clock map the document means. Read off the ingest and not the node config,
    /// because only the ingest knows whether the key was NAMED: the field reads `false` for a
    /// document that never mentioned it, and a router's own default is on.
    pub timestamping: TimestampingEnabled,
    /// What the session does with multicast scouting, or `None` when it does not scout.
    #[cfg(feature = "scout")]
    pub scouting: Option<ScoutingPlan>,
    /// How the session gossips, or `None` when it does not.
    pub gossip: Option<GossipPolicy>,
    /// The authentication the node holds.
    pub auth: Option<NodeAuth>,
    /// The traffic policy the node holds.
    pub policy: NodePolicy,
    /// The prefix every key the session publishes carries on the wire and every key it receives
    /// is relative to: the `namespace` of the document. A text that is a key expression a prefix
    /// can be is what [`Self::resolve`] lets through, and a build without `routing-namespace` has
    /// no decorator to install it with and refuses a document that states one
    /// ([`OpenRefusal::Namespace`]); so a plan that carries one is one the build can carry out.
    pub namespace: Option<String>,
    /// The certificate material for the `tls/` and `quic/` links.
    pub tls: CapiTlsConfig,
    /// The files [`Self::resolve`] read for the material above and for the authentication, in the
    /// order of their keys: what the open asks of the file system, and cannot go on without, since
    /// an unreadable one is refused (`crate::open_facilities`).
    pub read_files: Vec<String>,
    /// The keys the document states that the engine does not act on, sorted: the leaves the
    /// reader reports ignored, whether or not the value is the default. What an open does about
    /// them is its client's (see [`KeyState`]).
    pub ignored: Vec<String>,
}

impl OpenPlan {
    /// Read the document for the role `role` (see [`dial_role`]) and the endpoints the caller
    /// stated, and refuse what the open cannot carry out.
    ///
    /// `document` is the document as nested json5 with the role's `mode` stated, or `None` when
    /// the caller could not render one; a document the reader refuses is the same as none, and is
    /// reported as [`OpenRefusal::DocumentUnreadable`] after every refusal that needs no document.
    pub fn resolve(
        role: WhatAmI,
        stated: StatedEndpoints,
        document: Option<&str>,
    ) -> Result<Self, OpenRefusal> {
        let ingest = document.and_then(|document| ZenohNodeConfig::from_json5(document).ok());
        let StatedEndpoints { connect, listen } = stated;
        let listen = listen_endpoints(listen, ingest.as_ref(), role);
        let timestamping = ingest.as_ref().map_or_else(
            TimestampingEnabled::default,
            ZenohConfigIngest::timestamping_enabled,
        );
        let ignored = ingest
            .as_ref()
            .map_or_else(Vec::new, |ingest| ingest.ignored.clone());
        let node = ingest.map(|ingest| ingest.config);
        let namespace_text = node.as_ref().and_then(|node| node.namespace.clone());
        let batch_size = node
            .as_ref()
            .map_or(DEFAULT_BATCH_SIZE, |node| node.batch_size);
        let lease_ms = node.as_ref().map_or(DEFAULT_LEASE_MS, |node| node.lease_ms);
        let keep_alive = node.as_ref().map_or(KeepAliveConf::ZENOH, |node| {
            KeepAliveConf::zenoh(node.keep_alive)
        });
        let link_rx = node
            .as_ref()
            .map_or_else(LinkRxConf::default, |node| node.link_rx);
        let accept = node
            .as_ref()
            .map_or_else(AcceptBounds::default, |node| AcceptBounds {
                timeout_ms: node.accept_timeout_ms,
                pending: node.accept_pending,
            });
        let dial = node.as_ref().map(|node| dial_phase(node, role));
        // R3076 -- what an endpoint that cannot be bound does to the open (`listen/exit_on_failure`
        // for this node's role, true when the document says nothing, as upstream's default is),
        // and R3089 -- how long and how often it is tried (`listen/timeout_ms`, `listen/retry`).
        let listen_phase = node.as_ref().map_or(ListenPhase::SHIPPED, listen_phase_of);

        // The authentication and the traffic policy the config asks the node to hold. Decided
        // before anything is bound or dialled: a config that names a security mechanism this open
        // cannot hold must not become a node that runs without it.
        let (auth, policy) = match node.as_ref().map(node_security_of).transpose()? {
            Some((auth, policy)) => (auth, policy),
            None => (None, NodePolicy::default()),
        };
        // The certificate material the config names for the `tls/` and `quic/` links, refused
        // like a credential file when it cannot be read.
        let tls = match node.as_ref().map(tls_of).transpose() {
            Ok(tls) => tls.unwrap_or_default(),
            Err(_) => return Err(OpenRefusal::TlsMaterial),
        };
        let read_files = node.as_ref().map_or_else(Vec::new, files_read_by_resolve);

        // The id this config STATES for its session, if it states one. Read off the node the
        // reader already parsed, so a config's `id` is one value whether it arrived by an insert,
        // by a document or from a file, and the session stands on it: `z_info_zid` reports it and
        // the INIT carries it, which is what upstream's runtime does with the same key.
        //
        // The insert doors refuse text zenoh refuses, as upstream's do, so an unparsable `id`
        // cannot be in a config those built. It is refused here as well, rather than met with a
        // fresh random id, because a config that named an identity and got another would be the
        // silent fallback this crate refuses everywhere else.
        let zid = match node.as_ref().and_then(|node| node.id.as_deref()) {
            None => None,
            Some(text) => match ConfiguredZid::from_zenoh_text(text) {
                Some(zid) => Some(zid),
                None => return Err(OpenRefusal::ZenohId),
            },
        };

        // Decided before anything else about the open, as upstream decides it when the transport
        // manager is built — before a single endpoint is looked at. A config the reader refused
        // has no offer to derive; the `dial` check below refuses that open.
        let offer = match node.as_ref().map(session_offer).transpose()? {
            Some(offer) => offer,
            None => SessionOffer::universal(),
        };

        // What the session does with multicast scouting: look for the nodes it should connect to
        // when its config says to. A group the config names that this host cannot scout on is
        // refused here, as zenoh refuses an address it cannot parse.
        //
        // R3070 -- before this a config that left scouting on and stated no endpoint was refused,
        // which is every config a program writes without `-e`.
        #[cfg(feature = "scout")]
        let scouting = match node
            .as_ref()
            .map(|node| ScoutingPlan::resolve(node, role))
            .transpose()
        {
            Ok(plan) => plan.flatten(),
            Err(_) => return Err(OpenRefusal::Scouting),
        };
        // Whether the session looks for a node to connect to. A build without `scout` does not.
        #[cfg(feature = "scout")]
        let scouts = scouting.as_ref().is_some_and(ScoutingPlan::scouts);
        #[cfg(not(feature = "scout"))]
        let scouts = false;
        // A build without the `peer` feature is the client's: it dials the endpoints it is told
        // of (or finds its router, with `scout`), and a listener or a role other than the
        // client's is refused here and not run as a client it was not asked to be.
        #[cfg(not(feature = "peer"))]
        if !listen.is_empty() || role != WhatAmI::Client {
            return Err(OpenRefusal::RoleNotInBuild);
        }
        // A build without `timestamping` holds no clock, so a config that enables one for this
        // role is refused here and not run with the stamping it asked for silently dropped.
        #[cfg(not(feature = "timestamping"))]
        if timestamping.get(role) {
            return Err(OpenRefusal::TimestampingNotInBuild);
        }
        // The namespace the session prefixes its keys with, or the refusal of a document that
        // states one this open cannot carry out: a build without `routing-namespace` has no
        // decorator to install, and a text that is not a plain key expression is no prefix. Neither
        // is run as a session that states no namespace.
        #[cfg(feature = "routing-namespace")]
        if let Some(text) = &namespace_text {
            OwnedNonWildKeyExpr::new(text).map_err(|_| OpenRefusal::Namespace)?;
        }
        #[cfg(not(feature = "routing-namespace"))]
        if namespace_text.is_some() {
            return Err(OpenRefusal::Namespace);
        }
        let namespace = namespace_text;

        // How the session gossips, from the four `scouting/gossip` keys a C session reads, or
        // nothing when its config turns gossip off. A client has no gossip to configure (it is
        // no peer hat), so its rows are not read. A config whose target for this node's role
        // names `client` fails the OPEN, as the real library's does with `-4`
        // (`"client" is not allowed as gossip target`); it is not a config the reader refuses.
        //
        // R3075 -- before this the session gossiped under the shipped policy whatever the
        // config said.
        #[cfg(feature = "gossip")]
        let gossip = if role == WhatAmI::Client {
            None
        } else {
            match node.as_ref().map_or_else(
                || Ok(Some(GossipPolicy::shipped(role))),
                |node| GossipPolicy::resolve(node, role),
            ) {
                Ok(policy) => policy,
                Err(_) => return Err(OpenRefusal::GossipTarget),
            }
        };
        // Without the `gossip` feature a session has no policy to hold.
        #[cfg(not(feature = "gossip"))]
        let gossip: Option<GossipPolicy> = None;

        // A config that states no endpoint to DIAL. Measured on the real library: a client with
        // nothing to dial and nothing to scout for fails its open whether or not it states a
        // listener (zenoh's `start_client` bails "No peer specified and multicast scouting
        // deactivated!"), and a peer or router opens, ALONE when it has nothing to listen on
        // either, delivering to its own subscribers. A client that does scout looks for the first
        // node it can open to and fails after `scouting/timeout` if there is none.
        //
        // R3067 -- a config stating both a listener and a dial is a peer that does both, and is
        // opened as one: the roles are a set (see `open_blocking`).
        if connect.is_empty() && role == WhatAmI::Client && !scouts {
            return Err(OpenRefusal::NothingToDial);
        }
        // Checked after the refusals above so a config that states no endpoint keeps answering
        // what it always did.
        let Some(dial) = dial else {
            return Err(OpenRefusal::DocumentUnreadable);
        };

        // Open-debt item 913 — the multicast groups among the endpoints, as zenoh's runtime
        // sorts them. A listened group is a multicast transport, in every role
        // (`io/zenoh-transport/src/manager.rs` @ `self.add_listener_multicast(endpoint).await`).
        // A group to dial is refused by a peer or a router, which fails the open
        // (`zenoh/src/net/runtime/orchestrator.rs` @
        // `bail!("Forbidden multicast endpoint in connect list!")`), and a client tries it as a
        // unicast link it never establishes, so it opens only when another endpoint does: a
        // client with nothing else to dial fails the open, and one with something else dials that.
        let (listen, group_endpoints): (Vec<String>, Vec<String>) = listen
            .into_iter()
            .partition(|endpoint| !names_a_group(endpoint));
        let connect = if connect.iter().any(|endpoint| names_a_group(endpoint)) {
            if role != WhatAmI::Client {
                return Err(OpenRefusal::GroupInConnect);
            }
            let dialable: Vec<String> = connect
                .into_iter()
                .filter(|endpoint| !names_a_group(endpoint))
                .collect();
            if dialable.is_empty() {
                return Err(OpenRefusal::NoDialableEndpoint);
            }
            dialable
        } else {
            connect
        };
        // A build without `multicast-transport` is handed the groups all the same, and its open
        // refuses them (`OpenStance::groups`), rather than binding a group as a unicast port.
        let shm = node.as_ref().map_or(
            ShmKeys {
                enabled: false,
                transport_optimization: false,
                pool_size: 0,
            },
            |node| ShmKeys {
                enabled: node.shared_memory,
                transport_optimization: node.shm_transport_optimization,
                pool_size: node.shm_pool_size,
            },
        );
        // The width of the sequence numbers the build advertises (`sn-resolution`); the document
        // has no key for it, since neither zenoh nor zenoh-pico does.
        let sn_resolution = SessionPolicy::from_build().sn_resolution;
        let groups = node.as_ref().map_or_else(Vec::new, |node| {
            let profile = zenoh_group_profile(node, batch_size, sn_resolution);
            // zenoh announces each subscriber on the groups it holds, on every target but
            // Windows, where the announcement is compiled out (`#[cfg(not(windows))]` above
            // `zenoh/src/net/routing/hat/peer/pubsub.rs` @
            // `if we have a multicast group, we use it to propagate subscribers to upstream gateways.`).
            let declarations = if cfg!(windows) {
                GroupDeclarations::None
            } else {
                GroupDeclarations::Subscribers
            };
            group_endpoints
                .into_iter()
                .map(|endpoint| GroupJoin {
                    endpoint,
                    profile,
                    // The calling build decides whether the transports are reported as
                    // shared-memory ones; see `AbiChoices::groups_report_shm`.
                    is_shm: node.shared_memory,
                    declarations,
                })
                .collect()
        });

        Ok(Self {
            role,
            connect,
            listen,
            groups,
            dial,
            listen_phase,
            batch_size,
            lease_ms,
            keep_alive,
            sn_resolution,
            accept,
            link_rx,
            offer,
            shm,
            zid,
            timestamping,
            #[cfg(feature = "scout")]
            scouting,
            gossip,
            auth,
            policy,
            namespace,
            tls,
            read_files,
            ignored,
        })
    }

    /// A description of the plan that holds no secret: what the document decided, one fact per
    /// line, in a form a test can hold as a golden. Credentials and certificate material appear
    /// only as whether they are held.
    pub fn describe(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let mut line = |text: String| {
            out.push_str(&text);
            out.push('\n');
        };
        line(format!("role: {:?}", self.role));
        line(format!("connect: {:?}", self.connect));
        line(format!("listen: {:?}", self.listen));
        let groups: Vec<String> = self
            .groups
            .iter()
            .map(|group| {
                format!(
                    "{} {:?} shm={} {:?}",
                    group.endpoint, group.profile, group.is_shm, group.declarations
                )
            })
            .collect();
        line(format!("groups: {groups:?}"));
        line(format!("dial: {:?}", self.dial));
        line(format!("listen_phase: {:?}", self.listen_phase));
        line(format!("batch_size: {}", self.batch_size));
        line(format!("lease_ms: {}", self.lease_ms));
        line(format!(
            "keep_alive: {} per lease, of the {:?} lease",
            self.keep_alive.per_lease, self.keep_alive.basis
        ));
        line(format!(
            "accept: {}ms, {} pending",
            self.accept.timeout_ms, self.accept.pending
        ));
        line(format!(
            "max_message_size: {}",
            self.link_rx.max_message_size
        ));
        // The three facts of the offer a document decides, and not its `Debug`: a build that carries
        // the shared-memory protocols adds a list of them to the type, and a description that held
        // the list would differ with the features it is built with.
        line(format!(
            "offer: mode={:?} compression={} shm={}",
            self.offer.mode, self.offer.compression, self.offer.shm
        ));
        line(format!("shm: {:?}", self.shm));
        line(format!("zid: {:?}", self.zid));
        line(format!("timestamping: {:?}", self.timestamping));
        #[cfg(feature = "scout")]
        line(format!("scouting: {:?}", self.scouting));
        line(format!("gossip: {:?}", self.gossip));
        line(format!("auth: {}", held(self.auth.is_some())));
        line(format!("policy: {}", held(!self.policy.is_inert())));
        let _ = write!(
            out,
            "tls: root_ca={} listen_certificate={} listen_private_key={}",
            held(self.tls.root_ca_pem.is_some()),
            held(self.tls.listen_cert_pem.is_some()),
            held(self.tls.listen_key_pem.is_some()),
        );
        out
    }

    /// Join the plan with the calling ABI's own choices, giving what this engine's open takes.
    pub fn into_arguments(self, abi: AbiChoices) -> OpenArguments {
        #[allow(unused_mut)]
        let mut offer = self.offer;
        #[cfg(feature = "session-extshm")]
        if abi.offer_shm {
            offer = offer.with_shm(self.shm.enabled);
        }
        #[cfg(not(feature = "session-extshm"))]
        debug_assert!(
            !abi.offer_shm,
            "a build without session-extshm cannot offer shared memory"
        );
        let mut groups = self.groups;
        if !abi.groups_report_shm {
            for group in &mut groups {
                group.is_shm = false;
            }
        }
        OpenArguments {
            connect: self.connect,
            listen: self.listen,
            tls: self.tls,
            role: self.role,
            dial: self.dial,
            stance: OpenStance {
                tx_queue: abi.tx_queue,
                batch_size: self.batch_size,
                lease_ms: self.lease_ms,
                keep_alive: self.keep_alive,
                sn_resolution: self.sn_resolution,
                accept: self.accept,
                link_rx: self.link_rx,
                offer,
                zid: self.zid,
                start_read_task: abi.start_read_task,
                timestamping: self.timestamping,
                shm_clients: abi.shm_clients,
                local_delivery: abi.local_delivery,
                liveliness_to_self: abi.liveliness_to_self,
                #[cfg(feature = "scout")]
                scouting: self.scouting,
                initial_interest: abi.initial_interest,
                gossip: self.gossip,
                listen_phase: self.listen_phase,
                face_drive: abi.face_drive,
                auth: self.auth,
                policy: self.policy,
                namespace: self.namespace,
                groups,
            },
        }
    }
}

/// `held` / `none`, for [`OpenPlan::describe`].
const fn held(present: bool) -> &'static str {
    if present {
        "held"
    } else {
        "none"
    }
}

/// The decisions that belong to the calling ABI and not to the document. They join the plan at
/// [`OpenPlan::into_arguments`], so the plan is one value for every ABI.
pub struct AbiChoices {
    /// The transmit model: zenoh's bounded queue ([`TxQueueConf::default`]) or pico's caller-thread
    /// write ([`TxQueueConf::pico`]).
    pub tx_queue: TxQueueConf,
    /// Whether the session's read task runs from the start.
    pub start_read_task: bool,
    /// Who runs the callbacks of a delivery the session makes to itself.
    pub local_delivery: LocalDeliveryDrain,
    /// Whether the session's liveliness tokens are told to its own liveliness subscribers and
    /// answer its own liveliness gets: zenoh's are, zenoh-pico's are not.
    pub liveliness_to_self: bool,
    /// Whether a face reached as a north-bound peer is ended with the initial interest's Final.
    pub initial_interest: bool,
    /// Where the faces of the session are driven.
    pub face_drive: FaceDrive,
    /// The shared-memory reader the session is opened over.
    pub shm_clients: OpenShmClients,
    /// Whether this build's handshake offer carries shared memory (from [`ShmKeys::enabled`]).
    /// Needs the `session-extshm` feature.
    pub offer_shm: bool,
    /// Whether this build reports its multicast transports as shared-memory ones.
    pub groups_report_shm: bool,
}

/// What this engine's open takes: the arguments of [`open_blocking`], in one value, so a shell
/// can still adjust the stance (the shared-memory protocols) before running it.
pub struct OpenArguments {
    /// The unicast endpoints dialled.
    pub connect: Vec<String>,
    /// The unicast endpoints bound.
    pub listen: Vec<String>,
    /// The certificate material for the `tls/` and `quic/` links.
    pub tls: CapiTlsConfig,
    /// The role the node dials as.
    pub role: WhatAmI,
    /// How the dial keeps trying.
    pub dial: DialPhase,
    /// The rest of the open: what the session offers, holds and does.
    pub stance: OpenStance,
}

impl OpenArguments {
    /// Open the session on this engine: the part of an open that is not a reading.
    pub fn run(self) -> Result<SessionState, OpenError> {
        open_blocking(
            self.connect,
            self.listen,
            self.tls,
            self.role,
            self.dial,
            self.stance,
        )
    }

    /// What the configuration asks of a router node that the node does not carry yet, by name
    /// (`None` when it asks nothing of the kind). A caller that opens the node reports this to
    /// whoever wrote the configuration; [`Self::run_router`] refuses the same asks.
    #[cfg(feature = "router-node")]
    pub fn router_refusal(&self) -> Option<&'static str> {
        crate::drive::router_refused_ask(&self.stance)
    }

    /// Open the node as a router: the router data plane run as a session, which the other roles
    /// are not (see [`crate::drive::RouterState`]). The role the plan resolved is the caller's
    /// to have asked for; what the node does not carry yet fails the open by name.
    #[cfg(feature = "router-node")]
    pub fn run_router(self) -> Result<crate::drive::RouterState, OpenError> {
        crate::drive::open_router_blocking(
            self.connect,
            self.listen,
            self.tls,
            self.dial,
            self.stance,
        )
    }
}

/// A build without the interceptors holds no traffic policy, so a config that states one does not
/// open (see [`node_security_of`]); one that states none does. Run by the lane that builds without
/// the feature, and by nothing else: the default build has the feature.
#[cfg(all(test, not(feature = "interceptors")))]
mod without_interceptors {
    use super::*;

    fn node(document: &str) -> ZenohNodeConfig {
        ZenohNodeConfig::from_json5(document)
            .expect("a document a real zenohd starts on")
            .config
    }

    #[test]
    fn a_config_that_states_a_traffic_policy_fails_the_open() {
        for document in [
            r#"{ low_pass_filter: [ { messages: ["put"], key_exprs: ["a/**"], size_limit: 4 } ] }"#,
            r#"{ access_control: { enabled: true, default_permission: "deny" } }"#,
        ] {
            assert!(node_security_of(&node(document)).is_err(), "{document}");
        }
    }

    #[test]
    fn a_config_that_states_no_policy_opens() {
        assert!(node_security_of(&node(r#"{ mode: "client" }"#)).is_ok());
        // CONTROL: a disabled access control is no policy, as it is in the default build.
        assert!(node_security_of(&node(
            r#"{ access_control: { enabled: false, default_permission: "deny" } }"#
        ))
        .is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node a config document reads as, through the one reader an open uses.
    fn node_of(document: &str) -> ZenohNodeConfig {
        ZenohNodeConfig::from_json5(document)
            .expect("the document is one the reader accepts")
            .config
    }

    /// The plan for `document` as `role`, with `connect` and `listen` stated by the caller.
    fn plan_of(
        role: WhatAmI,
        connect: &[&str],
        listen: &[&str],
        document: &str,
    ) -> Result<OpenPlan, OpenRefusal> {
        let own = |list: &[&str]| list.iter().map(|text| (*text).to_owned()).collect();
        OpenPlan::resolve(
            role,
            StatedEndpoints {
                connect: own(connect),
                listen: own(listen),
            },
            Some(document),
        )
    }

    /// The refusal a document meets, for a document that must be refused.
    fn refusal_of(role: WhatAmI, connect: &[&str], listen: &[&str], document: &str) -> OpenRefusal {
        match plan_of(role, connect, listen, document) {
            Ok(plan) => panic!("{document} opened: {}", plan.describe()),
            Err(refusal) => refusal,
        }
    }

    /// The offer for a config document, read by the one reader an open uses.
    fn offer_for(document: &str) -> Result<SessionOffer, OpenRefusal> {
        session_offer(&node_of(document))
    }

    /// R2970 — an unconfigured session offers QoS, upstream's default, and nothing else: shared
    /// memory is not in this offer, it joins at [`OpenPlan::into_arguments`] on the arm that
    /// carries it.
    #[test]
    fn an_unconfigured_session_offers_qos_and_nothing_else() {
        assert_eq!(
            offer_for("{}"),
            Ok(SessionOffer::universal().with_mode(TransportMode::Qos))
        );
    }

    /// Each unicast key reaches the offer on its own. Compression is the one half the C-level
    /// differential cannot see — no zenoh-c accessor reports it — so its staging is held here.
    #[test]
    fn each_unicast_key_reaches_the_offer() {
        assert_eq!(
            offer_for(r#"{ transport: { unicast: { qos: { enabled: false } } } }"#),
            Ok(SessionOffer::universal())
        );
        assert_eq!(
            offer_for(
                r#"{ transport: { unicast: { qos: { enabled: false }, lowlatency: true } } }"#
            ),
            Ok(SessionOffer::universal().with_mode(TransportMode::LowLatency))
        );
        assert_eq!(
            offer_for(r#"{ transport: { unicast: { compression: { enabled: true } } } }"#),
            Ok(SessionOffer::universal()
                .with_mode(TransportMode::Qos)
                .with_compression(true))
        );
    }

    /// QoS stays on by default, so lowlatency alone is the refused pair — the configuration
    /// upstream's manager refuses when it is built.
    #[test]
    fn lowlatency_with_the_default_qos_is_refused() {
        assert_eq!(
            offer_for(r#"{ transport: { unicast: { lowlatency: true } } }"#),
            Err(OpenRefusal::QosWithLowlatency)
        );
    }

    /// R3052 -- the shared-memory keys reach the plan whatever the arm, and the handshake offer
    /// carries them only where the build says it can: the staging that moved here from the C
    /// shell, whose arm condition is now the caller's [`AbiChoices::offer_shm`].
    #[test]
    fn shared_memory_is_offered_from_the_key_where_the_build_carries_the_axis() {
        let plan = |enabled: bool| {
            plan_of(
                WhatAmI::Client,
                &["tcp/127.0.0.1:7447"],
                &[],
                &format!(r#"{{ transport: {{ shared_memory: {{ enabled: {enabled} }} }} }}"#),
            )
            .expect("a client with an endpoint opens")
        };
        let abi = |offer_shm| AbiChoices {
            tx_queue: TxQueueConf::default(),
            start_read_task: true,
            local_delivery: LocalDeliveryDrain::Caller,
            liveliness_to_self: true,
            initial_interest: true,
            face_drive: FaceDrive::PerFace,
            shm_clients: crate::faces::no_shm_clients(),
            offer_shm,
            groups_report_shm: false,
        };
        assert!(plan(true).shm.enabled, "the reader carries the key");
        assert!(!plan(false).shm.enabled, "and carries it off");
        // An arm without the axis never offers it, whatever the key says.
        assert!(!plan(true).into_arguments(abi(false)).stance.offer.shm);
        #[cfg(feature = "session-extshm")]
        {
            assert!(plan(true).into_arguments(abi(true)).stance.offer.shm);
            assert!(!plan(false).into_arguments(abi(true)).stance.offer.shm);
        }
    }

    /// The lease and the largest rejoined message a document states reach the session's stance,
    /// and a document that states neither gives zenoh's defaults: the stance carried a constant
    /// lease and no receive half before, so both keys were read and dropped.
    #[test]
    fn the_lease_and_the_rejoin_ceiling_a_document_states_reach_the_stance() {
        let stance = |document: &str| {
            plan_of(WhatAmI::Client, &["tcp/127.0.0.1:7447"], &[], document)
                .expect("a client with an endpoint opens")
                .into_arguments(AbiChoices {
                    tx_queue: TxQueueConf::default(),
                    start_read_task: true,
                    local_delivery: LocalDeliveryDrain::Caller,
                    liveliness_to_self: true,
                    initial_interest: true,
                    face_drive: FaceDrive::PerFace,
                    shm_clients: crate::faces::no_shm_clients(),
                    offer_shm: false,
                    groups_report_shm: false,
                })
                .stance
        };
        let stated = stance(
            r#"{ transport: { link: { tx: { lease: 4000, keep_alive: 2 },
                                      rx: { max_message_size: 4096 } },
                              unicast: { accept_timeout: 2500, accept_pending: 7 } } }"#,
        );
        assert_eq!(stated.lease_ms, 4000);
        assert_eq!(stated.keep_alive, KeepAliveConf::zenoh(2));
        assert_eq!(stated.link_rx.max_message_size, 4096);
        assert_eq!(
            stated.accept,
            AcceptBounds {
                timeout_ms: 2500,
                pending: 7
            }
        );
        // Control: the same open with none of the keys is zenoh's defaults, so the numbers above
        // are the document's and not the plan's own.
        let silent = stance("{}");
        assert_eq!(silent.lease_ms, DEFAULT_LEASE_MS);
        assert_eq!(silent.keep_alive, KeepAliveConf::ZENOH);
        assert_eq!(silent.link_rx, LinkRxConf::default());
        assert_eq!(silent.accept, AcceptBounds::default());
    }

    /// The width of the sequence numbers a group's Join states is the `sn-resolution` policy's,
    /// each value its own code, and the request-id resolution is not moved by it: a member of a
    /// group built with another width refuses a Join that states a different one, so the
    /// width has to reach the Join and nothing beside it.
    #[test]
    fn a_groups_join_states_the_width_the_sn_resolution_policy_states() {
        let node = ZenohNodeConfig::default();
        for (width, code) in [
            (SnResolution::Bits32, 0x02),
            (SnResolution::Bits8, 0x00),
            (SnResolution::Bits16, 0x01),
            (SnResolution::Bits64, 0x03),
        ] {
            let profile = zenoh_group_profile(&node, 65535, width);
            assert_eq!(profile.seq_num_res, code, "{}", width.id());
            assert_eq!(profile.req_id_res, 0x02, "the request id is untouched");
        }
    }

    /// The role is read from the `mode` key, and the default is the build's.
    #[test]
    fn the_role_is_the_mode_key_and_otherwise_the_builds_default() {
        assert_eq!(dial_role(Some("client")), WhatAmI::Client);
        assert_eq!(dial_role(Some("router")), WhatAmI::Router);
        assert_eq!(dial_role(Some("peer")), WhatAmI::Peer);
        let default = if cfg!(feature = "peer") {
            WhatAmI::Peer
        } else {
            WhatAmI::Client
        };
        assert_eq!(dial_role(None), default);
        assert_eq!(dial_role(Some("anything else")), default);
    }

    /// A client dials what it is told and binds nothing: it has no default listener, and its
    /// absence is the instruction.
    #[test]
    fn a_client_dials_its_endpoints_and_has_no_default_listener() {
        let plan = plan_of(
            WhatAmI::Client,
            &["tcp/127.0.0.1:7447", "tcp/127.0.0.1:7448"],
            &[],
            r#"{ mode: "client" }"#,
        )
        .expect("a client with endpoints opens");
        assert_eq!(plan.connect, ["tcp/127.0.0.1:7447", "tcp/127.0.0.1:7448"]);
        assert!(plan.listen.is_empty());
        assert!(plan.groups.is_empty());
        assert_eq!(
            plan.dial.policy,
            PhasePolicy::connect_default_for(WhatAmI::Client),
            "a client makes one attempt"
        );
    }

    /// R3071 -- a node of a role that binds on its own does so when the config says nothing about
    /// its listeners; a key the config NAMES, even as an empty list, suppresses the default.
    #[cfg(feature = "peer")]
    #[test]
    fn a_listener_the_config_does_not_state_is_the_roles_default() {
        for role in [WhatAmI::Peer, WhatAmI::Router] {
            let default: Vec<String> = default_listen_endpoint(role)
                .map(str::to_owned)
                .into_iter()
                .collect();
            assert_eq!(default.len(), 1, "{role:?} binds one endpoint on its own");
            let unstated = plan_of(role, &[], &[], "{}").expect("opens alone");
            assert_eq!(unstated.listen, default, "{role:?}");
            let empty =
                plan_of(role, &[], &[], r#"{ listen: { endpoints: [] } }"#).expect("opens alone");
            assert!(
                empty.listen.is_empty(),
                "{role:?}: an empty list is an instruction"
            );
        }
    }

    /// R3076 -- every endpoint the config states, in its order, wherever it is stated: by the
    /// caller's own reading of the keys, or by the document.
    #[cfg(feature = "peer")]
    #[test]
    fn every_stated_listener_is_bound_in_the_order_stated() {
        let by_caller = plan_of(
            WhatAmI::Peer,
            &[],
            &["tcp/127.0.0.1:0", "tcp/127.0.0.1:1"],
            "{}",
        )
        .expect("opens");
        assert_eq!(by_caller.listen, ["tcp/127.0.0.1:0", "tcp/127.0.0.1:1"]);
        let by_document = plan_of(
            WhatAmI::Peer,
            &[],
            &[],
            r#"{ listen: { endpoints: ["tcp/127.0.0.1:2", "tcp/127.0.0.1:3"] } }"#,
        )
        .expect("opens");
        assert_eq!(by_document.listen, ["tcp/127.0.0.1:2", "tcp/127.0.0.1:3"]);
        // The caller's reading wins over the document's.
        let both = plan_of(
            WhatAmI::Peer,
            &[],
            &["tcp/127.0.0.1:4"],
            r#"{ listen: { endpoints: ["tcp/127.0.0.1:5"] } }"#,
        )
        .expect("opens");
        assert_eq!(both.listen, ["tcp/127.0.0.1:4"]);
    }

    /// A key stated as a mode table is the row for the node's role; a table with no row for it
    /// states nothing for it, which suppresses the default as a stated empty list does.
    #[cfg(feature = "peer")]
    #[test]
    fn a_listener_table_without_a_row_for_the_role_binds_nothing() {
        // The document is read for the role it states, as the caller renders it (a caller that
        // states no `mode` has the role's name put in).
        let document = |mode: &str| {
            format!(
                r#"{{ mode: "{mode}", listen: {{ endpoints: {{ router: ["tcp/127.0.0.1:6"] }} }} }}"#
            )
        };
        let peer = plan_of(WhatAmI::Peer, &[], &[], &document("peer")).expect("opens alone");
        assert!(peer.listen.is_empty());
        let router = plan_of(WhatAmI::Router, &[], &[], &document("router")).expect("opens");
        assert_eq!(router.listen, ["tcp/127.0.0.1:6"]);
    }

    /// Open-debt item 913 -- a group in `listen` is a multicast transport and not a unicast
    /// bind, and whether its transports read as shared memory is the build's to say.
    #[cfg(feature = "peer")]
    #[test]
    fn a_listened_group_is_joined_and_not_bound() {
        let group = "udp/224.0.0.224:7446#iface=lo";
        let plan = plan_of(WhatAmI::Peer, &[], &["tcp/127.0.0.1:0", group], "{}").expect("opens");
        assert_eq!(plan.listen, ["tcp/127.0.0.1:0"]);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].endpoint, group);
        assert!(
            plan.groups[0].is_shm,
            "the plan says what the document says: the key defaults on"
        );
        let abi = |groups_report_shm| AbiChoices {
            tx_queue: TxQueueConf::default(),
            start_read_task: true,
            local_delivery: LocalDeliveryDrain::Caller,
            liveliness_to_self: true,
            initial_interest: true,
            face_drive: FaceDrive::PerFace,
            shm_clients: crate::faces::no_shm_clients(),
            offer_shm: false,
            groups_report_shm,
        };
        let plan = |abi| {
            plan_of(WhatAmI::Peer, &[], &[group], "{}")
                .expect("opens")
                .into_arguments(abi)
                .stance
                .groups
        };
        assert!(plan(abi(true))[0].is_shm);
        assert!(!plan(abi(false))[0].is_shm);
    }

    /// Every refusal is reachable from a document, and each names the key it is about.
    #[test]
    fn each_refusal_is_reached_by_its_document_and_names_its_key() {
        let group = "udp/224.0.0.224:7446#iface=lo";
        let off = r#"scouting: { multicast: { enabled: false } }"#;
        let cases: Vec<(OpenRefusal, OpenRefusal)> = vec![
            (
                refusal_of(
                    WhatAmI::Client,
                    &["tcp/127.0.0.1:1"],
                    &[],
                    &format!("{{ {off}, transport: {{ unicast: {{ lowlatency: true }} }} }}"),
                ),
                OpenRefusal::QosWithLowlatency,
            ),
            (
                refusal_of(WhatAmI::Client, &[], &[], &format!("{{ {off} }}")),
                OpenRefusal::NothingToDial,
            ),
            (
                refusal_of(WhatAmI::Client, &[group], &[], &format!("{{ {off} }}")),
                OpenRefusal::NoDialableEndpoint,
            ),
            (
                refusal_of(WhatAmI::Client, &[], &[], "{ this_is_not_a_zenoh_key: 1 }"),
                OpenRefusal::NothingToDial,
            ),
        ];
        for (found, expected) in cases {
            assert_eq!(found, expected);
            assert!(!found.key().is_empty());
        }
    }

    /// A `namespace` is carried out or refused by its key, and never opened without. With the
    /// decorator it reaches the plan as the prefix the document states, and a text that cannot be
    /// a prefix (a wildcard) is refused; without it any `namespace` is refused, so that a session
    /// told to prefix its keys is not run with them unprefixed.
    #[test]
    fn a_namespace_reaches_the_plan_or_is_refused_by_its_key() {
        let off = r#"scouting: { multicast: { enabled: false } }"#;
        let with = |namespace: &str| {
            plan_of(
                WhatAmI::Client,
                &["tcp/127.0.0.1:1"],
                &[],
                &format!("{{ {off}, namespace: {namespace} }}"),
            )
        };
        let none = plan_of(
            WhatAmI::Client,
            &["tcp/127.0.0.1:1"],
            &[],
            &format!("{{ {off} }}"),
        )
        .expect("a document with no namespace opens");
        assert_eq!(none.namespace, None);
        #[cfg(feature = "routing-namespace")]
        {
            let plan = with(r#""demo/ns""#).expect("a plain key expression is a prefix");
            assert_eq!(plan.namespace.as_deref(), Some("demo/ns"));
            assert_eq!(with(r#""demo/*""#).err(), Some(OpenRefusal::Namespace));
        }
        #[cfg(not(feature = "routing-namespace"))]
        assert_eq!(with(r#""demo/ns""#).err(), Some(OpenRefusal::Namespace));
        assert_eq!(OpenRefusal::Namespace.key(), "namespace");
    }

    /// A document the reader refuses is refused AFTER every refusal that needs no document, which
    /// is the order the C ABI has always answered in: a client with nothing to dial reports that,
    /// and the unreadable document only when there was something to dial.
    #[test]
    fn an_unreadable_document_is_reported_after_the_refusals_that_need_none() {
        let unreadable = "{ this_is_not_a_zenoh_key: 1 }";
        assert_eq!(
            refusal_of(WhatAmI::Client, &[], &[], unreadable),
            OpenRefusal::NothingToDial
        );
        assert_eq!(
            refusal_of(WhatAmI::Client, &["tcp/127.0.0.1:1"], &[], unreadable),
            OpenRefusal::DocumentUnreadable
        );
        // No document at all is the same as an unreadable one.
        assert_eq!(
            OpenPlan::resolve(
                WhatAmI::Client,
                StatedEndpoints {
                    connect: vec!["tcp/127.0.0.1:1".to_owned()],
                    listen: Vec::new(),
                },
                None,
            )
            .err(),
            Some(OpenRefusal::DocumentUnreadable)
        );
    }

    /// A peer or a router told to dial a group is refused, and so is a client whose only endpoints
    /// are groups; a client with something else to dial dials that.
    #[test]
    fn a_group_in_the_connect_list_is_refused_by_every_role_but_a_clients() {
        let group = "udp/224.0.0.224:7446#iface=lo";
        let off = r#"{ scouting: { multicast: { enabled: false } } }"#;
        #[cfg(feature = "peer")]
        for role in [WhatAmI::Peer, WhatAmI::Router] {
            assert_eq!(
                refusal_of(role, &[group], &[], off),
                OpenRefusal::GroupInConnect,
                "{role:?}"
            );
        }
        let client = plan_of(WhatAmI::Client, &[group, "tcp/127.0.0.1:1"], &[], off)
            .expect("a client dials what it can");
        assert_eq!(client.connect, ["tcp/127.0.0.1:1"]);
    }

    /// What three documents decide, held whole as goldens: the reading's one observable record.
    /// A field added to the plan, or a default that moves, shows here first, and the change is
    /// then looked at and not just accepted. Only the default build has the capabilities these
    /// lines name, on a target where a group's subscribers are announced.
    #[cfg(all(
        feature = "peer",
        feature = "scout",
        feature = "gossip",
        feature = "timestamping",
        not(windows)
    ))]
    #[test]
    fn what_three_documents_decide_is_held_as_goldens() {
        let described = |role: WhatAmI, connect: &[&str], listen: &[&str], mode: &str| {
            plan_of(role, connect, listen, &format!(r#"{{ mode: "{mode}" }}"#))
                .expect("opens")
                .describe()
        };
        let client = described(WhatAmI::Client, &["tcp/127.0.0.1:7447"], &[], "client");
        let peer = described(WhatAmI::Peer, &[], &[], "peer");
        let router = described(
            WhatAmI::Router,
            &[],
            &["tcp/127.0.0.1:7447", "udp/224.0.0.224:7446#iface=lo"],
            "router",
        );
        const SCHEDULE: &str = "RetryPolicy { period_init_ms: 1000, period_max_ms: 4000, \
                                period_increase_factor: 2.0 }";
        // The lines every document of these three shares, around the ones that differ: the
        // role's own head, its dial budget, the matcher its scouting looks for, and its gossip.
        let golden = |head: &str, budget: &str, exit: bool, matcher: u8, gossip: &str| {
            format!(
                "{head}\n\
                 dial: DialPhase {{ policy: PhasePolicy {{ budget: PhaseBudget({budget}), \
                 exit_on_failure: {exit} }}, schedule: {SCHEDULE}, redial: Some({SCHEDULE}), \
                 start_window: Some(500ms), router_hold: 500ms }}\n\
                 listen_phase: ListenPhase {{ policy: PhasePolicy {{ budget: PhaseBudget(0), \
                 exit_on_failure: true }}, schedule: {SCHEDULE} }}\n\
                 batch_size: 65535\n\
                 lease_ms: 10000\n\
                 keep_alive: 4 per lease, of the Own lease\n\
                 accept: 10000ms, 100 pending\n\
                 max_message_size: 1073741824\n\
                 offer: mode=Qos compression=false shm=false\n\
                 shm: ShmKeys {{ enabled: true, transport_optimization: true, pool_size: 16777216 }}\n\
                 zid: None\n\
                 timestamping: TimestampingEnabled {{ router: true, peer: false, client: false }}\n\
                 scouting: Some(ScoutingPlan {{ group: 224.0.0.224, port: 7446, interface: None, \
                 ttl: None, delay: 500ms, timeout: 3s, matcher: WhatAmIMatcher({matcher}), \
                 strategies: Unique(Always), answers: true }})\n\
                 gossip: {gossip}\n\
                 auth: none\n\
                 policy: none\n\
                 tls: root_ca=none listen_certificate=none listen_private_key=none"
            )
        };
        let gossip = |autoconnect: u8| {
            format!(
                "Some(GossipPolicy {{ target: WhatAmIMatcher(3), \
                 autoconnect: WhatAmIMatcher({autoconnect}), strategies: Unique(Always) }})"
            )
        };
        // A client makes one attempt and does not gossip; it scouts for a router or a peer.
        assert_eq!(
            client,
            golden(
                "role: Client\nconnect: [\"tcp/127.0.0.1:7447\"]\nlisten: []\ngroups: []",
                "0",
                true,
                7,
                "None"
            )
        );
        // A peer retries without bound, binds `tcp/[::]:0` on its own, and meets every role.
        assert_eq!(
            peer,
            golden(
                "role: Peer\nconnect: []\nlisten: [\"tcp/[::]:0\"]\ngroups: []",
                "-1",
                false,
                7,
                &gossip(7)
            )
        );
        // A router meets nobody by scouting, joins the group it is told to listen on, with
        // the beacon zenoh's multicast transport fills, and capped at the multicast batch.
        assert_eq!(
            router,
            golden(
                "role: Router\nconnect: []\nlisten: [\"tcp/127.0.0.1:7447\"]\n\
                 groups: [\"udp/224.0.0.224:7446#iface=lo GroupProfile { lease_ms: 10000, \
                 join_interval_ms: 2500, seq_num_res: 2, req_id_res: 2, batch_size: 8192, \
                 is_qos: false } shm=true Subscribers\"]",
                "-1",
                false,
                0,
                &gossip(0)
            )
        );
    }

    /// Each key is mapped, inert or unmapped, and a key no list knows has no state.
    #[test]
    fn a_key_is_mapped_inert_or_unmapped_and_a_key_nobody_lists_has_none() {
        assert_eq!(key_state("connect/timeout_ms"), Some(KeyState::Mapped));
        assert_eq!(
            key_state("transport/auth/pubkey/key_size"),
            Some(KeyState::Inert)
        );
        assert_eq!(
            key_state("transport/unicast/open_timeout"),
            Some(KeyState::Unmapped)
        );
        // A key the C interface acts on is mapped, whichever list it left.
        assert_eq!(
            key_state("transport/unicast/accept_timeout"),
            Some(KeyState::Mapped)
        );
        assert_eq!(
            key_state("transport/link/tls/root_ca_certificate_base64"),
            Some(KeyState::Unmapped)
        );
        assert_eq!(key_state("a/key/nobody/lists"), None);
        assert!(is_section_of_keys_with_a_state("gateway"));
        assert!(!is_section_of_keys_with_a_state(
            "transport/unicast/open_timeout"
        ));
    }

    /// The plan reports every key the document states that the engine does not act on, and the
    /// keys it acts on are not among them.
    #[test]
    fn the_plan_reports_the_keys_the_document_states_that_the_engine_does_not_act_on() {
        let plan = plan_of(
            WhatAmI::Client,
            &["tcp/127.0.0.1:1"],
            &[],
            r#"{ connect: { timeout_ms: 500 },
                 scouting: { multicast: { enabled: false } },
                 transport: { unicast: { open_timeout: 1234 } } }"#,
        )
        .expect("opens");
        assert_eq!(plan.ignored, ["transport/unicast/open_timeout"]);
    }

    /// A plan's description never holds a credential, so a golden built from it cannot leak one.
    #[cfg(feature = "auth_usrpwd")]
    #[test]
    fn the_description_holds_no_secret() {
        let plan = plan_of(
            WhatAmI::Client,
            &["tcp/127.0.0.1:1"],
            &[],
            r#"{ scouting: { multicast: { enabled: false } },
                 transport: { auth: { usrpwd: { user: "someone", password: "hunter2-never-printed" } } } }"#,
        )
        .expect("a user with a password opens");
        let text = plan.describe();
        assert!(text.contains("auth: held"), "{text}");
        assert!(!text.contains("hunter2-never-printed"), "{text}");
        assert!(!text.contains("someone"), "{text}");
    }

    /// The node a config document reads as, through the one reader `z_open` uses.
    #[cfg(any(feature = "transport_tls", feature = "transport_quic"))]
    fn tls_document(key: &str, path: &std::path::Path) -> String {
        format!(
            "{{ transport: {{ link: {{ tls: {{ {key}: {:?} }} }} }} }}",
            path.to_str().expect("a utf-8 path")
        )
    }

    /// A temp file holding `text`.
    #[cfg(any(feature = "transport_tls", feature = "transport_quic"))]
    fn file_of(text: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().expect("a temp file");
        file.write_all(text.as_bytes()).expect("write");
        file
    }

    /// A config that names no certificate gives the cert-free material, with the name check on.
    #[cfg(any(feature = "transport_tls", feature = "transport_quic"))]
    #[test]
    fn a_config_that_names_no_certificate_reads_none() {
        let tls = tls_of(&node_of("{}")).expect("nothing to read");
        assert!(tls.root_ca_pem.is_none());
        assert!(tls.listen_cert_pem.is_none());
        assert!(tls.listen_key_pem.is_none());
        assert!(
            tls.verify_name_on_connect,
            "upstream checks the name by default"
        );
        assert!(tls.connect_cert_pem.is_none() && tls.connect_key_pem.is_none());
        assert!(!tls.require_client_auth);
    }

    /// Each of the three keys reaches its own slot, read from the file it names.
    #[cfg(any(feature = "transport_tls", feature = "transport_quic"))]
    #[test]
    fn each_tls_key_is_read_from_the_file_it_names() {
        let file = file_of("PEM TEXT");
        for key in [
            "root_ca_certificate",
            "listen_certificate",
            "listen_private_key",
        ] {
            let tls = tls_of(&node_of(&tls_document(key, file.path()))).expect("a readable file");
            let slots = [
                ("root_ca_certificate", tls.root_ca_pem),
                ("listen_certificate", tls.listen_cert_pem),
                ("listen_private_key", tls.listen_key_pem),
            ];
            for (slot, value) in slots {
                if slot == key {
                    assert_eq!(value.as_deref(), Some(&b"PEM TEXT"[..]), "{key}");
                } else {
                    assert!(value.is_none(), "{key} filled the {slot} slot too");
                }
            }
        }
    }

    /// A path that cannot be read is an error, which fails the open.
    #[cfg(any(feature = "transport_tls", feature = "transport_quic"))]
    #[test]
    fn a_certificate_path_that_cannot_be_read_is_refused() {
        let missing = std::path::Path::new("/nonexistent/wz-tls-ca.pem");
        assert!(tls_of(&node_of(&tls_document("root_ca_certificate", missing))).is_err());
        let empty = file_of("");
        assert!(tls_of(&node_of(&tls_document("listen_certificate", empty.path()))).is_err());
        // And the open names it.
        assert_eq!(
            refusal_of(
                WhatAmI::Client,
                &["tcp/127.0.0.1:1"],
                &[],
                &tls_document("root_ca_certificate", missing)
            ),
            OpenRefusal::TlsMaterial
        );
    }

    /// A config naming a pubkey file pair that cannot be loaded is refused: by the loader in a
    /// build that holds the identity, and by the key alone in one that cannot.
    #[test]
    fn a_pubkey_identity_that_cannot_be_held_is_refused() {
        let node = node_of(
            r#"{ transport: { auth: { pubkey: {
                public_key_file: "/nonexistent/wz-pub.pem",
                private_key_file: "/nonexistent/wz-priv.pem" } } } }"#,
        );
        assert_eq!(node_security_of(&node).err(), Some(OpenRefusal::Security));
    }

    /// A config that names no pubkey key builds no authentication from it.
    #[test]
    fn a_config_without_pubkey_keys_builds_no_authentication() {
        let (auth, _policy) = node_security_of(&node_of("{}")).expect("nothing to refuse");
        assert!(auth.is_none());
    }

    /// A loadable identity is held, in a build that has the method.
    #[cfg(feature = "auth_pubkey")]
    #[test]
    fn a_loadable_pubkey_identity_is_held() {
        use wz_runtime_tokio::extauth_pubkey::generate_keypair;
        use wz_runtime_tokio::rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
        use wz_runtime_tokio::rsa::RsaPublicKey;

        let private = generate_keypair(512).expect("a 512-bit test key");
        let public = RsaPublicKey::from(&private)
            .to_pkcs1_pem(LineEnding::LF)
            .expect("public PEM");
        let private = private
            .to_pkcs1_pem(LineEnding::LF)
            .expect("private PEM")
            .to_string();
        let node = node_of(&format!(
            "{{ transport: {{ auth: {{ pubkey: {{ public_key_pem: {public:?}, \
             private_key_pem: {private:?} }} }} }} }}"
        ));
        let (auth, _policy) = node_security_of(&node).expect("a loadable identity");
        let auth = auth.expect("the identity is held");
        assert!(auth.dial_dispatch().is_some(), "the node presents its key");
        assert!(
            auth.accept_dispatch().is_some(),
            "and asks one of its peers"
        );
    }
}
