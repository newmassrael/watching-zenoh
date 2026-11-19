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
    config_key_in_build, default_listen_endpoint, honours_config_key, ConfigIngestError,
    ShmInitMode, ZenohConfigIngest, ZenohNodeConfig, UNHONOURED_READER_GAP,
    UNHONOURED_UPSTREAM_CONFIG_KEYS, UPSTREAM_INERT_CONFIG_KEYS, WZ_EXTENSION_CONFIG_KEYS,
};
#[cfg(feature = "routing-namespace")]
use wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr;
use wz_session_core::region_partition::SouthPartition;

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
use crate::session_defaults::{
    PromotedMessages, PublicationDefaults, PublicationQos, SessionDefaults, ShmInit, ShmPromotion,
};
use wz_runtime_tokio::declaration_aggregation::DeclarationAggregation;

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

/// What a session applies itself of the keys only a session applies
/// ([`SESSION_HONOURED_KEYS`](wz_runtime_tokio::zenoh_config::SESSION_HONOURED_KEYS)), which the
/// reader of the engine cannot know: it is the build of the
/// session's own crate that says whether it has shared memory and a provider to copy into. Each
/// client of the engine states its own, so that [`key_state`] answers for the session asking and
/// not for the best build of wz.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionReach {
    /// The session gives its publications the QoS `qos/publication` names for their keys.
    pub publication_qos: bool,
    /// The session's build has shared memory. Upstream's built without it reads the three
    /// shared-memory keys and does nothing with them, so they are inert in such a build.
    pub shared_memory: bool,
    /// The messages whose large payload the session copies into its provider.
    pub promotion: PromotedMessages,
}

/// The state of the key `path` (`transport/link/tx/threads`) for a session that reaches `reach`,
/// or `None` for a key no list of the runtime's reader knows: one a bump of the pinned upstream
/// added, which has no state until it is given one, and which a test over the default
/// configuration fails on until then.
pub fn key_state(path: &str, reach: SessionReach) -> Option<KeyState> {
    if let Some(state) = session_key_state(path, reach) {
        return Some(state);
    }
    if NODE_KEYS_THE_ENGINE_DOES_NOT_ACT_ON.contains(&path) {
        Some(KeyState::Unmapped)
    } else if honours_config_key(path) {
        // A key whose reader is a capability this build was made without is acted on by a build
        // with it, and not by this one.
        Some(if config_key_in_build(path) {
            KeyState::Mapped
        } else {
            KeyState::Unmapped
        })
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

/// Keys the runtime's reader honours for a wz NODE whose effect lives in a part of that node this
/// engine does not have: the plugin plane of the storage host searches
/// `plugins_loading/search_dirs`, and the node's stats registry hands `stats/filters` to the
/// sessions it counts, which this engine does not install. Stating one here asks for something
/// that will not happen, so it is [`KeyState::Unmapped`] and reported among [`OpenPlan::ignored`]
/// although the reader read it.
///
/// `aggregation/*` is not here: the registry of faces gives every session it holds the
/// aggregates ([`SessionDefaults::aggregation`]), and an open that runs as a node, which does not
/// carry them, is refused by name (`OpenArguments::router_refusal`).
pub const NODE_KEYS_THE_ENGINE_DOES_NOT_ACT_ON: &[&str] =
    &["plugins_loading/search_dirs", "stats/filters"];

/// The state of `path` for a session that reaches `reach` when it is a key only a session applies
/// ([`SESSION_HONOURED_KEYS`](wz_runtime_tokio::zenoh_config::SESSION_HONOURED_KEYS)), and `None`
/// for any other key.
///
/// A shared-memory key the session does not act on is [`KeyState::Inert`] in a build without
/// shared memory, as upstream's built so ignores it, and [`KeyState::Unmapped`] in one with it,
/// where upstream acts on it. `messages` is acted on only by a session that copies every kind of
/// message it can name: one that copies some kinds and not others would leave a kind the
/// document names uncopied.
pub fn session_key_state(path: &str, reach: SessionReach) -> Option<KeyState> {
    let acted_on = match path {
        "qos/publication" => {
            return Some(if reach.publication_qos {
                KeyState::Mapped
            } else {
                KeyState::Unmapped
            })
        }
        // The subsystem is made by this engine's open, which has it in a build with the
        // shared-memory transport.
        "transport/shared_memory/mode" => cfg!(feature = "transport-shm") && reach.shared_memory,
        "transport/shared_memory/transport_optimization/message_size_threshold" => {
            reach.promotion.any()
        }
        "transport/shared_memory/transport_optimization/messages" => reach.promotion.all(),
        _ => return None,
    };
    Some(if acted_on {
        KeyState::Mapped
    } else if reach.shared_memory {
        KeyState::Unmapped
    } else {
        KeyState::Inert
    })
}

/// What a session applies itself above its links (`SESSION_HONOURED_KEYS` and `aggregation/*`),
/// compiled from the reading of its document: the one place the C ABI and the Rust API take it
/// from, carried into the session by [`OpenPlan::into_arguments`].
///
/// An aggregate that is not a key expression, or one stated in a build without the inclusion test
/// that applies it, is [`OpenRefusal::Aggregation`]. The reader refuses both first, so only a
/// reading built by hand reaches it; a session that declared each entity as its own key instead
/// would put on the wire what it was told not to.
pub fn session_defaults_of(node: &ZenohNodeConfig) -> Result<SessionDefaults, OpenRefusal> {
    let aggregation = DeclarationAggregation::new(
        node.aggregation_subscribers.clone(),
        node.aggregation_publishers.clone(),
    )
    .map_err(|_| OpenRefusal::Aggregation)?;
    let publication_qos = PublicationQos::new(node.publication_qos.iter().map(|item| {
        let conf = item.config;
        (
            item.key_exprs.clone(),
            PublicationDefaults {
                congestion_control: conf.congestion_control,
                priority: conf.priority,
                express: conf.express,
                reliability: conf
                    .reliable
                    .map(wz_runtime_tokio::Reliability::from_reliable_bool),
                allowed_destination: conf.allowed_destination,
            },
        )
    }));
    let listed = |message: &str| {
        node.shm_optimised_messages
            .iter()
            .any(|named| named == message)
    };
    Ok(SessionDefaults {
        publication_qos,
        shm_init: match node.shm_init_mode {
            ShmInitMode::Lazy => ShmInit::Lazy,
            ShmInitMode::Init => ShmInit::Init,
        },
        shm_promotion: ShmPromotion {
            threshold: usize::try_from(node.shm_message_size_threshold).unwrap_or(usize::MAX),
            messages: PromotedMessages {
                put: listed("put"),
                query: listed("query"),
                reply: listed("reply"),
            },
        },
        aggregation,
    })
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
    /// A certificate or key file `transport/link/tls` names cannot be read, or the document
    /// states `transport/link/tls` in a build with neither a `tls/` nor a `quic/` link.
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
    /// The document enables `transport/multicast/compression/enabled` for a node that joins a
    /// group, in a build without `transport_compression`. A group whose other members compress
    /// reads this node's uncompressed datagrams as noise, and the reverse; there is no handshake
    /// to settle it, so the open does not run as the uncompressed member it was not asked to be.
    MulticastCompressionNotInBuild,
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
    /// An endpoint to listen on or dial names a protocol that `transport/link/protocols` leaves
    /// out. Upstream's transport manager refuses it when it makes the link manager
    /// (`Unsupported protocol: {}. Supported protocols are: {:?}`); an open that listened on it
    /// anyway would be a node that ignores the whitelist it was given.
    UnsupportedProtocol,
    /// The document states a `namespace` the open cannot carry out: it is not a key expression a
    /// prefix can be (it holds a wildcard, or is empty), or the build has no `routing-namespace`.
    /// A session told to prefix every key it publishes that opens and does not is worse than one
    /// that does not open: its keys leave unprefixed and nothing says so.
    Namespace,
    /// The document keeps a south apart (`gateway/south` names subregions) and the open has no node
    /// to carry that out: the engine places a remote in a region only where it runs as a node
    /// ([`OpenPlan::refuse_uncarried_south`] says which opens do). Upstream gives every such node
    /// its regions whatever links it holds; an open that accepted the key and ran as the registry
    /// of faces would hold a south it never partitions, and nothing would say so.
    GatewayNotCarried,
    /// The document configures a part of the links this build does not have: the FIFO mode of
    /// `transport/link/unixpipe` in a build without a `unixpipe/` link, or the per-link RX pool
    /// of `transport/link/rx/buffer_size` in a build whose links read into the node's shared
    /// table. Told how to make a link in a way it has no means of, the open refuses rather than
    /// accept an instruction it could only drop.
    LinkNotInBuild,
    /// The document turns on `plugins_loading/enabled`, the by-name lookup of plugins, in a
    /// build with no plugin host to look one up in. A node told to load the plugins its
    /// section names that opens and loads none would be doing less than it was told.
    PluginHostNotInBuild,
    /// An aggregate of `aggregation/subscribers` or `aggregation/publishers` is not a key
    /// expression, or the build has no inclusion test to tell which entities an aggregate holds.
    Aggregation,
    /// The document lists `stats/filters` in a build without `transport-stats`, which keeps no
    /// counter to count a payload under a filter in.
    StatsNotInBuild,
    /// The document's `wz` member is refused
    /// ([`ConfigIngestError::PoliciesRefused`], whose text names each refusal): a policy, a value
    /// or a profile the build does not have, a value its domain leaves out, a member of `wz` it
    /// does not read. Reported before every refusal that reads the rest of the document, as the
    /// reader refuses the whole document: a session is never opened on part of the policies it
    /// was given, nor on the build defaults in their place.
    Policies,
}

impl OpenRefusal {
    /// The configuration key or keys the refusal is about, as a zenoh user writes them.
    pub const fn key(self) -> &'static str {
        match self {
            Self::DocumentUnreadable => "(the configuration document)",
            Self::Security => {
                "transport/auth, access_control, low_pass_filter, downsampling, qos/network"
            }
            Self::TlsMaterial => "transport/link/tls",
            Self::ZenohId => "id",
            Self::QosWithLowlatency => "transport/unicast/qos, transport/unicast/lowlatency",
            Self::Scouting => "scouting/multicast",
            Self::RoleNotInBuild => "mode, listen/endpoints",
            Self::TimestampingNotInBuild => "timestamping/enabled",
            Self::MulticastCompressionNotInBuild => "transport/multicast/compression/enabled",
            Self::GossipTarget => "scouting/gossip/target",
            Self::UnsupportedProtocol => "transport/link/protocols",
            Self::NothingToDial => "connect/endpoints, scouting/multicast/enabled",
            Self::GroupInConnect | Self::NoDialableEndpoint => "connect/endpoints",
            Self::Namespace => "namespace",
            Self::GatewayNotCarried => "gateway/south",
            Self::LinkNotInBuild => "transport/link/unixpipe, transport/link/rx/buffer_size",
            Self::PluginHostNotInBuild => "plugins_loading/enabled",
            Self::Aggregation => "aggregation/subscribers, aggregation/publishers",
            Self::StatsNotInBuild => "stats/filters",
            Self::Policies => "wz/profile, wz/policies",
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
        // `open/return_conditions/declares`, which a peer's open honours as it does
        // `connect_scouted`: it waits for the initial declarations of the peers it met.
        // Upstream's default is true.
        wait_declares: node.open_declares.unwrap_or(true),
        // `transport/unicast/open_timeout`, upstream's ten seconds unless the document states
        // another.
        open_timeout: std::time::Duration::from_millis(node.open_timeout_ms),
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
    let offer = SessionOffer::universal()
        .with_mode(mode)
        .with_compression(node.compression);
    // The region the node names itself, announced by each of its sessions. The reader checked
    // the name, so one that does not convert is a config built by hand, and its document is
    // unreadable as the reader's would have been.
    match node
        .region_name
        .as_deref()
        .map(wz_session_core::extregion::RegionName::new)
    {
        None => Ok(offer),
        Some(Ok(name)) => Ok(offer.with_region(&name)),
        Some(Err(_)) => Err(OpenRefusal::DocumentUnreadable),
    }
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
/// request ids (32 bits; `transport/link/tx/sequence_number_resolution`, or the build's
/// `sn-resolution` policy, states another width of the sequence number), the session's batch size held to the multicast cap (the UDP link's own
/// MTU is above it on every target zenoh names), per-priority conduits when
/// `transport/multicast/qos/enabled` asks for them, and batch compression when
/// `transport/multicast/compression/enabled` does. Beside the beacon, the cap on the group's
/// members of `transport/multicast/max_sessions`, which zenoh's multicast manager holds every
/// group to (`io/zenoh-transport/src/multicast/manager.rs` @
/// `self = self.max_sessions(config.transport().multicast().max_sessions().unwrap());`).
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
        // zenoh holds every group to its multicast manager's cap, 1000 unless the document
        // states another, so a zenoh session always has one.
        max_sessions: Some(node.multicast_max_sessions),
        seq_num_res: sn_resolution.wire_code(),
        req_id_res: BITS_32,
        batch_size: batch_size.min(ZENOH_MULTICAST_BATCH),
        is_qos: node.multicast_qos,
        compression: node.multicast_compression,
        // A document of zenoh's configuration is read for the zenoh presets, whose group follows
        // zenoh's rule.
        join_rule: wz_session_core::multicast_params::GroupJoinRule::Zenoh,
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
///   * `access_control`, `low_pass_filter`, `downsampling` and `qos/network` are compiled into the
///     node's traffic policy and enforced on every face in both directions; a subtree the compiler
///     refuses (a policy naming a rule that does not exist) fails the open, as zenoh's start
///     does. A disabled `access_control` and an absent filter state no policy at all. A build
///     without `interceptors` cannot hold a policy, so there a config that enables
///     `access_control` or states a filter, a downsampling rule or a QoS overwrite fails the open.
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
            || !node.qos_network.is_empty()
            || node.access_control.enabled
        {
            return Err(OpenRefusal::Security);
        }
        NodePolicy::default()
    };
    Ok((auth, policy))
}

/// The refusal of a document that states an instruction to `path`, a key whose reader the runtime
/// was built without ([`ConfigIngestError::NotInBuild`]): the refusal a build that read the key and
/// could not hold its mechanism gives, so the open answers the same code whichever half is missing.
/// The traffic policy's keys are [`OpenRefusal::Security`], as [`node_security_of`] refuses them;
/// the certificate material of a build with no `tls/` or `quic/` link is
/// [`OpenRefusal::TlsMaterial`]; a south kept apart in a build with no region hat is
/// [`OpenRefusal::GatewayNotCarried`], as [`OpenPlan::refuse_uncarried_south`] refuses it; the
/// configuration of a part of the links the build does not have is
/// [`OpenRefusal::LinkNotInBuild`]; an aggregate in a build with no inclusion test is
/// [`OpenRefusal::Aggregation`], as [`session_defaults_of`] refuses it; a statistics filter in a
/// build with no counters is [`OpenRefusal::StatsNotInBuild`].
fn refusal_of_unbuilt_key(path: &str) -> OpenRefusal {
    match path {
        "low_pass_filter" | "downsampling" | "qos/network" => OpenRefusal::Security,
        _ if path.starts_with("access_control/") => OpenRefusal::Security,
        _ if path.starts_with("transport/link/tls/") => OpenRefusal::TlsMaterial,
        _ if path.starts_with("transport/link/unixpipe/") => OpenRefusal::LinkNotInBuild,
        "transport/link/rx/buffer_size" => OpenRefusal::LinkNotInBuild,
        "plugins_loading/enabled" => OpenRefusal::PluginHostNotInBuild,
        "gateway/south" => OpenRefusal::GatewayNotCarried,
        "aggregation/subscribers" | "aggregation/publishers" => OpenRefusal::Aggregation,
        "stats/filters" => OpenRefusal::StatsNotInBuild,
        _ => OpenRefusal::DocumentUnreadable,
    }
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
/// `verify_name_on_connect` is left unstated, and `false` turns that check off. A dial presents
/// the client certificate `connect_certificate` and its key `connect_private_key`, when it has
/// both, and a listener with `enable_mtls` asks every peer for one and verifies it against the root
/// certificate.
#[cfg(any(feature = "transport_tls", feature = "transport_quic"))]
fn tls_of(node: &ZenohNodeConfig) -> std::io::Result<CapiTlsConfig> {
    use wz_runtime_tokio::tls_config::read_pem_file;
    let read = |path: Option<&String>| path.map(read_pem_file).transpose();
    Ok(CapiTlsConfig {
        root_ca_pem: read(node.tls_root_ca.as_ref())?,
        verify_name_on_connect: node.tls_verify_name_on_connect.unwrap_or(true),
        connect_cert_pem: read(node.tls_connect_certificate.as_ref())?,
        connect_key_pem: read(node.tls_connect_private_key.as_ref())?,
        listen_cert_pem: read(node.tls_listen_certificate.as_ref())?,
        listen_key_pem: read(node.tls_listen_private_key.as_ref())?,
        require_client_auth: node.tls_enable_mtls.unwrap_or(false),
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
            &node.tls_connect_certificate,
            &node.tls_connect_private_key,
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

/// The keys of `transport/link/tx/queue` a document states with a value other than upstream's
/// default, which the open lays over the transmit model its ABI chose
/// ([`AbiChoices::tx_queue`]). A key at upstream's default is no instruction: a document
/// rendered from a whole configuration states every key at its default, and the model then
/// stands as the ABI chose it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatedTxQueue {
    /// `batching/enabled`.
    pub batching: Option<bool>,
    /// `batching/time_limit`, in microseconds.
    pub batching_time_limit_us: Option<u64>,
    /// `allocation/mode`.
    pub allocation: Option<wz_session_core::link::QueueAllocation>,
}

impl StatedTxQueue {
    /// What `node` states away from upstream's defaults.
    fn of(node: &ZenohNodeConfig) -> Self {
        let upstream = ZenohNodeConfig::default().tx_queue;
        let stated = node.tx_queue;
        Self {
            batching: (stated.batching != upstream.batching).then_some(stated.batching),
            batching_time_limit_us: (stated.batching_time_limit_us
                != upstream.batching_time_limit_us)
                .then_some(stated.batching_time_limit_us),
            allocation: (stated.allocation != upstream.allocation).then_some(stated.allocation),
        }
    }

    /// `model` with each stated key laid over it.
    fn over(self, mut model: TxQueueConf) -> TxQueueConf {
        if let Some(batching) = self.batching {
            model.batching = batching;
        }
        if let Some(limit_us) = self.batching_time_limit_us {
            model.batching_time_limit_us = limit_us;
        }
        if let Some(allocation) = self.allocation {
            model.allocation = allocation;
        }
        model
    }
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
    /// `transport/link/tx/sequence_number_resolution` when the document states a width other than
    /// upstream's 32 bits, and the build's `sn-resolution` policy, 32 bits unless it states
    /// another, when it does not.
    pub sn_resolution: SnResolution,
    /// How long an inbound link gets to complete its handshake and how many get it at once:
    /// `transport/unicast/accept_timeout` and `accept_pending`. A config that states none is
    /// upstream's ten seconds and a hundred.
    pub accept: AcceptBounds,
    /// What the session's links rejoin from fragments: `transport/link/rx/max_message_size`. A
    /// config that states none is zenoh's default.
    pub link_rx: LinkRxConf,
    /// The transmit-queue keys the document states away from upstream's defaults, laid over the
    /// ABI's transmit model when the plan becomes the open's arguments.
    pub tx_queue: StatedTxQueue,
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
    /// How the node keeps its south apart: the subregions of `gateway/south`, or the preset that
    /// places a remote by its role alone. Carried out by a node that forwards between its faces
    /// (`OpenArguments::run_node`, which the `router-node` build has); the registry of faces has
    /// no south to partition.
    pub gateway_south: SouthPartition,
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
    /// What the session applies itself above its links ([`session_defaults_of`]), which the open
    /// carries into the session for every ABI that publishes through it to read.
    pub session: SessionDefaults,
    /// The snapshot of the policies the open resolved ([`resolve_policy`]), handed to every
    /// machine the open makes: the sessions of the registry or the node, their links and their
    /// faces. A machine reads a policy here and never from the build.
    pub session_policy: SessionPolicy,
}

/// The policies an open from `node` (the document the open read, or `None` when it read none)
/// runs under: the one place the open of an [`OpenPlan`] decides them. The snapshot the
/// document's `wz` member resolved to when the reader read it ([`ZenohNodeConfig::policies`]),
/// which is the build defaults for a document with no such member; the build defaults when no
/// document was read. A member the reader refused never reaches here: the open is refused with
/// [`OpenRefusal::Policies`].
pub fn resolve_policy(node: Option<&ZenohNodeConfig>) -> SessionPolicy {
    match node {
        Some(node) => node.policies.policy,
        None => SessionPolicy::defaults(),
    }
}

impl OpenPlan {
    /// Whether a peer opened with this plan can run as a forwarding node
    /// ([`OpenArguments::run_node`] with [`NodeRole::Peer`](crate::drive::NodeRole::Peer)): it
    /// accepts sessions, which is what makes it a node others route through, and asks nothing
    /// of the node that it does not carry (a multicast group, a listener that is bound after the
    /// open). A peer that scouts and keeps its south apart (`gateway/south` names subregions) is a
    /// node too: it is the gateway of the nodes that find it, and the node carries the scouting
    /// that dials what it finds ([`OpenArguments::run_node`]). So is one that accepts no session
    /// and keeps its south apart, which dials the remotes it places in it. A peer that scouts and
    /// keeps no south apart fits no node, and is the registry of faces the other roles are, which
    /// does not forward between its faces.
    #[cfg(feature = "router-node")]
    pub fn peer_fits_node(&self) -> bool {
        #[cfg(feature = "scout")]
        let scouts = self.scouting.as_ref().is_some_and(|plan| plan.scouts());
        #[cfg(not(feature = "scout"))]
        let scouts = false;
        let a_gateway = matches!(self.gateway_south, SouthPartition::Custom(_));
        // A peer that keeps a south apart is a node whether or not it accepts a session: the
        // remotes it dials are placed by the partition as the ones that dial it are, so it has a
        // south to keep apart on the links it opens itself. A peer that keeps none is a node
        // only as the node others route through, which is one that accepts sessions.
        //
        // A listener that cannot be bound is a failed open here; one that is bound later, when
        // `listen/exit_on_failure` is off, is the registry's to serve.
        (!self.listen.is_empty() || a_gateway)
            && self.groups.is_empty()
            && (!scouts || a_gateway)
            && self.listen_phase.policy.exit_on_failure
    }

    /// Whether a client opened with this plan can run as a forwarding node
    /// ([`OpenArguments::run_node`] with [`NodeRole::Client`](crate::drive::NodeRole::Client)):
    /// it keeps a south apart (`gateway/south` names subregions) and is told where its router is,
    /// so that it scouts for no one. It is the gateway of the nodes that find it when it accepts
    /// sessions, and when it accepts none it dials the remotes it places in its south, as the peer
    /// that keeps a south does ([`Self::peer_fits_node`]). A client that fits no node is the
    /// registry of faces, which has no south to keep apart.
    #[cfg(feature = "router-node")]
    pub fn client_fits_node(&self) -> bool {
        !self.connect.is_empty()
            && self.groups.is_empty()
            && matches!(self.gateway_south, SouthPartition::Custom(_))
            && self.listen_phase.policy.exit_on_failure
    }

    /// The node `role` is opened as when this plan keeps its south apart (`gateway/south` names
    /// subregions), which only a node places a remote by: a router always, a peer or a client
    /// where [`Self::peer_fits_node`] or [`Self::client_fits_node`] say so. `None` for a plan that
    /// keeps no south apart, which every surface opens as it opened it before, and for a shape
    /// that fits no node.
    #[cfg(feature = "router-node")]
    pub fn node_for_south(&self, role: WhatAmI) -> Option<crate::drive::NodeRole> {
        use crate::drive::NodeRole;
        if !matches!(self.gateway_south, SouthPartition::Custom(_)) {
            return None;
        }
        match role {
            WhatAmI::Router => Some(NodeRole::Router),
            WhatAmI::Peer => self.peer_fits_node().then_some(NodeRole::Peer),
            WhatAmI::Client => self.client_fits_node().then_some(NodeRole::Client),
        }
    }

    /// The node `role` is opened as by a surface that opens every router as one: a router is the
    /// router data plane whatever it holds (a router that forwards nothing is not what
    /// `mode: "router"` asks for), and a peer or a client is one where it keeps a south apart
    /// ([`Self::node_for_south`]).
    #[cfg(feature = "router-node")]
    pub fn node_role(&self, role: WhatAmI) -> Option<crate::drive::NodeRole> {
        match role {
            WhatAmI::Router => Some(crate::drive::NodeRole::Router),
            WhatAmI::Peer | WhatAmI::Client => self.node_for_south(role),
        }
    }

    /// Whether the south this plan keeps apart is carried out when `role` is opened by a caller
    /// that can run a node (`can_run_a_node`) or one that cannot.
    ///
    /// The preset places a remote by its role alone, which every open does. Subregions are a
    /// partition only a node holds (`gateway/south`, [`Self::gateway_south`]): a router is always
    /// one, a peer or a client is one where `peer_fits_node` or `client_fits_node` (both of a
    /// `router-node` build, so not links here) say so, and a build without `router-node` has none. The one place that decides this, for
    /// every surface that opens a plan.
    pub fn carries_south(&self, role: WhatAmI, can_run_a_node: bool) -> bool {
        if !matches!(self.gateway_south, SouthPartition::Custom(_)) {
            return true;
        }
        #[cfg(feature = "router-node")]
        {
            can_run_a_node && self.node_for_south(role).is_some()
        }
        #[cfg(not(feature = "router-node"))]
        {
            let _ = (role, can_run_a_node);
            false
        }
    }

    /// Refuse a plan whose south is not carried out ([`Self::carries_south`]), by the key's name:
    /// stating subregions that nothing places a remote by is not the default the key has, and the
    /// open does not run as if it had not been stated.
    pub fn refuse_uncarried_south(
        &self,
        role: WhatAmI,
        can_run_a_node: bool,
    ) -> Result<(), OpenRefusal> {
        if self.carries_south(role, can_run_a_node) {
            Ok(())
        } else {
            Err(OpenRefusal::GatewayNotCarried)
        }
    }

    /// Read the document for the role `role` (see [`dial_role`]) and the endpoints the caller
    /// stated, and refuse what the open cannot carry out.
    ///
    /// `document` is the document as nested json5 with the role's `mode` stated, or `None` when
    /// the caller could not render one; a document the reader refuses is the same as none, and is
    /// reported as [`OpenRefusal::DocumentUnreadable`] after every refusal that needs no document.
    ///
    /// The policies the plan runs under are [`resolve_policy`]'s; a caller that has resolved its
    /// own snapshot opens with [`Self::resolve_under`].
    pub fn resolve(
        role: WhatAmI,
        stated: StatedEndpoints,
        document: Option<&str>,
    ) -> Result<Self, OpenRefusal> {
        Self::resolve_under(role, stated, document, resolve_policy)
    }

    /// [`Self::resolve`], with the policies the plan runs under made by `policy_of` from the
    /// document the reader parsed (`None` when it parsed none).
    pub fn resolve_under(
        role: WhatAmI,
        stated: StatedEndpoints,
        document: Option<&str>,
        policy_of: impl FnOnce(Option<&ZenohNodeConfig>) -> SessionPolicy,
    ) -> Result<Self, OpenRefusal> {
        let ingest = match document.map(ZenohNodeConfig::from_json5) {
            Some(Ok(ingest)) => Some(ingest),
            // An instruction to a key whose reader this build was made without: refused for what
            // it asks, where a build with the reader and not the mechanism refuses it.
            Some(Err(ConfigIngestError::NotInBuild { path, .. })) => {
                return Err(refusal_of_unbuilt_key(path))
            }
            // The policies the document states for the session, refused: what the session would
            // run under is not known, so nothing else about the open is decided.
            Some(Err(ConfigIngestError::PoliciesRefused { .. })) => {
                return Err(OpenRefusal::Policies)
            }
            Some(Err(_)) | None => None,
        };
        let StatedEndpoints { connect, listen } = stated;
        let listen = listen_endpoints(listen, ingest.as_ref(), role);
        let timestamping = ingest.as_ref().map_or_else(
            TimestampingEnabled::default,
            ZenohConfigIngest::timestamping_enabled,
        );
        let ignored = ingest.as_ref().map_or_else(Vec::new, |ingest| {
            let mut ignored = ingest.ignored.clone();
            ignored.extend(
                ingest
                    .named
                    .iter()
                    .filter(|key| NODE_KEYS_THE_ENGINE_DOES_NOT_ACT_ON.contains(key))
                    .map(|key| String::from(*key)),
            );
            ignored.sort_unstable();
            ignored
        });
        let node = ingest.map(|ingest| ingest.config);
        let session_policy = policy_of(node.as_ref());
        // The width of the sequence numbers the sessions offer, unicast and in a group's Join:
        // `transport/link/tx/sequence_number_resolution` when the document states a width other
        // than upstream's, the open's `sn-resolution` policy otherwise. A document rendered from
        // a whole configuration states every key at its default, so upstream's own width there is
        // no instruction, and the policy stands.
        let upstream_width = ZenohNodeConfig::default().sn_resolution;
        let sn_resolution = match node.as_ref().map(|node| node.sn_resolution) {
            Some(stated) if stated != upstream_width => stated,
            _ => session_policy.sn_resolution(),
        };
        let namespace_text = node.as_ref().and_then(|node| node.namespace.clone());
        // How the node keeps its south apart (`gateway/south`): the preset unless the document
        // states subregions.
        let gateway_south = node
            .as_ref()
            .map_or(SouthPartition::Auto, |node| node.gateway_south.clone());
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
        let tx_queue = node
            .as_ref()
            .map_or_else(StatedTxQueue::default, StatedTxQueue::of);
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
        // The key governs a multicast transport, so a node that joins no group has nothing to
        // compress; one that joins a group in a build without the lz4 wrap is refused.
        #[cfg(not(feature = "transport_compression"))]
        if !group_endpoints.is_empty()
            && node.as_ref().is_some_and(|node| node.multicast_compression)
        {
            return Err(OpenRefusal::MulticastCompressionNotInBuild);
        }
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
        // `transport/link/protocols`, when the document states it, is the whitelist of the
        // unicast links the node makes: an endpoint to listen on or dial whose protocol it leaves
        // out is refused, as upstream refuses it when it makes the link manager. A group is a
        // multicast transport, which this list does not govern.
        if let Some(protocols) = node.as_ref().and_then(|node| node.link_protocols.as_ref()) {
            let left_out = |endpoint: &String| {
                let protocol = endpoint.split('/').next().unwrap_or_default();
                !protocols.iter().any(|allowed| allowed == protocol)
            };
            if listen.iter().chain(connect.iter()).any(left_out) {
                return Err(OpenRefusal::UnsupportedProtocol);
            }
        }
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
        let session = node
            .as_ref()
            .map(session_defaults_of)
            .transpose()?
            .unwrap_or_default();

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
            tx_queue,
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
            gateway_south,
            tls,
            read_files,
            ignored,
            session,
            session_policy,
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
                tx_queue: self.tx_queue.over(abi.tx_queue),
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
                gateway_south: self.gateway_south,
                groups,
                session_defaults: self.session,
                session_policy: self.session_policy,
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
    /// The transmit model: zenoh's bounded queue ([`TxQueueConf::of_policy`]) or pico's
    /// caller-thread write ([`TxQueueConf::pico_of_policy`]), each under the plan's
    /// [`OpenPlan::session_policy`].
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
        self.run_node(crate::drive::NodeRole::Router)
    }

    /// [`Self::run_router`] for a node of the given role: a peer that forwards between the
    /// sessions it accepts and dials is the same data plane at node mode Peer.
    #[cfg(feature = "router-node")]
    pub fn run_node(
        self,
        role: crate::drive::NodeRole,
    ) -> Result<crate::drive::RouterState, OpenError> {
        crate::drive::open_router_blocking(
            role,
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

    const POLICIES: [&str; 2] = [
        r#"{ low_pass_filter: [ { messages: ["put"], key_exprs: ["a/**"], size_limit: 4 } ] }"#,
        r#"{ access_control: { enabled: true, default_permission: "deny" } }"#,
    ];

    #[test]
    fn a_config_that_states_a_traffic_policy_fails_the_open() {
        for document in POLICIES {
            match ZenohNodeConfig::from_json5(document) {
                // The runtime has the key's reader (another crate of the build asked for it), and
                // this build holds no policy.
                Ok(ingest) => assert!(node_security_of(&ingest.config).is_err(), "{document}"),
                // The runtime was built without it, and the reader refuses the key by its name.
                Err(refused) => assert!(
                    matches!(refused, ConfigIngestError::NotInBuild { .. }),
                    "{document}: {refused}"
                ),
            }
        }
    }

    /// Whichever half is missing, the reader or the mechanism, the open refuses a stated policy
    /// with one code.
    #[test]
    fn a_stated_policy_is_refused_as_security_whichever_half_is_missing() {
        for document in POLICIES {
            let plan = OpenPlan::resolve(
                WhatAmI::Client,
                StatedEndpoints {
                    connect: vec!["tcp/127.0.0.1:1".to_owned()],
                    listen: Vec::new(),
                },
                Some(document),
            );
            assert_eq!(plan.err(), Some(OpenRefusal::Security), "{document}");
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

    /// A key whose reader the runtime was built without draws the refusal of its mechanism: the
    /// traffic policy's keys are a security refusal, the certificate material a TLS one, a south
    /// kept apart the gateway's, and any other key the unreadable document's.
    #[test]
    fn a_key_out_of_the_build_draws_the_refusal_of_its_mechanism() {
        for (key, refusal) in [
            ("low_pass_filter", OpenRefusal::Security),
            ("downsampling", OpenRefusal::Security),
            ("qos/network", OpenRefusal::Security),
            ("access_control/enabled", OpenRefusal::Security),
            ("access_control/rules", OpenRefusal::Security),
            (
                "transport/link/tls/root_ca_certificate",
                OpenRefusal::TlsMaterial,
            ),
            ("transport/link/tls/so_rcvbuf", OpenRefusal::TlsMaterial),
            (
                "transport/link/unixpipe/file_access_mask",
                OpenRefusal::LinkNotInBuild,
            ),
            ("transport/link/rx/buffer_size", OpenRefusal::LinkNotInBuild),
            ("plugins_loading/enabled", OpenRefusal::PluginHostNotInBuild),
            ("gateway/south", OpenRefusal::GatewayNotCarried),
            ("aggregation/subscribers", OpenRefusal::Aggregation),
            ("aggregation/publishers", OpenRefusal::Aggregation),
            ("stats/filters", OpenRefusal::StatsNotInBuild),
            ("transport/link/protocols", OpenRefusal::DocumentUnreadable),
        ] {
            assert_eq!(refusal_of_unbuilt_key(key), refusal, "{key}");
        }
        // Every key a build can be made without is given one of the mechanism refusals.
        for (key, _, _) in wz_runtime_tokio::zenoh_config::CAPABILITY_HONOURED_KEYS {
            assert_ne!(
                refusal_of_unbuilt_key(key),
                OpenRefusal::DocumentUnreadable,
                "{key} has no mechanism refusal"
            );
        }
    }

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

    /// A value of `subscriber-overload` other than the build default that the build's domain
    /// allows, by its id; the build default itself where the build allows one value.
    fn a_chosen_overload() -> &'static str {
        use wz_runtime_tokio::policy::SubscriberOverload;
        use wz_session_core::policy_binding::PolicyValue;

        <SubscriberOverload as PolicyValue>::ALL
            .iter()
            .copied()
            .find(|value| {
                *value != <SubscriberOverload as PolicyValue>::DEFAULT
                    && <SubscriberOverload as PolicyValue>::DOMAIN.contains(*value)
            })
            .unwrap_or(<SubscriberOverload as PolicyValue>::DEFAULT)
            .id()
    }

    /// The plan runs under the snapshot the document's `wz` member resolved to, and a document
    /// without the member, or no document, under the build defaults.
    #[test]
    fn the_plan_runs_under_the_policies_the_document_states() {
        let value = a_chosen_overload();
        let stated = format!(r#"{{ wz: {{ policies: {{ "subscriber-overload": "{value}" }} }} }}"#);
        let plan = plan_of(WhatAmI::Client, &["tcp/127.0.0.1:7447"], &[], &stated)
            .expect("a client told its router opens");
        assert_eq!(plan.session_policy.subscriber_overload().id(), value);
        let node = node_of(&stated);
        assert_eq!(resolve_policy(Some(&node)), node.policies.policy);
        assert_eq!(plan.session_policy, node.policies.policy);

        let plain = plan_of(WhatAmI::Client, &["tcp/127.0.0.1:7447"], &[], "{}")
            .expect("a client told its router opens");
        assert_eq!(plain.session_policy, SessionPolicy::defaults());
        assert_eq!(resolve_policy(None), SessionPolicy::defaults());
    }

    /// A refused `wz` member refuses the open, before every refusal that reads the rest of the
    /// document: a client with nothing to dial is told of the member, not of its endpoints.
    #[test]
    fn a_refused_wz_member_refuses_the_open_first() {
        assert_eq!(
            refusal_of(
                WhatAmI::Client,
                &["tcp/127.0.0.1:7447"],
                &[],
                r#"{ wz: { policies: { "key-set": "ajar" } } }"#
            ),
            OpenRefusal::Policies
        );
        let nothing_to_dial = r#"{ scouting: { multicast: { enabled: false } } }"#;
        assert_eq!(
            refusal_of(WhatAmI::Client, &[], &[], nothing_to_dial),
            OpenRefusal::NothingToDial
        );
        assert_eq!(
            refusal_of(
                WhatAmI::Client,
                &[],
                &[],
                r#"{ scouting: { multicast: { enabled: false } }, wz: { limits: {} } }"#
            ),
            OpenRefusal::Policies
        );
        assert_eq!(OpenRefusal::Policies.key(), "wz/profile, wz/policies");
    }

    /// A peer is a forwarding node when it accepts sessions and asks nothing the node does not
    /// carry. One that scouts is a node only when it keeps its south apart: it is then the gateway
    /// of the nodes that find it, and the node scouts and dials what it finds. A peer that scouts
    /// and keeps no south apart is the registry of faces, which does not forward between them.
    #[cfg(all(feature = "router-node", feature = "scout"))]
    #[test]
    fn a_peer_that_scouts_is_a_node_only_when_it_holds_a_gateway() {
        let listening = |document: &str| {
            plan_of(WhatAmI::Peer, &[], &["tcp/127.0.0.1:0"], document)
                .expect("a document a peer opens with")
        };
        let scouting = r#"scouting: { multicast: { enabled: true, address: "224.7.7.7:7777" } }"#;
        let gateway =
            r#"gateway: { south: [ { filters: [ { negated: true, region_names: ["main"] } ] } ] }"#;
        assert!(
            !listening(&format!("{{ {scouting} }}")).peer_fits_node(),
            "a peer that scouts and holds no gateway is the registry of faces"
        );
        assert!(
            listening(&format!("{{ {scouting}, {gateway} }}")).peer_fits_node(),
            "a peer that scouts and holds a gateway is a node"
        );
        assert!(
            listening(r#"{ scouting: { multicast: { enabled: false } } }"#).peer_fits_node(),
            "a peer that does not scout is a node whatever its south"
        );
    }

    /// A client is a node only when it holds a south it keeps apart: it is told its router and
    /// its `gateway/south` names subregions, whether or not it accepts sessions. A client without
    /// them is the registry of faces, as every client was before.
    #[cfg(feature = "router-node")]
    #[test]
    fn a_client_is_a_node_only_when_it_holds_a_south_and_a_router() {
        let gateway =
            r#"{ gateway: { south: [ { filters: [ { modes: ["client", "peer"] } ] } ] } }"#;
        let client = |connect: &[&str], listen: &[&str], document: &str| {
            plan_of(WhatAmI::Client, connect, listen, document)
                .expect("a document a client opens with")
        };
        assert!(
            client(&["tcp/127.0.0.1:7447"], &["tcp/127.0.0.1:0"], gateway).client_fits_node(),
            "a client that listens, dials its router and holds a south is a node"
        );
        assert!(
            !client(&["tcp/127.0.0.1:7447"], &["tcp/127.0.0.1:0"], "{}").client_fits_node(),
            "a client with no south to keep apart has nothing to forward between"
        );
        assert!(
            client(&["tcp/127.0.0.1:7447"], &[], gateway).client_fits_node(),
            "a client that accepts no session dials the remotes it places in its south"
        );
        assert!(
            !client(&["tcp/127.0.0.1:7447"], &[], "{}").client_fits_node(),
            "a client that keeps no south apart and accepts no session is the registry of faces"
        );
        assert!(
            !client(&[], &["tcp/127.0.0.1:0"], gateway).client_fits_node(),
            "a client that is told no router has nothing north"
        );
    }

    /// Subregions of `gateway/south` are placed by a node alone, so an open that holds none is
    /// refused by the key and not run as the registry of faces: a router is a node whatever it
    /// holds, a peer or a client where it fits one, a caller that runs no node never, and the
    /// preset every open.
    #[test]
    fn a_south_apart_is_refused_where_no_node_carries_it() {
        let south = r#"{ gateway: { south: [ { filters: [ { modes: ["peer"] } ] } ] } }"#;
        let plan = |role: WhatAmI, connect: &[&str], listen: &[&str], document: &str| {
            plan_of(role, connect, listen, document).expect("a document these roles open with")
        };
        let dial = ["tcp/127.0.0.1:7447"];
        let bind = ["tcp/127.0.0.1:0"];
        // The preset places a remote by its role alone, which every open does.
        for role in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            for node in [false, true] {
                assert_eq!(
                    plan(role, &dial, &bind, "{}").refuse_uncarried_south(role, node),
                    Ok(()),
                    "the preset needs no node ({role:?}, node: {node})"
                );
            }
        }
        // A caller that runs no node carries no partition, whatever the shape.
        for role in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            assert_eq!(
                plan(role, &dial, &bind, south).refuse_uncarried_south(role, false),
                Err(OpenRefusal::GatewayNotCarried),
                "a surface with no node refuses the partition ({role:?})"
            );
        }
        assert_eq!(OpenRefusal::GatewayNotCarried.key(), "gateway/south");
        #[cfg(feature = "router-node")]
        {
            assert_eq!(
                plan(WhatAmI::Router, &[], &[], south)
                    .refuse_uncarried_south(WhatAmI::Router, true),
                Ok(()),
                "a router is a node whatever it holds"
            );
            assert_eq!(
                plan(WhatAmI::Peer, &[], &bind, south).refuse_uncarried_south(WhatAmI::Peer, true),
                Ok(()),
                "a peer that listens and does not scout is a node"
            );
            // A peer binds its role's default unless its document names the key, so a peer that
            // accepts no session says so.
            let deaf = r#"{ listen: { endpoints: [] },
                gateway: { south: [ { filters: [ { modes: ["peer"] } ] } ] } }"#;
            assert_eq!(
                plan(WhatAmI::Peer, &dial, &[], deaf).refuse_uncarried_south(WhatAmI::Peer, true),
                Ok(()),
                "a peer that keeps a south apart is a node though it accepts no session"
            );
            assert!(
                !plan(
                    WhatAmI::Peer,
                    &dial,
                    &[],
                    r#"{ listen: { endpoints: [] } }"#
                )
                .peer_fits_node(),
                "a peer that keeps no south apart and accepts no session is the registry of faces"
            );
            assert_eq!(
                plan(WhatAmI::Client, &dial, &bind, south)
                    .refuse_uncarried_south(WhatAmI::Client, true),
                Ok(()),
                "a client that listens and dials its router is a node"
            );
            assert_eq!(
                plan(WhatAmI::Client, &dial, &[], south)
                    .refuse_uncarried_south(WhatAmI::Client, true),
                Ok(()),
                "a client that keeps a south apart is a node though it accepts no session"
            );
            assert_eq!(
                plan(WhatAmI::Client, &[], &bind, south)
                    .refuse_uncarried_south(WhatAmI::Client, true),
                Err(OpenRefusal::GatewayNotCarried),
                "a client that is told no router scouts for one, and no node carries that"
            );
        }
        #[cfg(not(feature = "router-node"))]
        assert_eq!(
            plan(WhatAmI::Router, &[], &[], south).refuse_uncarried_south(WhatAmI::Router, true),
            Err(OpenRefusal::GatewayNotCarried),
            "a build without router-node has no node to carry it"
        );
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

    /// `open/return_conditions/declares` reaches the peer's open as the wait on its peers' initial
    /// declarations: held when the key says `true` and when it says nothing (upstream's default),
    /// and not held when it says `false`, and the other key of the block is untouched by it.
    #[test]
    fn open_declares_reaches_the_dial_phase() {
        let phase = |document: &str| dial_phase(&node_of(document), WhatAmI::Peer);
        assert!(phase("{}").wait_declares, "absent: upstream's default");
        assert!(
            phase(r#"{ open: { return_conditions: { declares: true } } }"#).wait_declares,
            "stated true"
        );
        let off = phase(r#"{ open: { return_conditions: { declares: false } } }"#);
        assert!(!off.wait_declares, "stated false");
        assert_eq!(
            off.start_window,
            phase("{}").start_window,
            "the start window the other key gates is the same"
        );
        let neither = phase(
            r#"{ open: { return_conditions: { declares: false, connect_scouted: false } } }"#,
        );
        assert!(!neither.wait_declares);
        assert_eq!(
            neither.start_window, None,
            "connect_scouted false still ends the wait"
        );
    }

    /// `region_name` reaches the offer, so each session of the node announces it; a document that
    /// states none, or `null`, offers no region.
    #[test]
    fn region_name_reaches_the_offer() {
        use wz_session_core::extregion::RegionName;

        let named = offer_for(r#"{ region_name: "south-1" }"#).expect("a region name is an offer");
        let expected = RegionName::new("south-1").expect("a valid name");
        assert_eq!(
            named.region.and_then(|region| region.name()),
            Some(expected.clone())
        );
        assert_eq!(
            named,
            SessionOffer::universal()
                .with_mode(TransportMode::Qos)
                .with_region(&expected)
        );
        assert_eq!(offer_for("{}").expect("an offer").region, None);
        assert_eq!(
            offer_for("{ region_name: null }").expect("an offer").region,
            None
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
            tx_queue: TxQueueConf::of_policy(&SessionPolicy::defaults()),
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
                    tx_queue: TxQueueConf::of_policy(&SessionPolicy::defaults()),
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

    /// The transmit-queue keys a document states away from upstream's defaults are laid over the
    /// ABI's transmit model, and a document that states them at upstream's defaults, or not at
    /// all, leaves the model as the ABI chose it.
    #[test]
    fn the_queue_keys_a_document_states_are_laid_over_the_abis_model() {
        let stance = |document: &str, model: TxQueueConf| {
            plan_of(WhatAmI::Client, &["tcp/127.0.0.1:7447"], &[], document)
                .expect("a client with an endpoint opens")
                .into_arguments(AbiChoices {
                    tx_queue: model,
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
                .tx_queue
        };
        let off = r#"{ transport: { link: { tx: { queue: { batching: { enabled: false } } } } } }"#;
        assert!(!stance(off, TxQueueConf::of_policy(&SessionPolicy::defaults())).batching);
        assert!(!stance(off, TxQueueConf::pico_of_policy(&SessionPolicy::defaults())).batching);
        let bound =
            r#"{ transport: { link: { tx: { queue: { batching: { time_limit: 4 } } } } } }"#;
        assert_eq!(
            stance(bound, TxQueueConf::of_policy(&SessionPolicy::defaults()))
                .batching_time_limit_us,
            4_000
        );
        let init =
            r#"{ transport: { link: { tx: { queue: { allocation: { mode: "init" } } } } } }"#;
        assert_eq!(
            stance(init, TxQueueConf::of_policy(&SessionPolicy::defaults())).allocation,
            wz_session_core::link::QueueAllocation::Init
        );
        // Upstream's own value is no instruction, and silence is none either: the model keeps
        // its writer's bound rather than taking upstream's millisecond.
        let on = r#"{ transport: { link: { tx: { queue: { batching: { enabled: true,
                                                                      time_limit: 1 },
                                                          allocation: { mode: "lazy" } } } } } }"#;
        assert_eq!(
            stance(on, TxQueueConf::pico_of_policy(&SessionPolicy::defaults())),
            TxQueueConf::pico_of_policy(&SessionPolicy::defaults())
        );
        assert_eq!(
            stance("{}", TxQueueConf::of_policy(&SessionPolicy::defaults())),
            TxQueueConf::of_policy(&SessionPolicy::defaults())
        );
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

    /// The width a document states is the one its sessions offer and its groups' Joins state,
    /// and a document that states none, or states upstream's own, offers the build's
    /// `sn-resolution` policy.
    #[test]
    fn the_width_a_document_states_is_the_one_its_sessions_offer() {
        let plan = |document: &str| {
            plan_of(WhatAmI::Client, &["tcp/127.0.0.1:7447"], &[], document)
                .expect("a client with an endpoint opens")
        };
        let stated =
            plan(r#"{ transport: { link: { tx: { sequence_number_resolution: "16bit" } } } }"#);
        assert_eq!(stated.sn_resolution, SnResolution::Bits16);
        // Control: silence is the build's policy, so the width above is the document's; and so
        // is upstream's own width, which a rendered configuration states for every open.
        let build = SessionPolicy::from_build().sn_resolution();
        assert_eq!(plan("{}").sn_resolution, build);
        assert_eq!(
            plan(r#"{ transport: { link: { tx: { sequence_number_resolution: "32bit" } } } }"#)
                .sn_resolution,
            build
        );
        // A width zenoh has no name for is a document the reader refuses.
        assert_eq!(
            refusal_of(
                WhatAmI::Client,
                &["tcp/127.0.0.1:7447"],
                &[],
                r#"{ transport: { link: { tx: { sequence_number_resolution: "12bit" } } } }"#,
            ),
            OpenRefusal::DocumentUnreadable
        );
    }

    /// A plan runs under the snapshot it is handed and not under the build's: a document that
    /// states no width offers the handed snapshot's `sn-resolution`, and the stance the plan
    /// becomes carries that snapshot to the machines the open makes.
    #[test]
    fn a_plan_runs_under_the_snapshot_it_is_handed() {
        let build = SessionPolicy::defaults();
        let other = if build.sn_resolution() == SnResolution::Bits16 {
            SnResolution::Bits8
        } else {
            SnResolution::Bits16
        };
        let mut handed = SessionPolicy::defaults();
        if handed.select_sn_resolution(other).is_err() {
            // The build allows one width: there is no other to hand.
            return;
        }
        let plan = OpenPlan::resolve_under(
            WhatAmI::Client,
            StatedEndpoints {
                connect: vec!["tcp/127.0.0.1:7447".to_owned()],
                listen: Vec::new(),
            },
            Some("{}"),
            |_| handed,
        )
        .expect("a client with an endpoint opens");
        assert_eq!(plan.sn_resolution, other);
        assert_eq!(plan.session_policy, handed);
        let stance = plan
            .into_arguments(AbiChoices {
                tx_queue: TxQueueConf::of_policy(&handed),
                start_read_task: true,
                local_delivery: LocalDeliveryDrain::Caller,
                liveliness_to_self: true,
                initial_interest: true,
                face_drive: FaceDrive::PerFace,
                shm_clients: crate::faces::no_shm_clients(),
                offer_shm: false,
                groups_report_shm: false,
            })
            .stance;
        assert_eq!(stance.sn_resolution, other);
        assert_eq!(stance.session_policy, handed);
        // Control: the open that resolves its own snapshot offers the build's width.
        let own = plan_of(WhatAmI::Client, &["tcp/127.0.0.1:7447"], &[], "{}")
            .expect("a client with an endpoint opens");
        assert_eq!(own.sn_resolution, build.sn_resolution());
        assert_eq!(own.session_policy, build);
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
            tx_queue: TxQueueConf::of_policy(&SessionPolicy::defaults()),
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

    /// `transport/multicast/compression/enabled` on a node that joins a group reaches the group's
    /// profile in a build with the lz4 wrap, and fails the open in one without it: a group's
    /// members cannot settle the wrap by handshake, so a node that dropped the switch would be a
    /// member the others cannot read. A node that joins no group has nothing to compress and opens
    /// either way.
    #[test]
    fn a_compressing_group_is_carried_or_refused_by_the_build() {
        let group = "udp/224.0.0.224:7446#iface=lo";
        let stated = |mode: &str| {
            format!(
                r#"{{ mode: "{mode}", transport: {{ multicast: {{ compression: {{ enabled: true }} }} }} }}"#
            )
        };
        let router = stated("router");
        #[cfg(feature = "transport_compression")]
        {
            let plan = plan_of(WhatAmI::Router, &[], &[group], &router).expect("opens");
            assert!(
                plan.describe()
                    .contains("compression: true, join_rule: Zenoh } shm="),
                "{}",
                plan.describe()
            );
        }
        #[cfg(not(feature = "transport_compression"))]
        assert_eq!(
            refusal_of(WhatAmI::Router, &[], &[group], &router),
            OpenRefusal::MulticastCompressionNotInBuild
        );
        assert_eq!(
            OpenRefusal::MulticastCompressionNotInBuild.key(),
            "transport/multicast/compression/enabled"
        );
        // No group is joined, so the key governs nothing.
        assert!(plan_of(WhatAmI::Router, &[], &["tcp/127.0.0.1:7447"], &router).is_ok());
    }

    /// `transport/multicast/max_sessions` reaches the profile of a group the node joins, and a
    /// document that states none gives the group upstream's cap of 1000.
    #[test]
    fn the_member_cap_a_document_states_reaches_the_group_profile() {
        let read = |document: &str| {
            ZenohNodeConfig::from_json5(document)
                .expect("the document reads")
                .config
        };
        let stated = read(r#"{ transport: { multicast: { max_sessions: 9 } } }"#);
        assert_eq!(
            zenoh_group_profile(&stated, 65535, SnResolution::Bits32).max_sessions,
            Some(9)
        );
        let silent = read("{}");
        assert_eq!(
            zenoh_group_profile(&silent, 65535, SnResolution::Bits32).max_sessions,
            Some(1000)
        );
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
                 start_window: Some(500ms), router_hold: 500ms, wait_declares: true, \
                 open_timeout: 10s }}\n\
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
                 autoconnect: WhatAmIMatcher({autoconnect}), strategies: Unique(Always), \
                 multihop: false }})"
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
                 join_interval_ms: 2500, max_sessions: Some(1000), seq_num_res: 2, \
                 req_id_res: 2, batch_size: 8192, \
                 is_qos: false, compression: false, join_rule: Zenoh } shm=true Subscribers\"]",
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
        let state = |path| key_state(path, SessionReach::default());
        assert_eq!(state("connect/timeout_ms"), Some(KeyState::Mapped));
        assert_eq!(
            state("transport/auth/pubkey/key_size"),
            Some(KeyState::Inert)
        );
        assert_eq!(state("transport/link/tx/threads"), Some(KeyState::Unmapped));
        // A key the C interface acts on is mapped, whichever list it left.
        assert_eq!(
            state("transport/unicast/accept_timeout"),
            Some(KeyState::Mapped)
        );
        assert_eq!(
            state("transport/unicast/open_timeout"),
            Some(KeyState::Mapped)
        );
        // The cap on a group's members, which each group the engine joins is held to.
        assert_eq!(
            state("transport/multicast/max_sessions"),
            Some(KeyState::Mapped)
        );
        assert_eq!(
            state("transport/link/tls/root_ca_certificate_base64"),
            Some(KeyState::Unmapped)
        );
        assert_eq!(state("a/key/nobody/lists"), None);
        assert!(is_section_of_keys_with_a_state("gateway"));
        assert!(!is_section_of_keys_with_a_state(
            "transport/link/tx/threads"
        ));
    }

    /// A key only a session applies is mapped for the session that applies it and for no other:
    /// a session without shared memory leaves the shared-memory keys inert, as upstream's built
    /// without it does, and one with shared memory that does not copy a kind of message leaves
    /// the promotion's keys unmapped, where upstream acts on them.
    #[test]
    fn a_session_key_is_mapped_only_for_the_session_that_applies_it() {
        use wz_runtime_tokio::zenoh_config::SESSION_HONOURED_KEYS;
        const THRESHOLD: &str =
            "transport/shared_memory/transport_optimization/message_size_threshold";
        const MESSAGES: &str = "transport/shared_memory/transport_optimization/messages";
        const MODE: &str = "transport/shared_memory/mode";

        let everything = SessionReach {
            publication_qos: true,
            shared_memory: true,
            promotion: PromotedMessages::ALL,
        };
        for key in SESSION_HONOURED_KEYS {
            assert!(
                session_key_state(key, SessionReach::default()).is_some(),
                "{key} is a session's and has no session state"
            );
            assert_eq!(
                key_state(key, everything),
                if *key == MODE && !cfg!(feature = "transport-shm") {
                    Some(KeyState::Unmapped)
                } else {
                    Some(KeyState::Mapped)
                },
                "{key}"
            );
        }
        assert_eq!(session_key_state("connect/timeout_ms", everything), None);

        let nothing = SessionReach::default();
        assert_eq!(
            key_state("qos/publication", nothing),
            Some(KeyState::Unmapped)
        );
        for key in [MODE, THRESHOLD, MESSAGES] {
            assert_eq!(key_state(key, nothing), Some(KeyState::Inert), "{key}");
        }

        // Shared memory and a provider that copies puts alone: the threshold is acted on, the
        // list is not, since a kind it names is left uncopied.
        let puts_only = SessionReach {
            publication_qos: true,
            shared_memory: true,
            promotion: PromotedMessages {
                put: true,
                query: false,
                reply: false,
            },
        };
        assert_eq!(key_state(THRESHOLD, puts_only), Some(KeyState::Mapped));
        assert_eq!(key_state(MESSAGES, puts_only), Some(KeyState::Unmapped));
        // Shared memory and no provider to copy into.
        let no_provider = SessionReach {
            promotion: PromotedMessages::NONE,
            ..puts_only
        };
        assert_eq!(key_state(THRESHOLD, no_provider), Some(KeyState::Unmapped));
        assert_eq!(key_state(MESSAGES, no_provider), Some(KeyState::Unmapped));
    }

    /// The plan compiles what the session applies itself from the document, and carries it into
    /// the open's arguments, from where the session holds it.
    #[test]
    fn the_plan_compiles_the_session_defaults_and_hands_them_to_the_open() {
        use crate::session_defaults::PromotedMessage;

        let plan = plan_of(
            WhatAmI::Client,
            &["tcp/127.0.0.1:1"],
            &[],
            r#"{ scouting: { multicast: { enabled: false } },
                 qos: { publication: [ { key_exprs: ["demo/**"],
                                         config: { priority: "background", express: true } } ] },
                 transport: { shared_memory: { mode: "init", transport_optimization: {
                     message_size_threshold: 128, messages: ["query", "delete"] } } } }"#,
        )
        .expect("opens");
        assert!(plan.ignored.is_empty(), "{:?}", plan.ignored);
        assert_eq!(plan.session.shm_init, ShmInit::Init);
        assert_eq!(plan.session.shm_promotion.threshold, 128);
        assert_eq!(
            plan.session.shm_promotion.messages,
            PromotedMessages {
                put: false,
                query: true,
                reply: false,
            },
            "a delete names no kind a payload is copied for"
        );
        assert!(plan
            .session
            .shm_promotion
            .admits(PromotedMessage::Query, 128));
        assert!(!plan
            .session
            .shm_promotion
            .admits(PromotedMessage::Put, 1 << 20));
        let given = plan.session.publication_qos.defaults_for("demo/a");
        assert_eq!(
            given.priority,
            Some(wz_runtime_tokio::qos::Priority::Background)
        );
        assert_eq!(given.express, Some(true));
        assert_eq!(given.congestion_control, None);

        let expected = plan.session.clone();
        let arguments = plan.into_arguments(AbiChoices {
            tx_queue: TxQueueConf::of_policy(&SessionPolicy::defaults()),
            start_read_task: true,
            local_delivery: LocalDeliveryDrain::Caller,
            liveliness_to_self: true,
            initial_interest: true,
            face_drive: FaceDrive::PerFace,
            shm_clients: crate::faces::no_shm_clients(),
            offer_shm: false,
            groups_report_shm: false,
        });
        assert_eq!(arguments.stance.session_defaults, expected);

        // A document that states none of the keys gives upstream's defaults, which apply nothing
        // to a publication.
        let silent = plan_of(
            WhatAmI::Client,
            &["tcp/127.0.0.1:1"],
            &[],
            r#"{ scouting: { multicast: { enabled: false } } }"#,
        )
        .expect("opens");
        assert_eq!(silent.session, SessionDefaults::default());
    }

    /// Every case the surfaces of `qos/publication` are held to is what the plan compiles: the
    /// one reading the C ABI and the Rust API preset both take their defaults from.
    #[test]
    fn the_plan_gives_each_shared_publication_case_its_settings() {
        for case in crate::session_defaults::PUBLICATION_QOS_CASES {
            let document = format!(
                "{{ scouting: {{ multicast: {{ enabled: false }} }}, qos: {{ publication: {} }} }}",
                case.rules
            );
            let plan = plan_of(WhatAmI::Client, &["tcp/127.0.0.1:1"], &[], &document)
                .unwrap_or_else(|refusal| panic!("{}: {refusal:?}", case.rules));
            assert_eq!(
                plan.session.publication_qos.defaults_for(case.key),
                case.expected,
                "{} on {}",
                case.rules,
                case.key
            );
        }
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
                 transport: { unicast: { open_timeout: 1234 },
                              link: { tx: { threads: 3 } } } }"#,
        )
        .expect("opens");
        assert_eq!(plan.ignored, ["transport/link/tx/threads"]);
        // The open bound is a key the engine acts on: it reaches the dial phase.
        assert_eq!(
            plan.dial.open_timeout,
            std::time::Duration::from_millis(1234)
        );
    }

    /// A key the reader honours for a wz node and this engine has no part to act on is unmapped
    /// here, and a document that states it has it reported, as one the reader does not read is.
    #[test]
    fn a_node_key_the_engine_has_no_part_for_is_unmapped_and_reported() {
        for key in NODE_KEYS_THE_ENGINE_DOES_NOT_ACT_ON {
            assert!(
                wz_runtime_tokio::zenoh_config::HONOURED_CONFIG_KEYS.contains(key),
                "{key} is not a node key, so the reader's own report already covers it"
            );
            assert_eq!(
                key_state(key, SessionReach::default()),
                Some(KeyState::Unmapped),
                "{key}"
            );
        }
        let plan = plan_of(
            WhatAmI::Client,
            &["tcp/127.0.0.1:1"],
            &[],
            r#"{ scouting: { multicast: { enabled: false } },
                 plugins_loading: { search_dirs: ["/opt/wz/plugins"] },
                 stats: { filters: [] } }"#,
        )
        .expect("opens");
        assert_eq!(
            plan.ignored,
            ["plugins_loading/search_dirs", "stats/filters"]
        );
    }

    /// `aggregation/*` is acted on by the registry of faces: the plan compiles the aggregates into
    /// what the session applies itself, carries them to the open, and does not report them among
    /// the keys it ignores. A list built by hand that holds no key expression is refused by the
    /// keys' name, as a build without the inclusion test refuses one.
    #[test]
    fn the_plan_carries_the_aggregates_to_the_open() {
        for key in ["aggregation/subscribers", "aggregation/publishers"] {
            assert!(
                !NODE_KEYS_THE_ENGINE_DOES_NOT_ACT_ON.contains(&key),
                "{key}"
            );
            assert_eq!(
                key_state(key, SessionReach::default()),
                Some(KeyState::Mapped),
                "{key}: the engine's runtime is built with the inclusion test"
            );
        }
        let plan = plan_of(
            WhatAmI::Client,
            &["tcp/127.0.0.1:1"],
            &[],
            r#"{ scouting: { multicast: { enabled: false } },
                 aggregation: { subscribers: ["demo/**"], publishers: ["demo/pub/**"] } }"#,
        )
        .expect("opens");
        assert!(plan.ignored.is_empty(), "{:?}", plan.ignored);
        let expected =
            DeclarationAggregation::new(vec!["demo/**".to_owned()], vec!["demo/pub/**".to_owned()])
                .expect("key expressions");
        assert_eq!(plan.session.aggregation, expected);
        let arguments = plan.into_arguments(AbiChoices {
            tx_queue: TxQueueConf::of_policy(&SessionPolicy::defaults()),
            start_read_task: true,
            local_delivery: LocalDeliveryDrain::Caller,
            liveliness_to_self: true,
            initial_interest: true,
            face_drive: FaceDrive::PerFace,
            shm_clients: crate::faces::no_shm_clients(),
            offer_shm: false,
            groups_report_shm: false,
        });
        assert_eq!(arguments.stance.session_defaults.aggregation, expected);

        let mut node = ZenohNodeConfig::from_json5("{}")
            .expect("an empty document")
            .config;
        node.aggregation_subscribers = vec!["demo//double".to_owned()];
        assert_eq!(
            session_defaults_of(&node).err(),
            Some(OpenRefusal::Aggregation)
        );
        assert_eq!(
            OpenRefusal::Aggregation.key(),
            "aggregation/subscribers, aggregation/publishers"
        );
    }

    /// A node holds its own entities as entries of its tables, so it does not carry an aggregate
    /// and an open that would run as one names the keys it was given; a node given none opens.
    #[cfg(feature = "router-node")]
    #[test]
    fn a_node_refuses_the_aggregates_by_their_keys() {
        let arguments = |document: &str| {
            plan_of(WhatAmI::Router, &[], &["tcp/127.0.0.1:0"], document)
                .expect("opens")
                .into_arguments(AbiChoices {
                    tx_queue: TxQueueConf::of_policy(&SessionPolicy::defaults()),
                    start_read_task: true,
                    local_delivery: LocalDeliveryDrain::Caller,
                    liveliness_to_self: true,
                    initial_interest: true,
                    face_drive: FaceDrive::PerFace,
                    shm_clients: crate::faces::no_shm_clients(),
                    offer_shm: false,
                    groups_report_shm: false,
                })
        };
        let silent = arguments(r#"{ scouting: { multicast: { enabled: false } } }"#);
        assert_eq!(silent.router_refusal(), None, "CONTROL: nothing asked");
        for list in ["subscribers", "publishers"] {
            let stated = arguments(&format!(
                r#"{{ scouting: {{ multicast: {{ enabled: false }} }},
                      aggregation: {{ {list}: ["demo/**"] }} }}"#
            ));
            assert_eq!(
                stated.router_refusal(),
                Some("`aggregation/subscribers` or `aggregation/publishers`"),
                "{list}"
            );
        }
    }

    /// `transport/link/protocols` is a whitelist of the unicast links the node makes: an endpoint
    /// to listen on or dial that it leaves out refuses the open, one it names opens, and a
    /// document that states none leaves every protocol open.
    #[test]
    fn the_protocols_whitelist_refuses_an_endpoint_it_leaves_out() {
        let open =
            |endpoints: &[&str], document: &str| plan_of(WhatAmI::Client, endpoints, &[], document);
        let scouting_off = "scouting: { multicast: { enabled: false } }";
        let listed =
            format!(r#"{{ transport: {{ link: {{ protocols: ["tcp"] }} }}, {scouting_off} }}"#);
        assert!(open(&["tcp/127.0.0.1:1"], &listed).is_ok());
        assert_eq!(
            open(&["tls/127.0.0.1:1"], &listed).err(),
            Some(OpenRefusal::UnsupportedProtocol),
            "tls is not in the whitelist"
        );
        let unlisted = format!("{{ {scouting_off} }}");
        assert!(
            open(&["tls/127.0.0.1:1"], &unlisted).is_ok(),
            "a document that states no whitelist leaves every protocol open"
        );
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
