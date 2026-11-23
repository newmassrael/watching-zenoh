// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_open` / `z_close`, the session ownership family, and the `zp_*_task`
//! shims — plus the async-drive bridge that makes a wz `Session` behave like a
//! self-driving pico session.
//!
//! ## The drive bridge
//!
//! wz has no `Session::open` and no self-driving session: a subscriber
//! callback fires only while a drive loop actively pumps the link, dispatching
//! each `IterationEvent` into the observer the subscriber registered on. pico's
//! `z_open`, by contrast, returns and the read/lease work runs in the
//! background (`~/zenoh-pico/src/api/api.c:882-942` starts the background
//! executor inside `z_open`).
//!
//! This crate bridges that by owning one OS thread per session, running a
//! multi-thread tokio runtime that `block_on`s the whole session lifecycle.
//! `block_on` does not require the driven future to be `Send`, which the accept
//! loop's per-face drive futures are not; the runtime is multi-thread so the
//! socket writer tasks and the drive loop make progress while the C thread is
//! between calls.
//!
//! ## The two roles, and what `z_open` blocks on
//!
//! The config's `connect` / `listen` keys pick the role, and each mirrors what
//! real pico does:
//!
//! - **`connect` (dial, client)** — pico performs a synchronous outbound
//!   InitSyn/InitAck/OpenSyn/OpenAck handshake and returns success, or an error
//!   if the peer is unreachable (`src/transport/unicast/transport.c:280-287`).
//!   So `z_open` here blocks until Established and lands exactly one peer
//!   (`DIAL_FACE_ID`) in the registry.
//! - **`listen` (accept, peer)** — pico forces PEER mode, does a non-blocking
//!   `bind()` + `listen()`, spawns an async accept task, and **returns
//!   immediately with zero peers and no error** (`src/net/session.c:87-118`,
//!   `src/transport/manager.c:98-130`); the LISTEN branch runs no handshake at
//!   all (`transport.c:294-311`). So `z_open` here returns as soon as the bind
//!   succeeds, and peers are accepted in the background.
//!
//! Round 1 blocked the `listen` role until its first peer connected, which was
//! both a divergence and an uncancellable hang (no `SessionState` existed yet,
//! so `z_close` could not interrupt it). R2 removes it: the bind is the whole
//! of `z_open(listen)`, and the accept loop races a cancellable shutdown.

use core::ffi::c_void;

use wz_session_core::session_zid::SessionZid;

use crate::abi::{z_moved_config_t, z_owned_config_t};
use crate::config::{
    ConfigState, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY,
    Z_CONFIG_SESSION_ZID_KEY,
};
use crate::config_policy::PolicyStatements;
// The twelve TLS key constants are consumed ONLY by `resolve_tls_config`, which
// exists only when a certificate has a backend that could consume it. Importing
// them at module scope would make the no-backend build carry twelve unused
// imports, which `-D warnings` rejects — so the import rides the same cfg as its
// single consumer rather than the consumer being widened to justify the import.
#[cfg(any(
    feature = "transport-link-tls",
    feature = "transport-link-quic",
    feature = "tls-mbedtls"
))]
use crate::config::{
    Z_CONFIG_TLS_CONNECT_CERTIFICATE_BASE64_KEY, Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY,
    Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_BASE64_KEY, Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY,
    Z_CONFIG_TLS_ENABLE_MTLS_KEY, Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY,
    Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY, Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY,
    Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY, Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY,
    Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY, Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY,
};
use crate::ffi::{guard_val, guarded};
use crate::prelude::*;
// The read-task doors' refusals, which only the multi-threaded arm has.
#[cfg(feature = "multi-thread")]
use crate::result::Z_EINVAL;
#[cfg(feature = "engine-tokio")]
use crate::result::Z_ERR_GENERIC;
use crate::result::{
    ZResult, Z_ERR_NULL, Z_ERR_SESSION_CLOSED, Z_ERR_TRANSPORT_NOT_AVAILABLE, Z_OK,
};
#[cfg(feature = "multi-thread")]
use crate::sync::Z_ERR_SYSTEM_GENERIC;
#[cfg(feature = "engine-tokio")]
use wz_capi_core::drive::{open_blocking, DialPhase, OpenError, OpenStance, SessionState};
#[cfg(any(feature = "engine-tokio", feature = "tls-mbedtls"))]
use wz_capi_port::tls_material::CapiTlsConfig;
#[cfg(feature = "multi-thread")]
use wz_capi_port::ReadTaskStartRefused;
use wz_session_core::limits::SessionLimits;
use wz_session_core::policy::{SessionPolicy, SnResolution};
use wz_session_core::session_init_params::{KeepAliveConf, LinkRxConf, TxQueueConf};
use wz_session_core::WhatAmI;

/// Open-debt item 913 — whether a `listen` endpoint names a multicast group: a `udp/`
/// locator whose metadata names an interface (`#iface=`). That is when pico's listen link
/// for it is the multicast one (`vendor/zenoh-pico/src/link/multicast/udp.c` @
/// `z_result_t _z_endpoint_udp_multicast_valid(`); pico's listen has no unicast UDP link
/// (`vendor/zenoh-pico/src/link/link.c` @ `z_result_t _z_listen_link(`).
///
/// Open-debt item 911 — and, with `raweth-transport`, any `reth/` endpoint: pico's listen of one
/// opens its raweth transport, a multicast session over raw Ethernet
/// (`vendor/zenoh-pico/src/transport/raweth/link.c` @
/// `static z_result_t _z_f_link_listen_raweth(_z_link_t *self) { return _z_f_link_open_raweth(self); }`).
#[cfg(any(feature = "engine-tokio", feature = "peer"))]
pub(crate) fn is_group_endpoint(endpoint: &str) -> bool {
    let (locator, metadata) = endpoint.split_once('#').unwrap_or((endpoint, ""));
    #[cfg(all(feature = "raweth-transport", target_os = "linux"))]
    if locator.starts_with("reth/") {
        return true;
    }
    locator.starts_with("udp/") && metadata.split(';').any(|pair| pair.starts_with("iface="))
}

/// The batch size a unicast session of this ABI advertises in its InitSyn, on either engine:
/// pico's `BATCH_UNICAST_SIZE` as the open's snapshot `limits` holds it
/// (`PICO_UNICAST_BATCH_BYTES`).
fn pico_unicast_batch(limits: &SessionLimits) -> u16 {
    pico_batch(limits.pico_unicast_batch_bytes())
}

/// The batch size pico's Join advertises on a group: its `BATCH_MULTICAST_SIZE` as the open's
/// snapshot `limits` holds it (`PICO_MULTICAST_BATCH_BYTES`).
#[cfg(feature = "multicast-transport")]
fn pico_multicast_batch(limits: &SessionLimits) -> u16 {
    pico_batch(limits.pico_multicast_batch_bytes())
}

/// A batch size of this ABI as the wire carries it, in two bytes. The domain of both batch limits
/// is `1..=65535`, so a snapshot holds no size the field cannot carry: a batch of 0 would size a
/// session that sends nothing, and one past `u16::MAX` does not fit the field.
fn pico_batch(bytes: usize) -> u16 {
    u16::try_from(bytes).unwrap_or(u16::MAX)
}

/// What a session of this ABI rejoins from fragments, unicast and in a group, on either engine:
/// pico's `FRAG_MAX_SIZE` as the open's snapshot `limits` holds it (`PICO_FRAG_MAX_BYTES`; a
/// snapshot that states no bound leaves the reassembly slot the only one), whose rule is upstream's
/// `transport/link/rx/max_message_size` (a chain a fragment would take past it is dropped,
/// `vendor/zenoh-pico/src/transport/unicast/rx.c` @
/// `if ((_z_wbuf_len(dbuf) + msg->_payload.len) > Z_FRAG_MAX_SIZE) {`).
///
/// The read storage a stream link pools is upstream's default, which pools exactly one buffer:
/// pico reads each unicast transport into one buffer of its own
/// (`vendor/zenoh-pico/src/transport/unicast/transport.c` @ `ztu->_common._zbuf = _z_zbuf_make(zbuf_size);`).
///
/// A link over TCP is as wide as pico's, the widest batch whatever the connection
/// ([`TcpLinkMtu::Widest`](wz_session_core::session_init_params::TcpLinkMtu::Widest)), and an
/// opening session refuses an InitAck that names a larger batch than it offered, as pico does
/// ([`WiderInitAckBatch::Refuse`](wz_session_core::session_init_params::WiderInitAckBatch::Refuse)).
fn pico_link_rx(limits: &SessionLimits) -> LinkRxConf {
    LinkRxConf {
        buffer_size: wz_session_core::session_init_params::RX_BUFFER_SIZE,
        max_message_size: limits.pico_frag_max_bytes().most().unwrap_or(usize::MAX),
        tcp_mtu: wz_session_core::session_init_params::TcpLinkMtu::Widest,
        wider_init_ack_batch: wz_session_core::session_init_params::WiderInitAckBatch::Refuse,
    }
}

/// How long a listening session of this ABI gives an inbound link, pico's
/// `Z_TRANSPORT_ACCEPT_TIMEOUT` as the open's snapshot `limits` holds it
/// (`PICO_ACCEPT_TIMEOUT_MS`). pico bounds no count of pending accepts (it accepts one link at a
/// time on its read task), so the count is upstream's rather than none: a bound pico never
/// refused on is no worse than zenoh's.
#[cfg(feature = "engine-tokio")]
fn pico_accept(limits: &SessionLimits) -> wz_capi_core::runtime::accept_bounds::AcceptBounds {
    wz_capi_core::runtime::accept_bounds::AcceptBounds {
        timeout_ms: limits.pico_accept_timeout_ms() as u64,
        pending: wz_capi_core::runtime::config::ACCEPT_PENDING,
    }
}

/// How the tokio engine's open of this ABI dials. One attempt, as pico's `z_open` makes; a lost
/// client session is opened again every 1000 ms, as pico re-opens it by default
/// (`Z_FEATURE_AUTO_RECONNECT`, `vendor/zenoh-pico/src/net/session.c` @
/// `return _z_fut_fn_result_wake_up_after(1000);`).
///
/// Each open of an endpoint, its dial and its handshake, is held to pico's
/// `Z_TRANSPORT_CONNECT_TIMEOUT` as the open's snapshot `limits` holds it
/// (`PICO_CONNECT_TIMEOUT_MS`), and the session machine holds the
/// handshake to the same bound, as the cooperative engine's open does: pico gives both receives of
/// its handshake one deadline that long (`vendor/zenoh-pico/src/transport/unicast/transport.c` @
/// `z_clock_advance_ms(&recv_deadline, Z_TRANSPORT_CONNECT_TIMEOUT);`), where zenoh's
/// `transport/unicast/open_timeout` would hold it to zenoh's ten seconds whatever the snapshot
/// states.
///
/// pico's `Z_CONFIG_SOCKET_TIMEOUT` has nothing to bound on this engine, so it is not read here.
/// Upstream it is how long a blocking receive, and the read task's wait on its sockets, lasts
/// before the task looks again (`vendor/zenoh-pico/src/transport/unicast/read.c` @
/// `return _z_socket_wait_readable(&iter, Z_CONFIG_SOCKET_TIMEOUT);`): a polling period, not a
/// deadline. This engine's read task is woken by its link's input and never polls, and its
/// `zp_read` processes nothing, so no wait of it corresponds.
#[cfg(feature = "engine-tokio")]
fn pico_dial_phase(limits: &SessionLimits) -> DialPhase {
    DialPhase {
        redial: Some(wz_capi_core::runtime::retry_period::RetryPolicy::constant(
            1000,
        )),
        open_timeout: core::time::Duration::from_millis(limits.pico_connect_timeout_ms() as u64),
        ..DialPhase::ONCE
    }
}

/// The lease a session of this ABI advertises, unicast in its InitSyn and in a group's Join, on
/// either engine: pico's `Z_TRANSPORT_LEASE` as the open's snapshot `limits` holds it
/// (`PICO_LEASE_MS`).
fn pico_lease_ms(limits: &SessionLimits) -> u64 {
    limits.pico_lease_ms() as u64
}

/// How often a session of this ABI sends a keepalive on an idle link, on either engine: pico's
/// `Z_TRANSPORT_LEASE_EXPIRE_FACTOR` as the open's snapshot `limits` holds it
/// (`PICO_KEEPALIVES_PER_LEASE`), dividing the adopted lease. The limit's domain starts at 1, so
/// no snapshot holds the factor of 0 that would divide by zero in pico's own task, and ends at
/// `u32::MAX`, so the factor always fits.
fn pico_keep_alive(limits: &SessionLimits) -> KeepAliveConf {
    KeepAliveConf::pico(u32::try_from(limits.pico_keepalives_per_lease()).unwrap_or(u32::MAX))
}

/// How long one read step of the cooperative engine waits on its links, in milliseconds: pico's
/// `Z_CONFIG_SOCKET_TIMEOUT` as the open's snapshot `limits` holds it
/// (`PICO_SOCKET_TIMEOUT_MS`), whose domain ends at `u32::MAX`, what the wait holds.
#[cfg(not(feature = "engine-tokio"))]
fn pico_socket_timeout(limits: &SessionLimits) -> u32 {
    u32::try_from(limits.pico_socket_timeout_ms()).unwrap_or(u32::MAX)
}

/// How long the cooperative engine's session machine gives a handshake, as the open's snapshot
/// `limits` holds the two bounds: an inbound link's whole handshake is pico's
/// `Z_TRANSPORT_ACCEPT_TIMEOUT` (`PICO_ACCEPT_TIMEOUT_MS`), as the tokio engine's
/// `pico_accept` reads it, and a dialled one's its `Z_TRANSPORT_CONNECT_TIMEOUT`
/// (`PICO_CONNECT_TIMEOUT_MS`), one deadline over both of its receives, so the session machine
/// holds the handshake to the bound the open holds the endpoint to and to no shorter one. The
/// other windows are the machine's own.
#[cfg(not(feature = "engine-tokio"))]
fn pico_session_timeouts(
    limits: &SessionLimits,
) -> wz_session_core::session_timeouts::SessionTimeouts {
    wz_session_core::session_timeouts::SessionTimeouts {
        accepting_inactivity_ms: limits.pico_accept_timeout_ms() as u64,
        opening_ms: limits.pico_connect_timeout_ms() as u64,
        ..wz_session_core::session_timeouts::SessionTimeouts::from_build()
    }
}

/// What pico's JOIN advertises on a group (`vendor/zenoh-pico/src/protocol/definitions/transport.c`
/// @ `_z_transport_message_t _z_t_msg_make_join(`): its `Z_TRANSPORT_LEASE`, beaconed every
/// `Z_JOIN_INTERVAL` (2500 ms), its `Z_SN_RESOLUTION` and `Z_REQ_RESOLUTION` (0x02 each), its
/// `Z_BATCH_MULTICAST_SIZE`, and no per-priority conduits. The lease and the batch size are build
/// switches of pico's (`BATCH_MULTICAST_SIZE`, `Z_TRANSPORT_LEASE` in its CMakeLists), so they are
/// the numbers the open's snapshot `limits` holds for them (`PICO_LEASE_MS`,
/// `PICO_MULTICAST_BATCH_BYTES`), pico's own by default: pico refuses a
/// member whose Join states another batch size. The join interval and the two resolutions are
/// fixed in pico's config template, not switches; the open's `sn-resolution` policy
/// ([`wz_session_core::policy::SnResolution`]) states another width of the sequence number for a
/// group whose members are built with one, as pico refuses a Join that states another than its own.
#[cfg(feature = "multicast-transport")]
fn pico_group(
    sn_resolution: SnResolution,
    limits: &SessionLimits,
) -> wz_capi_port::group::GroupProfile {
    wz_capi_port::group::GroupProfile {
        lease_ms: pico_lease_ms(limits),
        join_interval_ms: 2_500,
        // pico has no cap on a group's members: its list grows while its allocator gives.
        max_sessions: None,
        seq_num_res: sn_resolution.wire_code(),
        req_id_res: 0x02,
        batch_size: pico_multicast_batch(limits),
        is_qos: false,
        compression: false,
        join_rule: wz_session_core::multicast_params::GroupJoinRule::Pico,
    }
}

/// The policies and the session limits a session [`z_open`] opens from a config runs under: the
/// one place this ABI decides them, resolved once and handed to the engine and to the session's
/// handle. `policies` is what the config's doors stated (`ConfigState::policies`), written over
/// the build defaults ([`PolicyStatements::compose_into`]); `Z_ERR_CONFIG_INVALID_VALUE` when the
/// build refuses any of it. The doors check a change through this before they keep it, so they
/// and the open cannot judge a config differently.
pub(crate) fn resolve_snapshots(
    policies: &PolicyStatements,
) -> Result<(SessionPolicy, SessionLimits), ZResult> {
    let mut policy = SessionPolicy::defaults();
    let mut limits = SessionLimits::defaults();
    policies.compose_into(&mut policy, &mut limits)?;
    Ok((policy, limits))
}

/// [`resolve_snapshots`] with where each value came from, which no door of this ABI reports: what
/// the tests read the doors and the open against.
#[cfg(test)]
pub(crate) fn resolve_policy(
    policies: &PolicyStatements,
) -> Result<wz_session_core::policy_document::Resolved, ZResult> {
    policies.compose(SessionPolicy::defaults())
}

/// pico's transmit model and the width of the sequence numbers its handshake advertises, under
/// `policy` and `limits`, the two snapshots of the open: what both engines' opens are given.
fn pico_link_policy(policy: &SessionPolicy, limits: &SessionLimits) -> (TxQueueConf, SnResolution) {
    (
        TxQueueConf::pico_of_snapshot(policy, limits),
        policy.sn_resolution(),
    )
}

/// Resolve one certificate value from its PATH key or its `*_BASE64` inline key.
///
/// pico offers both forms for every TLS certificate value and they mean the same
/// thing, so this collapses them at the boundary: the path is read off disk, the
/// inline blob is base64-decoded, and both yield PEM bytes.
///
/// PATH WINS when both are set, matching the examples' own precedence — each of
/// them inserts the inline blob only in the `else` arm of "did the user pass a
/// path" (`z_pub_tls.c:150-176`). Encoding the same precedence here means a
/// caller that sets both by hand gets the answer the example would have given.
///
/// A value that is present but unreadable or undecodable is an ERROR, never a
/// silent `None`: `None` means "the caller configured no such material", and
/// letting a corrupt one collapse into it would open a session with less
/// protection than was asked for.
#[cfg(any(
    feature = "transport-link-tls",
    feature = "transport-link-quic",
    feature = "tls-mbedtls"
))]
fn resolve_pem(
    cfg: &ConfigState,
    path_key: u8,
    base64_key: u8,
) -> Result<Option<Vec<u8>>, ZResult> {
    if let Some(path) = cfg.get(path_key) {
        return wz_tls_pem::read_pem_file(path)
            .map(Some)
            .map_err(|_| crate::result::Z_ERR_INVALID);
    }
    if let Some(b64) = cfg.get(base64_key) {
        return wz_tls_pem::decode_base64_pem(b64)
            .map(Some)
            .map_err(|_| crate::result::Z_ERR_INVALID);
    }
    Ok(None)
}

/// Read pico's twelve TLS config keys into the ABI-neutral [`CapiTlsConfig`].
///
/// The boolean keys are compared against `"true"` because that is the literal
/// the examples insert (`z_pub_tls.c:225` writes `"true"` / `"false"`), and
/// anything else — including an absent key — is pico's `false` default.
///
/// Gated on the two link features because the PEM loaders it calls are: wz's
/// `tls_config` module is itself `cfg(any(transport-link-tls,
/// transport-link-quic))`, since without either backend there is nothing that
/// could consume a certificate. The `not` arm below is not a stub — it is the
/// correct answer for that build, where a `tls/` or `quic/` endpoint is rejected
/// at bind/dial as `Unsupported` and the cert keys have no consumer to reach.
#[cfg(any(
    feature = "transport-link-tls",
    feature = "transport-link-quic",
    feature = "tls-mbedtls"
))]
pub(crate) fn resolve_tls_config(cfg: &ConfigState) -> Result<CapiTlsConfig, ZResult> {
    let enable_mtls = cfg.get(Z_CONFIG_TLS_ENABLE_MTLS_KEY) == Some("true");
    // The mTLS material is read only when mTLS is ON. pico gates its own
    // insertion the same way (`if (enable_mtls)`), so reading it unconditionally
    // would make wz present a client cert in a configuration where pico does not.
    let (connect_cert_pem, connect_key_pem) = if enable_mtls {
        (
            resolve_pem(
                cfg,
                Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY,
                Z_CONFIG_TLS_CONNECT_CERTIFICATE_BASE64_KEY,
            )?,
            resolve_pem(
                cfg,
                Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY,
                Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_BASE64_KEY,
            )?,
        )
    } else {
        (None, None)
    };
    Ok(CapiTlsConfig {
        root_ca_pem: resolve_pem(
            cfg,
            Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY,
            Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY,
        )?,
        verify_name_on_connect: cfg.get(Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY) == Some("true"),
        connect_cert_pem,
        connect_key_pem,
        listen_cert_pem: resolve_pem(
            cfg,
            Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY,
            Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY,
        )?,
        listen_key_pem: resolve_pem(
            cfg,
            Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY,
            Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY,
        )?,
        require_client_auth: enable_mtls,
    })
}

/// The no-TLS-backend build: no certificate can reach a consumer, so the
/// cert-free config is the honest resolution. The keys still PARSE into the
/// config map (`zp_config_insert` is scheme-agnostic), which is what keeps a
/// program written against the full key set compiling and running here — it just
/// cannot open a `tls/` endpoint, and the runtime says so at bind/dial.
#[cfg(all(
    feature = "engine-tokio",
    not(any(
        feature = "transport-link-tls",
        feature = "transport-link-quic",
        feature = "tls-mbedtls"
    ))
))]
pub(crate) fn resolve_tls_config(_cfg: &ConfigState) -> Result<CapiTlsConfig, ZResult> {
    Ok(CapiTlsConfig::default())
}

/// The files [`resolve_tls_config`] reads: each of its keys that names the PEM by path, the
/// client certificate's two only when mTLS is on, as it reads them. Read by
/// `wz_ext_config_device_requires` only, so it is part of the unstable surface.
#[cfg(all(
    feature = "unstable-api",
    any(
        feature = "transport-link-tls",
        feature = "transport-link-quic",
        feature = "tls-mbedtls"
    )
))]
pub(crate) fn tls_files_named(cfg: &ConfigState) -> Vec<String> {
    let mut keys = vec![
        Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY,
        Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY,
        Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY,
    ];
    if cfg.get(Z_CONFIG_TLS_ENABLE_MTLS_KEY) == Some("true") {
        keys.extend([
            Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY,
            Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY,
        ]);
    }
    keys.into_iter()
        .filter_map(|key| cfg.get(key).map(str::to_owned))
        .collect()
}

/// The no-TLS-backend build reads no certificate file.
#[cfg(all(
    feature = "unstable-api",
    not(any(
        feature = "transport-link-tls",
        feature = "transport-link-quic",
        feature = "tls-mbedtls"
    ))
))]
pub(crate) fn tls_files_named(_cfg: &ConfigState) -> Vec<String> {
    Vec::new()
}

// --- ABI structs (session owned = pico rc `{ void* _val; void* _cnt }`) ----

/// Owned session (pico `z_owned_session_t`, 16 B rc). `_val` carries the place of our
/// [`PicoSessionHandle`]: on the tokio engine an object of its own, on the cooperative engine a
/// place in the session's arena (`crate::session_place`); `_cnt` is unused.
#[repr(C)]
pub struct z_owned_session_t {
    pub(crate) _val: *mut c_void,
    pub(crate) _cnt: *mut c_void,
}

/// Loaned session (pico `z_loaned_session_t`), same 16 B layout.
#[repr(C)]
pub struct z_loaned_session_t {
    pub(crate) _val: *mut c_void,
    pub(crate) _cnt: *mut c_void,
}

/// Moved session (pico `z_moved_session_t`).
#[repr(C)]
pub struct z_moved_session_t {
    pub(crate) _this: z_owned_session_t,
}

impl z_owned_session_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            _val: core::ptr::null_mut(),
            _cnt: core::ptr::null_mut(),
        }
    }
}

/// What a session's report of its memory is computed from (`crate::session_memory`): `limits`,
/// the snapshot the open resolved from the config and hands the engine, how many links the session
/// may hold by what it listens on, and the numbers its links are opened with from that snapshot,
/// `tx_queue` and what `pico_link_rx` and `pico_unicast_batch` read. The report is of the
/// session the program holds, so it is never read from the build's values.
#[cfg(feature = "session-memory")]
fn memory_basis(
    listen: Option<&str>,
    tx_queue: &TxQueueConf,
    limits: &SessionLimits,
) -> crate::session_memory::MemoryBasis {
    let rx = pico_link_rx(limits);
    crate::session_memory::MemoryBasis {
        limits: *limits,
        links: crate::session_memory::links_of(listen, limits),
        queue_batches: tx_queue.sizes.iter().sum(),
        batch_bytes: usize::from(pico_unicast_batch(limits)),
        rx_bytes: rx.buffer_size,
        // `pico_link_rx` hands the engine `usize::MAX` where the snapshot states no bound.
        message_bytes: limits.pico_frag_max_bytes().most(),
    }
}

/// The session as the handle holds it. The tokio engine boxes its session out of line so that the
/// session's drop glue stays in that engine's crate (`SessionState::into_drive`); the cooperative
/// engine hands its own `Arc`, which the handle keeps by value, so its open makes no box for it,
/// and it is the engine's own type: the one engine of the build, or with `app-transport` either of
/// the two the build opens ([`PicoDrive`]).
#[cfg(feature = "engine-tokio")]
pub(crate) type HeldDrive = Box<dyn wz_capi_port::SessionDrive>;
#[cfg(all(not(feature = "engine-tokio"), not(feature = "app-transport")))]
pub(crate) type HeldDrive = wz_capi_coop::CoopDrive<HostLinks, SessionClockOf>;
#[cfg(all(not(feature = "engine-tokio"), feature = "app-transport"))]
pub(crate) type HeldDrive = PicoDrive;

/// The clock a cooperative session runs on: the program's time base where the build takes one,
/// which may also be the host's (`crate::time_base::SessionClock`), else the host's.
#[cfg(all(not(feature = "engine-tokio"), feature = "time-base"))]
pub(crate) type SessionClockOf = crate::time_base::SessionClock;
#[cfg(all(not(feature = "engine-tokio"), not(feature = "time-base")))]
pub(crate) type SessionClockOf = crate::coop_host::Clock;

/// The host's links, over a secure channel where the build has one.
#[cfg(all(not(feature = "engine-tokio"), feature = "tls-mbedtls"))]
type SecuredLinks = <crate::coop_host::Links as wz_capi_coop::ComposedLinks>::WithTls<
    wz_capi_coop::tls::HostTls<crate::coop_host::TcpDial, SessionClockOf>,
>;
#[cfg(all(not(feature = "engine-tokio"), not(feature = "tls-mbedtls")))]
type SecuredLinks = crate::coop_host::Links;

/// The links a cooperative session opens over the host's sockets, as [`open_on_coop`] composes
/// them: the host's, over a secure channel and joining groups where the build does either.
#[cfg(all(not(feature = "engine-tokio"), feature = "multicast-transport"))]
pub(crate) type HostLinks = <SecuredLinks as wz_capi_coop::ComposedLinks>::WithGroups<
    wz_capi_coop::host_group::HostGroups<crate::coop_host::Multicast>,
>;
#[cfg(all(not(feature = "engine-tokio"), not(feature = "multicast-transport")))]
pub(crate) type HostLinks = SecuredLinks;

/// The session of a build that opens over the host's sockets or the program's transport: one of
/// two engines, a closed set, each held as its own type and reached by a match, not through a
/// table of functions.
#[cfg(all(not(feature = "engine-tokio"), feature = "app-transport"))]
pub(crate) enum PicoDrive {
    /// Over the host's sockets.
    Host(wz_capi_coop::CoopDrive<HostLinks, SessionClockOf>),
    /// Over the program's transport.
    App(wz_capi_coop::CoopDrive<wz_capi_coop::app_link::AppLinks, SessionClockOf>),
}

#[cfg(all(not(feature = "engine-tokio"), feature = "app-transport"))]
impl PicoDrive {
    /// The engine the session's entities keep.
    pub(crate) fn engine(&self) -> alloc::sync::Arc<Engine> {
        match self {
            Self::Host(drive) => drive.engine(),
            Self::App(drive) => drive.engine(),
        }
    }

    /// The engine, borrowed for the length of one call.
    pub(crate) fn engine_ref(&self) -> &Engine {
        match self {
            Self::Host(drive) => drive.engine_ref(),
            Self::App(drive) => drive.engine_ref(),
        }
    }

    /// The place the session's arena lent the handle.
    pub(crate) fn handle_place(&self) -> Option<wz_capi_coop::arena::HandlePlace> {
        match self {
            Self::Host(drive) => drive.handle_place(),
            Self::App(drive) => drive.handle_place(),
        }
    }

    /// The session's own zid, zero-padded to 16 bytes.
    pub(crate) fn zid(&self) -> [u8; 16] {
        match self {
            Self::Host(drive) => drive.zid(),
            Self::App(drive) => drive.zid(),
        }
    }

    /// Close the session.
    pub(crate) fn close(&self) {
        match self {
            Self::Host(drive) => drive.close(),
            Self::App(drive) => drive.close(),
        }
    }

    /// Whether the session is closed.
    pub(crate) fn is_closed(&self) -> bool {
        match self {
            Self::Host(drive) => drive.is_closed(),
            Self::App(drive) => drive.is_closed(),
        }
    }

    /// Start the read task.
    #[cfg(feature = "multi-thread")]
    pub(crate) fn start_read_task(&self) -> Result<(), ReadTaskStartRefused> {
        match self {
            Self::Host(drive) => drive.start_read_task(),
            Self::App(drive) => drive.start_read_task(),
        }
    }

    /// Stop the read task.
    #[cfg(feature = "multi-thread")]
    pub(crate) fn stop_read_task(&self) -> Result<(), wz_capi_port::CalledFromReadTask> {
        match self {
            Self::Host(drive) => drive.stop_read_task(),
            Self::App(drive) => drive.stop_read_task(),
        }
    }

    /// Whether the read task runs.
    #[cfg(feature = "multi-thread")]
    pub(crate) fn read_task_is_running(&self) -> bool {
        match self {
            Self::Host(drive) => drive.read_task_is_running(),
            Self::App(drive) => drive.read_task_is_running(),
        }
    }

    /// Read what the session's links hold.
    #[cfg(not(feature = "multi-thread"))]
    pub(crate) fn read(&self, single: bool) -> Result<(), wz_capi_port::SessionClosed> {
        match self {
            Self::Host(drive) => drive.read(single),
            Self::App(drive) => drive.read(single),
        }
    }

    /// Send a keep-alive on each link.
    #[cfg(not(feature = "multi-thread"))]
    pub(crate) fn send_keep_alive(&self) -> Result<(), wz_capi_port::SessionClosed> {
        match self {
            Self::Host(drive) => drive.send_keep_alive(),
            Self::App(drive) => drive.send_keep_alive(),
        }
    }

    /// Run one turn of the session's work.
    #[cfg(not(feature = "multi-thread"))]
    pub(crate) fn spin_once(&self) -> bool {
        match self {
            Self::Host(drive) => drive.spin_once(),
            Self::App(drive) => drive.spin_once(),
        }
    }
}

/// What a C session handle points at: the engine's session, behind the port, and what this ABI
/// keeps per session itself (`docs/capi-pico-on-coop-engine.md`, decision D7).
pub(crate) struct PicoSessionHandle {
    /// The session as the engine runs it, made by the engine (`into_drive`).
    pub(crate) drive: HeldDrive,
    /// The session's role, clock, connectivity listeners and admin space.
    pub(crate) ext: crate::session_ext::PicoSessionExt,
    /// The release latches of the closures the program declared with no handle to undeclare them
    /// by (`z_declare_background_*`), and of the gets it issued. A close waits on them, as an
    /// undeclare waits on its own.
    background: crate::ffi::LatchList,
    /// What the session's report of its memory is computed from, as its open decided it.
    #[cfg(feature = "session-memory")]
    pub(crate) memory: crate::session_memory::MemoryBasis,
}

impl PicoSessionHandle {
    pub(crate) fn new(drive: HeldDrive, ext: crate::session_ext::PicoSessionExt) -> Self {
        Self {
            drive,
            ext,
            background: crate::ffi::LatchList::default(),
            #[cfg(feature = "session-memory")]
            memory: crate::session_memory::MemoryBasis::default(),
        }
    }

    /// The handle, its memory reported from `memory`.
    #[cfg(feature = "session-memory")]
    fn with_memory(mut self, memory: crate::session_memory::MemoryBasis) -> Self {
        self.memory = memory;
        self
    }

    /// Whether the session has been closed. A declaration or a get made after it is refused with
    /// `_Z_ERR_SESSION_CLOSED`, and the closure the call consumed runs its `drop(context)`.
    pub(crate) fn is_closed(&self) -> bool {
        self.drive.is_closed()
    }

    /// Keep the latch of a closure with no handle to undeclare it by, for the close to wait on.
    pub(crate) fn keep_background(&self, latch: alloc::sync::Arc<crate::ffi::ReleaseLatch>) {
        self.background.keep(latch);
    }

    /// Block until every such closure has run its `drop(context)`.
    fn wait_background(&self) {
        self.background.wait_all();
    }
}

#[cfg(feature = "engine-tokio")]
impl PicoSessionHandle {
    /// The tokio engine's session, for a capability the port does not carry yet; `None` when
    /// another engine runs it.
    pub(crate) fn tokio(&self) -> Option<&SessionState> {
        self.drive.as_any().downcast_ref::<SessionState>()
    }
}

/// Read the [`PicoSessionHandle`] behind a loaned session, or `None` if the pointer or its
/// handle slot is null.
///
/// # Safety
/// `zs` must be null, or a valid `z_loaned_session_t` whose `_val` slot is a live
/// `PicoSessionHandle` handle (what [`z_open`] installs).
pub(crate) unsafe fn session_handle<'a>(
    zs: *const z_loaned_session_t,
) -> Option<&'a PicoSessionHandle> {
    if zs.is_null() {
        return None;
    }
    let val = (*zs)._val;
    if val.is_null() {
        return None;
    }
    held_at(val)
}

/// The place a cooperative session's handle lies in, a span of the session's arena.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) type SessionPlace = crate::session_place::HeldPlace<PicoSessionHandle>;

#[cfg(not(feature = "engine-tokio"))]
const _: () = assert!(
    SessionPlace::LAYOUT.align() <= wz_session_core::bounded::ARENA_ALIGN,
    "the handle's place starts where a span of the arena does"
);

/// The handle at `val`, a place [`z_open`] filled.
///
/// # Safety
/// `val` is the `_val` of an owned session [`z_open`] made, whose memory still stands.
#[cfg(feature = "engine-tokio")]
unsafe fn held_at<'a>(val: *mut c_void) -> Option<&'a PicoSessionHandle> {
    Some(&*(val as *const PicoSessionHandle))
}

/// The handle at `val`, while its place still holds it: a copy of the owned session kept past
/// `z_session_drop` finds the place vacant.
///
/// # Safety
/// As the tokio engine's twin.
#[cfg(not(feature = "engine-tokio"))]
unsafe fn held_at<'a>(val: *mut c_void) -> Option<&'a PicoSessionHandle> {
    (*(val as *const SessionPlace)).held()
}

/// Let go of the handle at `val`, which closes its session.
///
/// # Safety
/// `val` is the `_val` of an owned session [`z_open`] made, given up by its owner.
#[cfg(feature = "engine-tokio")]
unsafe fn release_handle(val: *mut c_void) {
    crate::object_slot::release(val as *mut PicoSessionHandle);
}

/// Let go of the handle at `val`, which closes its session. The handle is moved out of its place
/// before it is dropped: its drive may hold the session's last hold, whose drop gives back the
/// arena the place lies in. A place already vacant (a copy dropped twice) lets go of nothing.
///
/// # Safety
/// As the tokio engine's twin, and the session's memory still stands.
#[cfg(not(feature = "engine-tokio"))]
unsafe fn release_handle(val: *mut c_void) {
    drop(SessionPlace::take(val as *mut SessionPlace));
}

/// Read the tokio engine's [`SessionState`] behind a loaned session, or `None` if the pointer or
/// its handle slot is null, or another engine runs the session.
///
/// For the modules of the capabilities the port does not carry yet (scouting, the advanced
/// plane); the client surface goes through the session's handle and the port.
///
/// Lives here, beside BOTH types it touches ([`SessionState`] and
/// [`z_loaned_session_t`]), because every module that reaches a session needs
/// it: `pubsub` and `query` each carried a byte-identical private copy until
/// R311y294 folded them into this one.
///
/// # Safety
/// `zs` must be null, or a valid `z_loaned_session_t` whose `_val` slot is null or the live
/// handle [`z_open`] installed.
#[cfg(feature = "engine-tokio")]
pub unsafe fn session_state<'a>(zs: *const z_loaned_session_t) -> Option<&'a SessionState> {
    session_handle(zs)?.tokio()
}

/// The engine a session's client surface goes through: the port's [`SessionEngine`], so the
/// modules that publish, subscribe, hold key expressions, watch for matches and filter writes
/// name no engine (`docs/capi-pico-on-coop-engine.md`, decision D1).
///
/// [`SessionEngine`]: wz_capi_port::SessionEngine
#[cfg(any(feature = "engine-tokio", feature = "app-transport"))]
pub(crate) type Engine = dyn wz_capi_port::SessionEngine;
/// A build of one engine reaches it as its own type, every call to it resolved when the build is
/// made: no table of its functions is made, so the operations the build never calls are not linked.
#[cfg(all(not(feature = "engine-tokio"), not(feature = "app-transport")))]
pub(crate) type Engine = wz_capi_coop::CoopEngine<HostLinks, SessionClockOf>;

/// The engine behind a session handle, to keep: what an entity declared on the session holds for
/// its own life. The engine hands itself out, so this crate never turns an engine's own type into
/// the port's, which would instantiate the engine's drop glue a second time here.
pub(crate) fn engine_of(handle: &PicoSessionHandle) -> alloc::sync::Arc<Engine> {
    handle.drive.engine()
}

/// The engine behind a session handle, for the length of one call: a put or a delete reaches the
/// engine without touching its reference count.
pub(crate) fn engine_ref(handle: &PicoSessionHandle) -> &Engine {
    handle.drive.engine_ref()
}

/// The engine as the port's trait object, for what serves any engine (the advanced plane's host
/// and its periodic jobs, an open set): a clone of the entity's hold.
#[cfg(feature = "advanced")]
pub(crate) fn port_engine(
    engine: &alloc::sync::Arc<Engine>,
) -> alloc::sync::Arc<dyn wz_capi_port::SessionEngine> {
    engine.clone()
}

// --- z_open / z_close ------------------------------------------------------

/// Open a session, consuming the moved config (pico `z_open`). A `connect`
/// config blocks until Established; a `listen` config returns as soon as the
/// bind succeeds. A config naming neither scouts for the first node that answers
/// and connects to its locators, as pico's `_z_open` does (see
/// `crate::scout::locators_by_scout`); nobody answering, or a build without
/// `scout`, is `Z_ERR_SCOUT_NO_RESULTS`.
///
/// `options->auto_start_read_task` decides whether the session's read task runs
/// from the open, as pico starts its executor only if it is set (default true);
/// without it the session is connected or bound and reads nothing until
/// `zp_start_read_task`. With `admin-space`, `options->auto_start_admin_space`
/// starts the admin space once the session is open, and a start that fails
/// drops the session and returns its error, as pico's `z_open` does
/// (`vendor/zenoh-pico/src/api/api.c` @ `if (opts.auto_start_admin_space) {`).
/// The rest of the options have no effect here: the lease flag is never read by
/// pico either, and the thread attributes have nothing to apply to.
///
/// Without `multi-thread` the options carry no read-task flag, and the session reads
/// from the open: pico's single-threaded program advances its session with `zp_read`
/// and `zp_spin_once`, which a wz session does on its own runtime.
#[no_mangle]
pub unsafe extern "C" fn z_open(
    zs: *mut z_owned_session_t,
    config: *mut z_moved_config_t,
    options: *const z_open_options_t,
) -> ZResult {
    guarded(|| {
        // What the config and the options ask for is read in a frame of its own, which has
        // returned before the engine opens the session (`open_request`).
        let request = match open_request(zs, config, options) {
            Ok(request) => request,
            Err(code) => return code,
        };
        #[cfg(feature = "engine-tokio")]
        return open_on_tokio(zs, request);
        #[cfg(not(feature = "engine-tokio"))]
        return open_on_coop(zs, request);
    })
}

/// What [`z_open`] reads off the moved config and its options, or the code `z_open` answers when
/// it refuses them: `*zs` is written null before anything fallible, and the config is consumed.
/// Never inlined, for the stack: the config's state, its resolved snapshots and a scout for a
/// locator lie in this frame, which has returned before the session is opened, so none of them is
/// under the open's handshake.
///
/// # Safety
/// As [`z_open`]'s: `zs`, `config` and `options` are each null or valid.
#[inline(never)]
unsafe fn open_request(
    zs: *mut z_owned_session_t,
    config: *mut z_moved_config_t,
    options: *const z_open_options_t,
) -> Result<OpenRequest, ZResult> {
    if zs.is_null() || config.is_null() {
        return Err(Z_ERR_NULL);
    }
    // pico reads the options only when they are given and otherwise takes
    // `z_open_options_default`, whose read task starts.
    #[cfg(feature = "multi-thread")]
    let start_read_task = options.is_null() || (*options).auto_start_read_task;
    #[cfg(not(feature = "multi-thread"))]
    let start_read_task = {
        // Read only for the admin-space flag, which a build may not have.
        let _ = options;
        true
    };
    // And its admin space does not start unless asked to.
    #[cfg(feature = "admin-space")]
    let start_admin_space = !options.is_null() && (*options).auto_start_admin_space;
    // Always-initialize the out-param (pico contract) before any fallible
    // work, so a caller reading `*zs` on an error path sees a null session.
    *zs = z_owned_session_t::null_value();
    let cfg_handle = (*config)._this.handle;
    if cfg_handle.is_null() {
        return Err(Z_ERR_NULL);
    }
    // z_open consumes the config: take ownership and null the source so a
    // defensive later `z_config_drop` is a safe no-op.
    let cfg = Box::from_raw(cfg_handle as *mut ConfigState);
    (*config)._this = z_owned_config_t::null_value();

    let open = open_config(&cfg)?;
    // The id the session opens on, refused here if the config names one pico's reader cannot
    // take (see [`session_zid`]).
    let zid = session_zid(&open)?;
    let OpenConfig {
        connect,
        listen,
        dial_whatami,
        zid: _,
    } = open;
    // A config that carries the program's transport opens every link on it, so a locator the
    // transport does not carry, and an open that would scout on the system's sockets, are
    // refused here, before anything is opened.
    #[cfg(feature = "app-transport")]
    let app_transport = cfg.transport.clone();
    #[cfg(feature = "app-transport")]
    if app_transport.is_some() {
        if let Some(code) =
            crate::app_transport::refused_open(connect.as_deref(), listen.as_deref())
        {
            return Err(code);
        }
    }
    // R311y406 / R311y534 — the TLS material, RESOLVED here (path or inline
    // base64 -> PEM bytes) because the key numbers are this ABI's knowledge.
    // A malformed value fails the open rather than degrading to a plaintext
    // or trust-free session: a caller that asked for TLS and silently got
    // something else is the one outcome worse than a failed z_open.
    #[cfg(any(feature = "engine-tokio", feature = "tls-mbedtls"))]
    let tls = resolve_tls_config(&cfg)?;
    // The connect locators: the configured one, or with neither locator configured the
    // first scouted node's (`vendor/zenoh-pico/src/net/session.c` @
    // `ret = _z_locators_by_scout(config, zid, &connect_locators);`), whose build without
    // scouting answers `_Z_ERR_SCOUT_NO_RESULTS`. A session that is re-dialled after it
    // lost its link dials the locators found here again. pico re-runs the whole open,
    // scouting included (`_z_client_reopen_task_fn` calls `_z_open`), so a router that
    // comes back on another locator is found there and not here. The scout runs under the
    // snapshot of the open it finds a node for, and a config whose policies or limits the
    // build refuses opens nothing and scouts for nothing.
    let (policy, limits) = resolve_snapshots(&cfg.policies)?;
    // The key-wire form, judged for the engine the session opens on, and the key ids every
    // node shares that the config states (`crate::key_ids`).
    #[cfg(feature = "shared-key-ids")]
    let key_ids = crate::key_ids::admit_at_open(&cfg, &policy, &limits)?;
    #[cfg(not(feature = "shared-key-ids"))]
    crate::key_ids::admit_at_open(&cfg, &policy)?;
    #[cfg(not(feature = "engine-tokio"))]
    let key_ids = crate::key_ids::coop_key_ids(
        #[cfg(feature = "shared-key-ids")]
        key_ids,
    );
    let connect: Vec<String> = match (connect, &listen) {
        (Some(connect), _) => vec![connect],
        (None, Some(_)) => Vec::new(),
        #[cfg(any(feature = "scout", feature = "scout-mcu"))]
        (None, None) => crate::scout::locators_by_scout(&cfg, &policy, &limits)?,
        #[cfg(not(any(feature = "scout", feature = "scout-mcu")))]
        (None, None) => return Err(crate::result::Z_ERR_SCOUT_NO_RESULTS),
    };
    // The time base the config names, which the session holds from here on.
    #[cfg(feature = "time-base")]
    let time_base = cfg.time_base.clone();
    drop(cfg);
    // A build without the `peer` feature is a client build: it opens to the endpoint it is
    // given, and a listener or `mode=peer` is a role it does not have. (zenoh-pico's own
    // `Z_FEATURE_UNICAST_PEER` gates less: a build without it still takes a lone listener,
    // refusing only the combined listen and connect and a second connect locator. This
    // feature is the stronger cut, for a device that only ever dials out.)
    #[cfg(not(feature = "peer"))]
    if listen.is_some() || dial_whatami != WhatAmI::Client {
        return Err(crate::result::Z_ERR_INVALID);
    }
    // A config carrying BOTH connect and listen is pico's dual-role listen-and-dial peer:
    // `_z_locators_by_config` refuses the pair only in a build without unicast peers and
    // otherwise forces the mode to peer for any listen config and goes on
    // (`vendor/zenoh-pico/src/net/session.c` @ `static z_result_t _z_locators_by_config(`).
    // The core runs it (a listener bound before the dial, an accept loop beside the dial
    // face), so it is not refused. Until R3090 it was, with `Z_ERR_INVALID`, and the comment
    // called it a follow-up. Its role is a peer's: `open_config` reads a listen config so.
    // On the tokio engine the handle's place is taken before anything opens, so a full pool
    // refuses the open and the open leaves nothing behind. The cooperative engine's arena holds
    // it, reserved with the rest of the session before anything is bound or dialled.
    #[cfg(feature = "engine-tokio")]
    let Some(slot) = crate::object_slot::Slot::take(crate::object_slot::Kind::Session) else {
        return Err(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY);
    };
    Ok(OpenRequest {
        #[cfg(feature = "engine-tokio")]
        slot,
        connect,
        listen,
        dial_whatami,
        zid,
        start_read_task,
        #[cfg(feature = "admin-space")]
        start_admin_space,
        #[cfg(any(feature = "engine-tokio", feature = "tls-mbedtls"))]
        tls,
        policy,
        limits,
        #[cfg(feature = "app-transport")]
        app_transport,
        #[cfg(any(not(feature = "engine-tokio"), feature = "shared-key-ids"))]
        key_ids,
        #[cfg(feature = "time-base")]
        time_base,
    })
}

/// What a config tells pico's open, read once for [`z_open`] and for the door that describes the
/// open (`wz_ext_config_device_requires`), so the two cannot read a config differently: the
/// locator it dials, the one it listens on, and the role it dials as.
pub(crate) struct OpenConfig {
    pub(crate) connect: Option<String>,
    pub(crate) listen: Option<String>,
    pub(crate) dial_whatami: WhatAmI,
    /// The text of `Z_CONFIG_SESSION_ZID_KEY`, if the config states one: the id the session opens
    /// on. Read by [`session_zid`], which says whether pico's reader could take it.
    pub(crate) zid: Option<String>,
}

/// The id the session opens on: the one `Z_CONFIG_SESSION_ZID_KEY` names, and `None` when the
/// config states none, which is the session minting its own as pico's does
/// (`vendor/zenoh-pico/src/api/api.c` @ `_z_session_generate_zid(&zid, Z_ZID_LENGTH);`).
///
/// The id is returned as the bytes an INIT carries (the sixteen of the UUID, up to the last
/// non-zero one). A key whose text pico's reader (`_z_uuid_to_bytes`) cannot take is an `Err`:
/// pico reads whatever its fixed indexes land on, so what it opens as is not an id the caller
/// named, and a caller that stated an id and silently got another is worse off than one whose
/// open failed, as with the TLS keys.
pub(crate) fn session_zid(open: &OpenConfig) -> Result<Option<Vec<u8>>, ZResult> {
    stated_zid(open.zid.as_deref()).map(|zid| zid.map(|zid| zid.to_vec()))
}

/// The id the text of `Z_CONFIG_SESSION_ZID_KEY` names, `None` when the config states none, and
/// `Z_ERR_INVALID` for text pico's reader cannot take, as [`session_zid`] reads it. `z_scout`
/// reads the key through this too, so a Scout names the node a later open stands on and is
/// refused the id the open is refused.
pub(crate) fn stated_zid(text: Option<&str>) -> Result<Option<SessionZid>, ZResult> {
    match text {
        None => Ok(None),
        Some(text) => pico_uuid_wire(text)
            .and_then(|wire| SessionZid::new(&wire).ok())
            .map(Some)
            .ok_or(crate::result::Z_ERR_INVALID),
    }
}

/// The wire form of the id zenoh-pico's `Z_CONFIG_SESSION_ZID_KEY` names, or `None` for text it
/// cannot take.
///
/// pico reads the key with `_z_uuid_to_bytes` (`vendor/zenoh-pico/src/utils/uuid.c` @
/// `void _z_uuid_to_bytes(`): a UUID, `8-4-4-4-12` hex digits, whose sixteen bytes become the id
/// IN THE ORDER WRITTEN, and not the `u128` text zenoh's own `id` key and `z_id_to_string` use.
/// Text of any other shape is read by pico as whatever its fixed indexes land on past the end of
/// the string, so what it makes of it is not an id anyone named: this takes the one shape the
/// reader was written for and refuses the rest, and an id of sixteen zero bytes, which zenoh
/// refuses.
fn pico_uuid_wire(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if digits.len() != 36 {
        return None;
    }
    let mut bytes = [0u8; 16];
    let mut at = 0;
    for (i, byte) in bytes.iter_mut().enumerate() {
        // The dashes come before the 5th, 7th, 9th and 11th byte (`i == 8, 12, 16, 18` over the
        // hex digits in pico's loop).
        if matches!(i, 4 | 6 | 8 | 10) {
            if digits[at] != b'-' {
                return None;
            }
            at += 1;
        }
        let hi = (digits[at] as char).to_digit(16)?;
        let lo = (digits[at + 1] as char).to_digit(16)?;
        *byte = ((hi << 4) | lo) as u8;
        at += 2;
    }
    // Written up to the last non-zero byte, as zenoh writes an id.
    let length = bytes.iter().rposition(|byte| *byte != 0)? + 1;
    Some(bytes[..length].to_vec())
}

#[cfg(test)]
mod zid_tests {
    use super::pico_uuid_wire;

    /// What zenoh-pico's `Z_CONFIG_SESSION_ZID_KEY` names: a UUID whose sixteen bytes are the id in
    /// the order written (`_z_uuid_to_bytes`), the first byte first, so `ff...` is a HIGH id and
    /// `01...` a low one, which `z_id_to_string` would print the other way round.
    #[test]
    fn a_uuid_names_the_id_in_the_order_written() {
        let high = pico_uuid_wire("ff000000-0000-0000-0000-000000000001").expect("sixteen bytes");
        assert_eq!(high[0], 0xff, "the first byte written is the first byte");
        assert_eq!(
            high.len(),
            16,
            "the last byte is not zero, so none is trimmed"
        );
        assert_eq!(
            pico_uuid_wire("01020304-0506-0708-090a-0b0c0d0e0f10").expect("sixteen bytes"),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        // Trailing zero bytes are trimmed from the wire form, as zenoh writes an id.
        assert_eq!(
            pico_uuid_wire("aabbccdd-eeff-0000-0000-000000000000").expect("six bytes and zeros"),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    /// Text that is not the UUID shape pico's reader indexes is refused, where pico reads whatever
    /// its fixed indexes land on, and so is an id of zero bytes, which zenoh refuses.
    #[test]
    fn text_that_is_not_a_uuid_names_no_id() {
        for text in [
            "",
            "ff000000000000000000000000000001",
            "ff000000-0000-0000-0000-00000000000",
            "ff000000-0000-0000-0000-0000000000011",
            "ff000000_0000-0000-0000-000000000001",
            "ff00000-00000-0000-0000-000000000001",
            "gf000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(
                pico_uuid_wire(text).is_none(),
                "`{text}` is not an id pico's reader was written for"
            );
        }
    }
}

/// Read [`OpenConfig`] off `cfg`, refusing a mode pico refuses.
///
/// The dial role's whatami is the config's mode, as pico's `_z_config_get_mode` reads it: none or
/// `client` opens a client, `peer` a peer, and any other value, `router` among them, is refused
/// with `_Z_ERR_CONFIG_INVALID_MODE` (`vendor/zenoh-pico/src/net/session.c` @
/// `ret = _Z_ERR_CONFIG_INVALID_MODE;`): pico has no router role. A config with a listen locator
/// is a peer whatever its mode said, because pico writes `peer` over the mode before it reads it
/// (`vendor/zenoh-pico/src/net/session.c` @
/// `_zp_config_insert(config, Z_CONFIG_MODE_KEY, Z_CONFIG_MODE_PEER);`), so its mode is never
/// refused.
pub(crate) fn open_config(cfg: &ConfigState) -> Result<OpenConfig, ZResult> {
    let listen = cfg.get(Z_CONFIG_LISTEN_KEY).map(str::to_owned);
    let dial_whatami = match cfg.get(Z_CONFIG_MODE_KEY) {
        _ if listen.is_some() => WhatAmI::Peer,
        None | Some("client") => WhatAmI::Client,
        Some("peer") => WhatAmI::Peer,
        Some(_) => return Err(crate::result::Z_ERR_CONFIG_INVALID_MODE),
    };
    Ok(OpenConfig {
        connect: cfg.get(Z_CONFIG_CONNECT_KEY).map(str::to_owned),
        listen,
        dial_whatami,
        zid: cfg.get(Z_CONFIG_SESSION_ZID_KEY).map(str::to_owned),
    })
}

#[cfg(test)]
mod open_config_tests {
    use super::{open_config, ConfigState, WhatAmI, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY};
    use crate::result::Z_ERR_CONFIG_INVALID_MODE;

    fn config(entries: &[(u8, &str)]) -> ConfigState {
        let mut cfg = ConfigState::default();
        for (key, value) in entries {
            cfg.insert(*key, value);
        }
        cfg
    }

    fn role(entries: &[(u8, &str)]) -> Result<WhatAmI, i8> {
        open_config(&config(entries)).map(|open| open.dial_whatami)
    }

    /// zenoh-pico has no router role: its open refuses `mode=router` with
    /// `_Z_ERR_CONFIG_INVALID_MODE` (-90), and so does this ABI.
    #[test]
    fn the_router_mode_is_refused_as_pico_refuses_it() {
        assert_eq!(Z_ERR_CONFIG_INVALID_MODE, -90);
        assert_eq!(
            role(&[(Z_CONFIG_MODE_KEY, "router")]),
            Err(Z_ERR_CONFIG_INVALID_MODE)
        );
    }

    /// pico compares the mode with `client` and `peer` exactly, so any other text is refused.
    #[test]
    fn a_mode_pico_does_not_know_is_refused() {
        for mode in ["", "Peer", "CLIENT", "gateway", "peer "] {
            assert_eq!(
                role(&[(Z_CONFIG_MODE_KEY, mode)]),
                Err(Z_ERR_CONFIG_INVALID_MODE),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn client_peer_and_no_mode_are_taken() {
        assert_eq!(role(&[]), Ok(WhatAmI::Client));
        assert_eq!(role(&[(Z_CONFIG_MODE_KEY, "client")]), Ok(WhatAmI::Client));
        assert_eq!(role(&[(Z_CONFIG_MODE_KEY, "peer")]), Ok(WhatAmI::Peer));
    }

    /// pico writes `peer` over the mode of a config that listens before it reads the mode, so a
    /// listener is a peer and its mode, whatever it said, is never refused.
    #[test]
    fn a_listening_config_is_a_peer_whatever_its_mode() {
        for mode in [None, Some("client"), Some("router")] {
            let mut entries = vec![(Z_CONFIG_LISTEN_KEY, "tcp/127.0.0.1:7447")];
            if let Some(mode) = mode {
                entries.push((Z_CONFIG_MODE_KEY, mode));
            }
            assert_eq!(role(&entries), Ok(WhatAmI::Peer), "{mode:?}");
        }
    }
}

/// What `z_open` read off the C config and its options, for the engine that opens it.
struct OpenRequest {
    /// The place the session's handle is installed in, taken before anything is opened.
    #[cfg(feature = "engine-tokio")]
    slot: crate::object_slot::Slot<PicoSessionHandle>,
    connect: Vec<String>,
    listen: Option<String>,
    dial_whatami: WhatAmI,
    /// The id the config names for the session, as the bytes an INIT carries, `None` for one the
    /// engine mints.
    zid: Option<Vec<u8>>,
    // The cooperative engine's single-threaded arm starts no read task: the program steps it.
    #[cfg_attr(
        all(not(feature = "engine-tokio"), not(feature = "multi-thread")),
        allow(dead_code)
    )]
    start_read_task: bool,
    #[cfg(feature = "admin-space")]
    start_admin_space: bool,
    /// The TLS material the config's keys name, resolved to PEM bytes: the tokio engine builds
    /// rustls configs from it, the cooperative engine the Mbed TLS channel's dial and listen.
    #[cfg(any(feature = "engine-tokio", feature = "tls-mbedtls"))]
    tls: CapiTlsConfig,
    /// The policies the session runs under ([`resolve_snapshots`]), handed to the engine and kept
    /// with the session's handle.
    policy: SessionPolicy,
    /// The session limits the session runs under, resolved with [`Self::policy`]: the engine's
    /// tables are held to them, whichever engine the session opens on, and the session's handle
    /// keeps them.
    limits: wz_session_core::limits::SessionLimits,
    /// The transport the program supplies, when the config carries one: every link goes over it.
    #[cfg(feature = "app-transport")]
    app_transport: Option<alloc::sync::Arc<wz_session_core::app_transport::AppTransport>>,
    /// The key ids every node of the deployment shares that the config states, and the endpoints
    /// whose key-wire form it states apart, as the engine the session opens on takes them.
    #[cfg(not(feature = "engine-tokio"))]
    key_ids: wz_capi_coop::OpenKeyIds,
    /// See the cooperative engine's twin.
    #[cfg(all(feature = "engine-tokio", feature = "shared-key-ids"))]
    key_ids: wz_session_core::shared_key_ids::KeyIdsAtOpen,
    /// The time base the program supplies, when the config names one: the session's clock.
    #[cfg(feature = "time-base")]
    time_base: Option<wz_node_time::time_base::TimeBaseHold>,
}

/// Open `request` on the tokio engine and install the session in `zs`.
///
/// # Safety
/// `zs` is a valid, null-initialised `z_owned_session_t`.
#[cfg(feature = "engine-tokio")]
unsafe fn open_on_tokio(zs: *mut z_owned_session_t, request: OpenRequest) -> ZResult {
    let OpenRequest {
        slot,
        connect,
        listen,
        dial_whatami,
        zid,
        start_read_task,
        #[cfg(feature = "admin-space")]
        start_admin_space,
        tls,
        policy,
        limits,
        #[cfg(feature = "app-transport")]
        app_transport,
        #[cfg(feature = "shared-key-ids")]
        key_ids,
        #[cfg(feature = "time-base")]
        time_base,
    } = request;
    let (tx_queue, sn_resolution) = pico_link_policy(&policy, &limits);
    #[cfg(feature = "session-memory")]
    let memory = memory_basis(listen.as_deref(), &tx_queue, &limits);
    // This ABI stays on one attempt: the retry the zenoh-c open gained reads
    // zenoh's `connect/retry` and `connect/timeout_ms`, which are zenoh-c
    // config keys, and this shim resolves pico's numeric keys instead.
    // pico's transmit model, not zenoh's: a pico put writes on the
    // caller's thread and a full socket slows it rather than dropping it
    // (see `TxQueueConf::pico_of_snapshot`). zenoh's 1 ms drop wait here discarded the
    // tail of a burst that `teardown_drain` puts before `z_close`.
    let session_mode = if listen.is_some() {
        WhatAmI::Peer
    } else {
        dial_whatami
    };
    // The locator pico's one transport is opened on, which its admin space
    // reports as the transport's link: the listen locator when there is one,
    // the connect locator otherwise (`vendor/zenoh-pico/src/net/session.c` @
    // `// First, try to open the optional listen locator.`).
    #[cfg(feature = "admin-space")]
    let transport_endpoint = listen.clone().or_else(|| connect.first().cloned());
    // Open-debt item 913 — a listen endpoint that names a group is joined as the
    // session's one transport, and a connect locator beside it opens nothing: pico adds a
    // peer to a unicast transport only (`vendor/zenoh-pico/src/transport/manager.c` @
    // `z_result_t _z_new_peer(`, whose other transports fall through). A build without
    // the multicast transport has no link for it, and refuses it as pico's does.
    let joins_a_group = listen.as_deref().is_some_and(is_group_endpoint);
    #[cfg(not(feature = "multicast-transport"))]
    if joins_a_group {
        return crate::result::Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN;
    }
    #[cfg(feature = "multicast-transport")]
    let (listen, connect, groups) = match listen {
        Some(endpoint) if joins_a_group => (
            None,
            Vec::new(),
            vec![wz_capi_port::group::GroupJoin {
                endpoint,
                profile: pico_group(sn_resolution, &limits),
                is_shm: false,
                // pico declares its entities over whatever transport it holds, a group too
                // (MEASURED off the group's wire: `decl_subscriber(1, ..)`), and with
                // `Z_FEATURE_MULTICAST_DECLARATIONS` its keyexprs and write filters as well
                // (MEASURED: `decl_kexpr(1, demo/mc/zp)`, `Interest(3, .., 1:)`).
                #[cfg(not(feature = "multicast-declarations"))]
                declarations: wz_capi_port::group::GroupDeclarations::Entities,
                #[cfg(feature = "multicast-declarations")]
                declarations: wz_capi_port::group::GroupDeclarations::Mapped,
            }],
        ),
        listen => (listen, connect, Vec::new()),
    };
    #[cfg(not(feature = "multicast-transport"))]
    let groups = Vec::new();
    match open_blocking(
        connect.into_iter().collect(),
        // pico's config carries ONE listen locator, so the set is that one or none.
        listen.into_iter().collect(),
        tls,
        dial_whatami,
        // R2948 — pico re-opens a lost client session by default; its handshake bound is
        // pico's (`pico_dial_phase`).
        pico_dial_phase(&limits),
        OpenStance {
            tx_queue,
            // pico's batch size and lease are build switches of its, not config keys
            // (`BATCH_UNICAST_SIZE`, `Z_TRANSPORT_LEASE`): its InitSyn carries
            // `Z_BATCH_UNICAST_SIZE` (`vendor/zenoh-pico/src/protocol/definitions/transport.c` @
            // `msg._body._init._batch_size = Z_BATCH_UNICAST_SIZE;`), 2048 by default and not
            // zenoh's 65535, so this advertises the numbers the open's snapshot holds for them.
            batch_size: pico_unicast_batch(&limits),
            lease_ms: pico_lease_ms(&limits),
            keep_alive: pico_keep_alive(&limits),
            sn_resolution,
            link_rx: pico_link_rx(&limits),
            accept: pico_accept(&limits),
            // pico negotiates no transport capability on unicast: its InitSyn
            // carries the patch ext and nothing else
            // (`vendor/zenoh-pico/src/protocol/codec/transport.c` @
            // `z_result_t _z_init_encode(`), so a drop-in for it offers none.
            offer: wz_capi_core::runtime::session_open::SessionOffer::universal(),
            // The id pico's `Z_CONFIG_SESSION_ZID_KEY` names, or one the session mints
            // (the zenoh-c ABI reads its `id` key into the same place). `pico_uuid_wire` built
            // the bytes, so they are always an id.
            zid: zid
                .as_deref()
                .and_then(wz_capi_core::drive::ConfiguredZid::from_wire),
            start_read_task,
            // pico has no `timestamping` config key, and its advanced publisher
            // never consults this session's clock (its own plane stamps from the
            // device's, `crate::advanced_plane`). The shipped map is what every
            // session of this registry was given before the field existed.
            timestamping: wz_capi_core::runtime::node_clock::TimestampingEnabled::default(),
            // pico has no client storage: its sessions read shared memory through the
            // default reader, as every session did before the field existed.
            shm_clients: wz_capi_core::faces::no_shm_clients(),
            // Without the local switches pico runs a callback only from its background
            // executor, so a delivery the session makes to itself is staged and run there,
            // never inside the call. With them, a session's own put, get and reply reach
            // its own subscribers, queryables and reply callbacks INSIDE the call, on the
            // calling thread (`vendor/zenoh-pico/src/session/loopback.c` @
            // `_z_session_deliver_push_locally`, which hands the message to
            // `_z_handle_network_message` before returning), as zenoh-c's does.
            #[cfg(not(any(feature = "local-subscriber", feature = "local-queryable")))]
            local_delivery: wz_capi_core::runtime::session::LocalDeliveryDrain::DriveTask,
            #[cfg(any(feature = "local-subscriber", feature = "local-queryable"))]
            local_delivery: wz_capi_core::runtime::session::LocalDeliveryDrain::Caller,
            // zenoh-pico tells a liveliness subscriber only of the tokens of its peers
            // (`vendor/zenoh-pico/src/net/liveliness.c` @
            // `_z_keyexpr_intmap_iterator_make(&zn->_remote_tokens)`).
            liveliness_to_self: false,
            // The plan is zenoh's scouting node, which keeps looking and answers Scouts.
            // pico's open looks once, before the open (`connect` above), and its session
            // answers no Scout.
            #[cfg(feature = "scout")]
            scouting: None,
            // zenoh-pico ends its push to every peer link it adds as a PEER, accepted or
            // opened, with that Final (`_z_interest_push_declarations_to_peer`), and none in
            // client mode; the rule the flag turns on only sends from a peer to a peer, which
            // is the pair a zenoh peer's open waits on. R3093 -- it was `false`, and a zenoh
            // peer that dialled this ABI's listener waited out `scouting/delay`.
            initial_interest: true,
            // zenoh-pico has no gossip: its peers are introduced by scouting alone.
            gossip: None,
            // Its one listener's bind failing has always failed the open, at the first attempt.
            listen_phase: wz_capi_core::drive::ListenPhase::SHIPPED,
            // pico's callbacks all run on the session's one read task, and a program
            // written for it shares state between them without a lock.
            face_drive: wz_capi_core::drive::FaceDrive::Serial,
            // pico's config carries no `transport/auth` keys this ABI reads, so its node
            // authenticates nobody, as it always has.
            auth: None,
            // And no `access_control`, `low_pass_filter` or `downsampling` keys either: its
            // node states no traffic policy, as it never has.
            policy: wz_capi_core::node_policy::NodePolicy::default(),
            namespace: None,
            // And no `gateway` key: a pico session has no south to keep apart.
            gateway_south: wz_session_core::region_partition::SouthPartition::Auto,
            // The group its listen endpoint names, when it names one.
            groups,
            // pico's config has no `qos/publication` and no `transport/shared_memory` keys, so
            // its session applies nothing above its links.
            // And the key ids every node shares, when the config states them (`crate::key_ids`),
            // and the time base the program supplies, when the config names one
            // (`crate::time_base`), which the session's clock is made over.
            #[cfg(feature = "shared-key-ids")]
            session_defaults: wz_capi_core::session_defaults::SessionDefaults {
                key_ids,
                #[cfg(feature = "time-base")]
                time_base,
                ..Default::default()
            },
            #[cfg(all(not(feature = "shared-key-ids"), feature = "time-base"))]
            session_defaults: wz_capi_core::session_defaults::SessionDefaults {
                time_base,
                ..Default::default()
            },
            #[cfg(not(any(feature = "shared-key-ids", feature = "time-base")))]
            session_defaults: wz_capi_core::session_defaults::SessionDefaults::default(),
            session_policy: policy,
            session_limits: limits,
            // pico's configuration states no limit of a node, so a node its open runs holds the
            // build's.
            runtime_limits: wz_session_core::limits::RuntimeLimits::defaults(),
            #[cfg(feature = "app-transport")]
            app_transport,
        },
    ) {
        Ok(state) => {
            // R2962 — this session's own role, for the write filters its
            // publishers and queriers create: a client asks its peers
            // differently from a peer (see `crate::write_filter`), and a
            // `listen` config is a peer whatever `Z_CONFIG_MODE_KEY` says.
            // Kept beside the engine's session in the handle (decision D7). It
            // carries the session's connectivity listeners too
            // (`crate::connectivity`), and watches the engine's faces for them
            // from here on.
            let zid = state.zid();
            let drive = state.into_drive();
            #[cfg(feature = "connectivity")]
            let ext = crate::session_ext::PicoSessionExt::new(
                session_mode,
                &zid,
                policy,
                limits,
                &drive.engine(),
            );
            #[cfg(not(feature = "connectivity"))]
            let ext = crate::session_ext::PicoSessionExt::new(session_mode, &zid, policy, limits);
            // The session's own clock, which pico always gives, was refused: the bound
            // `UHLC_MAX_DELTA_MS` states is one it does not honour. The open fails as it does for
            // a stated value the build refuses, after the engine's session is closed.
            #[cfg(any(feature = "advanced", feature = "clock-source"))]
            if ext.clock_refused().is_some() {
                drop(ext);
                drive.close();
                return crate::result::Z_ERR_CONFIG_INVALID_VALUE;
            }
            #[cfg(feature = "admin-space")]
            let ext = ext.with_transport_endpoint(transport_endpoint);
            let handle = PicoSessionHandle::new(drive, ext);
            #[cfg(feature = "session-memory")]
            let handle = handle.with_memory(memory);
            *zs = z_owned_session_t {
                _val: slot.fill(handle) as *mut c_void,
                _cnt: core::ptr::null_mut(),
            };
            #[cfg(feature = "admin-space")]
            if start_admin_space {
                let code = crate::admin_space::zp_start_admin_space(z_session_loan_mut(zs));
                if code != Z_OK {
                    z_session_drop(z_session_move(zs));
                    return code;
                }
            }
            Z_OK
        }
        // R311y498 — the core reports a NEUTRAL failure; this shim maps it
        // onto zenoh-pico's code. The mapping exists precisely because the
        // other ABI's `int8_t` uses different values for the same idea.
        Err(OpenError::DriveFailed) => Z_ERR_GENERIC,
        Err(OpenError::LinkFailed) => crate::result::Z_ERR_TRANSPORT_OPEN_FAILED,
        Err(OpenError::SchemeUnknown) => crate::result::Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
        // The node's clock was refused for the bound `UHLC_MAX_DELTA_MS` states: a stated value
        // the open cannot honour, answered as a refused policy statement is.
        Err(OpenError::ClockRefused(_)) => crate::result::Z_ERR_CONFIG_INVALID_VALUE,
    }
}

/// `links` whose opens wait on the clock of the session they are for: its time base's, for a
/// session on one, so an open the program has not reported up is given up when the program's time
/// passes its bound.
#[cfg(all(
    feature = "app-transport",
    feature = "time-base",
    not(feature = "engine-tokio")
))]
fn app_links_on(
    links: wz_capi_coop::app_link::AppLinks,
    clock: &crate::time_base::SessionClock,
) -> wz_capi_coop::app_link::AppLinks {
    match crate::time_base::open_bound(clock) {
        Some(bound) => links.with_open_bound(bound),
        None => links,
    }
}

/// `links` as they are: a session on the host's clock waits the wall clock's bound.
#[cfg(all(
    feature = "app-transport",
    not(feature = "time-base"),
    not(feature = "engine-tokio")
))]
fn app_links_on<C>(
    links: wz_capi_coop::app_link::AppLinks,
    _clock: &C,
) -> wz_capi_coop::app_link::AppLinks {
    links
}

/// Open `request` on the cooperative engine and install the session in `zs`: a session dialled
/// over the sockets of the system the build runs on (`crate::coop_host`), and with `peer` one that listens on the `tcp/` endpoint of its
/// `listen` key as well, opened on this thread before `z_open` returns, as the tokio engine's is.
/// A listener is open once its port is bound, as pico's `z_open(listen)` returns, and takes each
/// inbound link as a face of the session (`wz-capi-coop`'s `listen`). With `multicast-transport` a
/// group (a `udp/` endpoint with an interface) is joined as the session's one transport, on the
/// host's sockets or over the program's transport, as the tokio engine's open joins it; a build
/// without it refuses that endpoint.
///
/// What zenoh-pico's client advertises, as the tokio engine's open does: pico's batch size
/// (`BATCH_UNICAST_SIZE`), pico's lease (`Z_TRANSPORT_LEASE`) and pico's transmit model
/// ([`TxQueueConf::pico_of_snapshot`]), as the request's snapshot of limits holds them.
/// The zid is the one `Z_CONFIG_SESSION_ZID_KEY` names, and otherwise minted, as this ABI's tokio
/// open does.
///
/// A lost link is dialled again, and the session declares again over it what it holds, as
/// zenoh-pico's client reopens by default (`Z_FEATURE_AUTO_RECONNECT`) and as this ABI's tokio
/// open does.
///
/// # Safety
/// `zs` is a valid, null-initialised `z_owned_session_t`.
#[cfg(not(feature = "engine-tokio"))]
unsafe fn open_on_coop(zs: *mut z_owned_session_t, request: OpenRequest) -> ZResult {
    // A build without `peer` is a client build: `z_open` refused a listener and the peer role
    // before this.
    #[cfg(not(feature = "peer"))]
    debug_assert!(request.listen.is_none());
    // A listen endpoint that names a group is joined as the session's one transport, and a
    // connect locator beside it opens nothing, as the tokio engine's open reads it (pico adds a
    // peer to a unicast transport only). A build without the multicast transport refuses it.
    #[cfg(feature = "peer")]
    let joins_a_group = request.listen.as_deref().is_some_and(is_group_endpoint);
    #[cfg(all(feature = "peer", not(feature = "multicast-transport")))]
    if joins_a_group {
        return crate::result::Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN;
    }
    let dial_whatami = request.dial_whatami;
    let policy = request.policy;
    let limits = request.limits;
    let (tx_queue, sn_resolution) = pico_link_policy(&policy, &limits);
    #[cfg(feature = "session-memory")]
    let memory = memory_basis(request.listen.as_deref(), &tx_queue, &limits);
    // The engine takes the id as the config states it, up to sixteen bytes: the form an INIT
    // carries.
    let zid = request.zid;
    // The locator pico's one transport is opened on, which its admin space reports as the
    // transport's link: the listen locator when there is one, a group's included, the first
    // connect locator otherwise (`vendor/zenoh-pico/src/net/session.c` @
    // `// First, try to open the optional listen locator.`).
    #[cfg(feature = "admin-space")]
    let transport_endpoint = request
        .listen
        .clone()
        .or_else(|| request.connect.first().cloned());
    // pico's config carries ONE listen locator, so the set is that one or none, unless it names
    // the group the session joins.
    #[cfg(feature = "multicast-transport")]
    let (listen, connect, groups): (Vec<String>, Vec<String>, Vec<_>) = match request.listen {
        Some(endpoint) if joins_a_group => (
            Vec::new(),
            Vec::new(),
            vec![wz_capi_port::group::GroupJoin {
                endpoint,
                profile: pico_group(sn_resolution, &limits),
                is_shm: false,
                // pico declares its entities over whatever transport it holds, a group too, and
                // with `Z_FEATURE_MULTICAST_DECLARATIONS` its keyexprs and write filters as
                // well, as the tokio engine's open reads it.
                #[cfg(not(feature = "multicast-declarations"))]
                declarations: wz_capi_port::group::GroupDeclarations::Entities,
                #[cfg(feature = "multicast-declarations")]
                declarations: wz_capi_port::group::GroupDeclarations::Mapped,
            }],
        ),
        listen => (listen.into_iter().collect(), request.connect, Vec::new()),
    };
    #[cfg(not(feature = "multicast-transport"))]
    let (listen, connect, groups): (
        Vec<String>,
        Vec<String>,
        Vec<wz_capi_port::group::GroupJoin>,
    ) = (
        request.listen.into_iter().collect(),
        request.connect,
        Vec::new(),
    );
    // A datagram link reads into a buffer of the batch the session advertises, as pico's UDP link
    // reads into one of its `BATCH_UNICAST_SIZE`: no peer's batch is larger once the two have
    // negotiated, and a node pays its batch for each link and not the largest datagram.
    let links = crate::coop_host::links().with_rx_capacity(limits.pico_unicast_batch_bytes());
    // A session that listens on nothing holds the one link it dials, as pico's client holds its
    // one transport, so its arena lays out the buffers and the tables of no other face; one that
    // listens holds as many as its limits admit, pico's `Z_LISTEN_MAX_CONNECTION_NB` at the pico
    // preset. A limit over the build's is refused as the open's arena refuses one.
    let max_faces = if listen.is_empty() {
        0
    } else {
        match wz_capi_coop::arena::admitted_faces(&limits) {
            Ok(faces) => faces,
            Err(refused) => {
                return coop_open_refusal(&wz_capi_coop::OpenError::Arena(refused));
            }
        }
    };
    let accept_pending = match wz_capi_coop::arena::admitted_handshakes(&limits) {
        Ok(handshakes) => handshakes,
        Err(refused) => return coop_open_refusal(&wz_capi_coop::OpenError::Arena(refused)),
    };
    // The clock every timer of the session reads: the time base the config names, or the host's.
    #[cfg(feature = "time-base")]
    let clock = crate::time_base::session_clock(request.time_base);
    #[cfg(not(feature = "time-base"))]
    let clock = crate::coop_host::clock();
    // The `tls/` link: the secure channel over the host's streams, for the dial and the listen,
    // made from the material the config's keys named. A config whose material cannot make a
    // channel (half a listener, a key that is not its chain's) fails the open, as a malformed
    // value does at the keys, and never degrades to a session without the protection asked for.
    // An inbound handshake is timed on the session's clock, as the session's own handshake is.
    #[cfg(feature = "tls-mbedtls")]
    let links = match wz_capi_coop::tls::HostTls::from_config(
        crate::coop_host::tcp_dial(),
        &request.tls,
        limits.pico_accept_timeout_ms() as u64,
        &clock,
    ) {
        Ok(tls) => links.with_tls(tls),
        Err(_) => return crate::result::Z_ERR_INVALID,
    };
    // A group is joined on the host's sockets, under the session's two link policies, as the
    // tokio engine's group sockets are.
    #[cfg(feature = "multicast-transport")]
    let links = links.with_groups(wz_capi_coop::host_group::HostGroups::<
        crate::coop_host::Multicast,
    >::of_policy(&policy));
    // The word that the program's clock moved on, read before the clock is handed to the engine.
    #[cfg(feature = "time-base")]
    let clock_moves = crate::time_base::clock_moves(&clock);
    #[cfg(not(feature = "time-base"))]
    let clock_moves: Option<wz_capi_coop::ClockMovesWord> = None;
    // The engine's config, made by the engine inside its open (`CoopEngine::open_made_in`): this
    // frame, which the open's handshake runs under, holds the maker and what it reads, and never
    // the config.
    let make_config = || wz_capi_coop::CoopConfig {
        endpoints: connect,
        whatami: dial_whatami,
        zid,
        // The numbers of pico's value build switches, as the open's snapshot holds them: the
        // batch size and lease its InitSyn carries (`BATCH_UNICAST_SIZE`,
        // `Z_TRANSPORT_LEASE`), the largest message it rejoins (`FRAG_MAX_SIZE`), how often
        // its keepalive speaks (`Z_TRANSPORT_LEASE_EXPIRE_FACTOR`) and its handshake's
        // receive deadline (`Z_TRANSPORT_CONNECT_TIMEOUT`).
        batch_size: pico_unicast_batch(&limits),
        lease_ms: pico_lease_ms(&limits),
        keep_alive: pico_keep_alive(&limits),
        sn_resolution,
        link_rx: pico_link_rx(&limits),
        tx_queue,
        timeouts: pico_session_timeouts(&limits),
        open_timeout_ms: limits.pico_connect_timeout_ms() as u64,
        // pico tries again every 1000 ms while the reopen fails
        // (`vendor/zenoh-pico/src/net/session.c` @
        // `return _z_fut_fn_result_wake_up_after(1000);`).
        redial_ms: Some(1000),
        // A read waits on the link as long as pico's socket receive times out, its
        // `Z_CONFIG_SOCKET_TIMEOUT` as the open's snapshot holds it.
        idle_wait_ms: pico_socket_timeout(&limits),
        // The bounds of an accept are the session's limits: the faces it holds besides its dial
        // (`MAX_FACES`) and the handshakes under way (`MAX_ACCEPT_PENDING`), at the pico preset
        // pico's own, ten peers and one handshake at a time.
        listen,
        accept_pending,
        max_faces,
        // The group the listen endpoint names, when it names one.
        groups,
        // A session on a time base waits for the program's word that its time moved on as well
        // as for its links.
        clock_moves,
        // The session limits the config states, which the engine's tables are held to.
        limits,
    };
    // A config that carries the program's transport opens the engine over its links, and over no
    // socket of the host's; `z_open` has refused a locator the transport does not carry. Either
    // way the session holds the key ids the config states (`crate::key_ids`). The read task waits
    // for the program's links as it waits for the host's sockets, with the session free: a link
    // waiting in its own loop would hold the session through each tick of its wait, and a call
    // that takes the session (a get takes it more than once) would wait behind the read task
    // turn after turn.
    #[cfg(feature = "app-transport")]
    let opened = match request.app_transport {
        Some(transport) => wz_capi_coop::CoopEngine::open_made_in(
            app_links_on(
                wz_capi_coop::app_link::AppLinks::new(
                    wz_session_core::app_transport::SessionTransport::new(transport, &limits),
                )
                .with_rx_capacity(limits.pico_unicast_batch_bytes())
                .waited_by_owner(),
                &clock,
            ),
            clock,
            crate::coop_host::entropy(),
            make_config,
            policy,
            request.key_ids,
            &wz_capi_coop::arena::AllocatorMemory,
            Some(SessionPlace::LAYOUT),
        )
        .map(|engine| PicoDrive::App(engine.into_drive())),
        None => wz_capi_coop::CoopEngine::open_made_in(
            links.waited_by_owner(),
            clock,
            crate::coop_host::entropy(),
            make_config,
            policy,
            request.key_ids,
            &wz_capi_coop::arena::AllocatorMemory,
            Some(SessionPlace::LAYOUT),
        )
        .map(|engine| PicoDrive::Host(engine.into_drive())),
    };
    #[cfg(not(feature = "app-transport"))]
    let opened = wz_capi_coop::CoopEngine::open_made_in(
        links.waited_by_owner(),
        clock,
        crate::coop_host::entropy(),
        make_config,
        policy,
        request.key_ids,
        &wz_capi_coop::arena::AllocatorMemory,
        Some(SessionPlace::LAYOUT),
    )
    .map(wz_capi_coop::CoopEngine::into_drive);
    let drive = match opened {
        Ok(drive) => drive,
        Err(refused) => return coop_open_refusal(&refused),
    };
    // The open was asked for the handle's place, so it lent one; an engine that lent none is
    // answered as an arena with no room for it, the session closed as the drive drops.
    let Some(place) = drive.handle_place() else {
        return crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
    };
    let zid = drive.zid();
    #[cfg(feature = "connectivity")]
    let ext = crate::session_ext::PicoSessionExt::new(
        dial_whatami,
        &zid,
        policy,
        limits,
        &drive.engine(),
    );
    #[cfg(not(feature = "connectivity"))]
    let ext = crate::session_ext::PicoSessionExt::new(dial_whatami, &zid, policy, limits);
    // A refused session clock fails the open as the tokio engine's does, the engine's session
    // closed first.
    #[cfg(any(feature = "advanced", feature = "clock-source"))]
    if ext.clock_refused().is_some() {
        drop(ext);
        drive.close();
        return crate::result::Z_ERR_CONFIG_INVALID_VALUE;
    }
    #[cfg(feature = "admin-space")]
    let ext = ext.with_transport_endpoint(transport_endpoint);
    let handle = PicoSessionHandle::new(drive, ext);
    #[cfg(feature = "session-memory")]
    let handle = handle.with_memory(memory);
    debug_assert!(place.bytes() >= SessionPlace::LAYOUT.size());
    *zs = z_owned_session_t {
        // SAFETY: the arena lent the place for `SessionPlace::LAYOUT`, aligned as a span starts,
        // to this handle alone, and it stands while the engine the handle holds does.
        _val: SessionPlace::fill(place.as_ptr(), handle) as *mut c_void,
        _cnt: core::ptr::null_mut(),
    };
    // The multi-threaded arm's read task starts with the open unless the options say not to. A
    // start that fails fails the open, the session dropped, as pico's `z_open` does
    // (`vendor/zenoh-pico/src/api/api.c` @ `_Z_CLEAN_RETURN_IF_ERR(_z_runtime_start(`).
    #[cfg(feature = "multi-thread")]
    if request.start_read_task {
        let code = read_task_start_code(
            session_handle(z_session_loan_mut(zs))
                .map_or(Ok(()), |handle| handle.drive.start_read_task()),
        );
        if code != Z_OK {
            z_session_drop(z_session_move(zs));
            return code;
        }
    }
    #[cfg(feature = "admin-space")]
    if request.start_admin_space {
        let code = crate::admin_space::zp_start_admin_space(z_session_loan_mut(zs));
        if code != Z_OK {
            z_session_drop(z_session_move(zs));
            return code;
        }
    }
    Z_OK
}

/// The code a refused open of the cooperative engine answers, as pico answers the same refusal.
/// An arena the memory cannot give is pico's out of memory, and so is a runtime whose task cells,
/// reserved at the open, have none for the session's link or group; a limit over the build's value
/// is a value the build refuses. Either way the engine bound and dialled nothing, and reserved no
/// place for the handle, which its arena holds.
#[cfg(not(feature = "engine-tokio"))]
fn coop_open_refusal(refused: &wz_capi_coop::OpenError) -> ZResult {
    use wz_capi_coop::arena::ArenaRefused;
    use wz_capi_coop::OpenError;
    match refused {
        OpenError::EntropyUnavailable => crate::result::Z_ERR_GENERIC,
        // `z_open` judged the form before this (`crate::key_ids::admit_at_open`), and the engine
        // judges it again with the same rule.
        OpenError::KeyWireForm(_) => crate::result::Z_ERR_INVALID,
        OpenError::Arena(ArenaRefused::Limit { .. }) => crate::result::Z_ERR_CONFIG_INVALID_VALUE,
        OpenError::Arena(
            ArenaRefused::TooLarge | ArenaRefused::NoMemory { .. } | ArenaRefused::Lend(_),
        )
        | OpenError::NoTask(_) => crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY,
        _ => crate::result::Z_ERR_TRANSPORT_OPEN_FAILED,
    }
}

#[cfg(all(test, not(feature = "engine-tokio")))]
mod coop_open_refusal_tests {
    use super::coop_open_refusal;
    use crate::result::{
        Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_ERR_TRANSPORT_OPEN_FAILED,
    };
    use wz_capi_coop::arena::ArenaRefused;
    use wz_capi_coop::OpenError;
    use wz_session_core::limit_binding::Quota;

    /// An open whose arena the memory cannot give, or that is past the address space, answers
    /// pico's out of memory, as a full pool of this ABI does.
    #[test]
    fn an_arena_that_cannot_be_reserved_is_out_of_memory() {
        assert_eq!(
            coop_open_refusal(&OpenError::Arena(ArenaRefused::NoMemory { bytes: 4096 })),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
        assert_eq!(
            coop_open_refusal(&OpenError::Arena(ArenaRefused::TooLarge)),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
        assert_eq!(
            coop_open_refusal(&OpenError::Arena(ArenaRefused::Lend(
                wz_session_core::bounded::LendRefused::Exhausted {
                    asked: Some(4096),
                    left: 0,
                }
            ))),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
    }

    /// A runtime with no task cell for the session's link, or none that fits its task, is out of
    /// memory as an arena that cannot be reserved is: the cells are the open's reservation.
    #[test]
    fn a_runtime_with_no_task_for_the_session_is_out_of_memory() {
        use wz_capi_coop::SpawnRefusal;
        assert_eq!(
            coop_open_refusal(&OpenError::NoTask(SpawnRefusal::NoTaskCell)),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
        assert_eq!(
            coop_open_refusal(&OpenError::NoTask(SpawnRefusal::TooLarge)),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
    }

    /// A limit the config states over the build's value is a value this build refuses; an open
    /// with nothing to dial stays a failed transport.
    #[test]
    fn a_limit_over_the_builds_value_is_an_invalid_value() {
        let why = Quota::at_most(9)
            .lent_under(Quota::at_most(8))
            .expect_err("nine is over eight");
        assert_eq!(
            coop_open_refusal(&OpenError::Arena(ArenaRefused::Limit {
                limit: "MAX_SUBSCRIPTIONS",
                why,
            })),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert_eq!(
            coop_open_refusal(&OpenError::NoEndpoint),
            Z_ERR_TRANSPORT_OPEN_FAILED
        );
    }
}

/// Close a session (pico `z_close`): stop the drive loop and join the driver
/// thread. Does not free the owned struct — that is `z_session_drop`.
#[no_mangle]
pub unsafe extern "C" fn z_close(zs: *mut z_loaned_session_t, _options: *const c_void) -> ZResult {
    guarded(|| {
        if zs.is_null() || (*zs)._val.is_null() {
            return Z_ERR_NULL;
        }
        // A copy of a session kept past its drop finds its place vacant.
        let Some(handle) = session_handle(zs) else {
            return Z_ERR_SESSION_CLOSED;
        };
        handle.drive.close();
        handle.ext.close_listeners();
        // The close let go of every closure the session held; a callback still running on a
        // dispatch thread finishes before this returns, and then the drops have run.
        handle.wait_background();
        Z_OK
    })
}

// --- session ownership family (null/check/loan/loan_mut/move/take/drop) -----

/// Zero an owned session (pico `z_internal_session_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_session_null(obj: *mut z_owned_session_t) {
    if !obj.is_null() {
        *obj = z_owned_session_t::null_value();
    }
}

/// `true` iff the owned session holds a live handle (pico
/// `z_internal_session_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_session_check(obj: *const z_owned_session_t) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj)._val.is_null())
}

/// Borrow a session immutably (pico `z_session_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_session_loan(
    obj: *const z_owned_session_t,
) -> *const z_loaned_session_t {
    obj as *const z_loaned_session_t
}

/// Borrow a session mutably (pico `z_session_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_session_loan_mut(
    obj: *mut z_owned_session_t,
) -> *mut z_loaned_session_t {
    obj as *mut z_loaned_session_t
}

/// Move-cast a session (pico `z_session_move`).
#[no_mangle]
pub unsafe extern "C" fn z_session_move(obj: *mut z_owned_session_t) -> *mut z_moved_session_t {
    obj as *mut z_moved_session_t
}

/// Take a session out of `src` into `dst` (pico `z_session_take`).
#[no_mangle]
pub unsafe extern "C" fn z_session_take(dst: *mut z_owned_session_t, src: *mut z_moved_session_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst)._val = (*src)._this._val;
    (*dst)._cnt = (*src)._this._cnt;
    (*src)._this = z_owned_session_t::null_value();
}

/// Drop an owned session (pico `z_session_drop`): closes (if not already) and
/// frees the [`SessionState`].
#[no_mangle]
pub unsafe extern "C" fn z_session_drop(obj: *mut z_moved_session_t) {
    let _ = guarded(|| {
        if obj.is_null() {
            return Z_OK;
        }
        let val = (*obj)._this._val;
        if !val.is_null() {
            // The engine's session closes as its drive drops (idempotent).
            release_handle(val);
            (*obj)._this = z_owned_session_t::null_value();
        }
        Z_OK
    });
}

// --- zp_*_task: the session's background executor --------------------------
//
// pico 1.10.1 has ONE executor, and it runs the keep-alive, lease, read and
// accept tasks together. `zp_start_read_task` and `zp_stop_read_task` start and
// stop it (`vendor/zenoh-pico/src/api/api.c` @
// `z_result_t zp_stop_read_task(z_loaned_session_t *zs) {`), and while it is
// stopped the session reads nothing and sends no keep-alive; the lease pair is a
// literal no-op (`zp_start_lease_task` returns `_Z_RES_OK` and touches nothing).
// The same gate answers all of it: see `wz_capi_core::drive::ReadGate`. pico declares
// the family only in its multi-threaded arm (`Z_FEATURE_MULTI_THREAD == 1`), and so
// does this crate, under `multi-thread`.
//
// These used to be Z_OK shims on the ground that wz's session drives itself, and
// that held for every program that never stopped the task. A program that opens
// without it (`auto_start_read_task` false), declares its subscribers and then
// starts it found pico holding the traffic until the start and wz having
// delivered it to nobody.

/// Start the session's read task (pico `zp_start_read_task`). Idempotent, as
/// pico's is. From inside one of the session's own callbacks it answers
/// `_Z_ERR_INVALID` and changes nothing, as pico's does from its executor's
/// thread. A system that gives no thread answers `_Z_ERR_SYSTEM_GENERIC`, as
/// pico's task creation does where `pthread_create` refuses, and the task is
/// not running.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn zp_start_read_task(
    zs: *mut z_loaned_session_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| match session_handle(zs) {
        Some(handle) => read_task_start_code(handle.drive.start_read_task()),
        None => Z_ERR_NULL,
    })
}

/// The code a start of the read task answers with, as zenoh-pico's start answers it.
#[cfg(feature = "multi-thread")]
fn read_task_start_code(started: Result<(), ReadTaskStartRefused>) -> ZResult {
    match started {
        Ok(()) => Z_OK,
        Err(ReadTaskStartRefused::CalledFromReadTask) => Z_EINVAL,
        Err(ReadTaskStartRefused::NoThread) => Z_ERR_SYSTEM_GENERIC,
    }
}

/// Stop the session's read task (pico `zp_stop_read_task`). Idempotent, as
/// pico's is. The session reads nothing and sends no keep-alive until it is
/// started again; a put still writes, on the caller's thread as pico's does.
/// It returns once no callback is running, as pico's does after joining its
/// executor's thread, and from inside one of the session's own callbacks it
/// answers `_Z_ERR_INVALID` and stops nothing.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn zp_stop_read_task(zs: *mut z_loaned_session_t) -> ZResult {
    match session_handle(zs) {
        Some(handle) => match handle.drive.stop_read_task() {
            Ok(()) => Z_OK,
            Err(_) => Z_EINVAL,
        },
        None => Z_ERR_NULL,
    }
}

/// pico `zp_start_lease_task` — a no-op in pico 1.10.1 too: the lease is checked
/// by the executor `zp_start_read_task` starts.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn zp_start_lease_task(
    _zs: *mut z_loaned_session_t,
    _options: *const c_void,
) -> ZResult {
    Z_OK
}

/// pico `zp_stop_lease_task` — a no-op in pico 1.10.1 too.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn zp_stop_lease_task(_zs: *mut z_loaned_session_t) -> ZResult {
    Z_OK
}

/// pico `zp_spin_once` — no-op (the drive loop IS the executor this pumps).
///
/// This is the export the SINGLE-THREADED example pair is built around.
/// `z_pub_st.c` / `z_sub_st.c` compile only under `Z_FEATURE_MULTI_THREAD == 0`,
/// where pico has no background executor thread and the application is
/// responsible for advancing the session by hand: each loop iteration sleeps and
/// then calls this to run ONE pending task (read, lease, keep-alive, accept,
/// connect) off pico's task queue
/// (`vendor/zenoh-pico/include/zenoh-pico/api/primitives.h:3336-3345`).
///
/// wz has no such queue to drain. Its session SELF-DRIVES — the face's drive
/// loop performs the read / lease / keep-alive work on its own runtime whether
/// or not the C thread ever calls in — so the faithful shim is to return
/// immediately, exactly as the `zp_start_read_task` / `zp_start_lease_task`
/// family above already does for the multi-threaded build.
///
/// The divergence is deliberate and one-directional: wz makes progress the
/// caller did not ask for, never less. A program written against the
/// single-threaded contract therefore behaves as its author intended (its
/// samples flow, its lease is held), while one that never called this would ALSO
/// work here — which is the honest statement of what wz's runtime model gives
/// up, not a claim that the call is meaningless.
///
/// R2528 — the return type is `bool`, and it CHANGED under us. zenoh-pico
/// 1.9.0 declared `void zp_spin_once(const z_loaned_session_t *zs);` and 1.10.1
/// declares `bool zp_spin_once(const z_loaned_session_t *zs);`. That single
/// declaration is the ENTIRE ABI delta of the public API headers between those
/// releases — measured by diffing them, not supposed — so a drop-in that kept
/// returning `void` would have been the one place the 1.10.1 bump made wz wrong.
///
/// Upstream's own words for the value: "Returns `false` if there are no more
/// tasks that can be executed immediately. This can only happen when
/// `Z_RUNTIME_IDLE_READ_TASK_SLEEP` is set to positive value; otherwise read
/// tasks always reschedule immediately, and `true` is always returned unless the
/// session is closed."
///
/// So under the default configuration the value reduces to "the session is
/// still alive", and that is what wz answers. It is a strictly BETTER answer
/// than the shim could give before: the previous doc here recorded, as a
/// limitation, that "pico reports no status here, so a null or dead session
/// cannot be signalled to the caller". Upstream has since given the call a
/// channel for exactly that, and wz now uses it.
///
/// wz never returns `false` for "no work to do", and that is the same
/// one-directional divergence the paragraphs above describe rather than a new
/// one: wz has no task queue to be empty. `Z_RUNTIME_IDLE_READ_TASK_SLEEP` is a
/// pico scheduling knob with no wz counterpart, so the branch that would return
/// `false` on a live session does not exist here.
///
/// A panic yields `false` — a spin that unwound made no progress, and claiming
/// otherwise is the direction that misleads.
#[cfg(not(feature = "multi-thread"))]
#[no_mangle]
pub unsafe extern "C" fn zp_spin_once(zs: *const z_loaned_session_t) -> bool {
    // Upstream: `if (!z_session_is_closed(zs)) { return _z_runtime_spin_once(..); } return
    // false;`, so a closed session answers `false` like a null one. The engine answers the
    // rest: one that drives itself answers "alive", one the program steps runs the turn.
    guard_val(false, || {
        session_handle(zs).is_some_and(|handle| handle.drive.spin_once())
    })
}

// --- the single-threaded entry points (pico `Z_FEATURE_MULTI_THREAD == 0`) --
//
// A program compiled against pico's single-threaded headers advances its session
// by hand with these three and `zp_spin_once`, which upstream declares (and defines)
// only when `Z_FEATURE_MULTI_THREAD == 0` (`vendor/zenoh-pico/include/zenoh-pico/api/primitives.h`,
// `vendor/zenoh-pico/src/api/api.c` `zp_read` .. `zp_spin_once`), and so does this crate,
// without `multi-thread`. The two header arms are two builds: they differ in the size of
// structs the C program allocates (`z_open_options_t`, the channel collections), so one
// cdylib cannot serve both.
//
// The wz session drives itself, so each is the same one-directional divergence
// `zp_spin_once` documents: the work a call would trigger (a read, a keep-alive, a
// join) is done by the session on its own schedule whether or not the call is made,
// and the call answers what upstream answers for a live session.

/// pico `zp_read_options_t` (`api/types.h`, `Z_FEATURE_MULTI_THREAD == 0`): one `bool`.
#[cfg(not(feature = "multi-thread"))]
#[repr(C)]
pub struct zp_read_options_t {
    pub single_read: bool,
}

/// pico `zp_send_keep_alive_options_t`: one byte so the struct is not empty.
#[cfg(not(feature = "multi-thread"))]
#[repr(C)]
pub struct zp_send_keep_alive_options_t {
    pub __dummy: u8,
}

/// pico `zp_send_join_options_t`: one byte so the struct is not empty.
#[cfg(not(feature = "multi-thread"))]
#[repr(C)]
pub struct zp_send_join_options_t {
    pub __dummy: u8,
}

/// pico `zp_read_options_default`: `single_read = false`.
#[cfg(not(feature = "multi-thread"))]
#[no_mangle]
pub unsafe extern "C" fn zp_read_options_default(options: *mut zp_read_options_t) {
    if !options.is_null() {
        (*options).single_read = false;
    }
}

/// pico `zp_read`: read and process what the session's link holds (one message with
/// `single_read`). An engine that reads continuously on its own runtime answers `Z_OK` for a
/// live session; one the program steps reads here. A null or closed session answers
/// `_Z_ERR_SESSION_CLOSED`, the code pico's session check uses.
#[cfg(not(feature = "multi-thread"))]
#[no_mangle]
pub unsafe extern "C" fn zp_read(
    zs: *const z_loaned_session_t,
    options: *const zp_read_options_t,
) -> ZResult {
    guarded(|| {
        let single = !options.is_null() && (*options).single_read;
        match session_handle(zs).map(|handle| handle.drive.read(single)) {
            Some(Ok(())) => Z_OK,
            _ => Z_ERR_SESSION_CLOSED,
        }
    })
}

/// pico `zp_send_keep_alive_options_default`.
#[cfg(not(feature = "multi-thread"))]
#[no_mangle]
pub unsafe extern "C" fn zp_send_keep_alive_options_default(
    options: *mut zp_send_keep_alive_options_t,
) {
    if !options.is_null() {
        (*options).__dummy = 0;
    }
}

/// pico `zp_send_keep_alive`: send a KeepAlive now. An engine that keeps its lease on its own
/// schedule answers `Z_OK` for a live session; one the program steps sends it here.
#[cfg(not(feature = "multi-thread"))]
#[no_mangle]
pub unsafe extern "C" fn zp_send_keep_alive(
    zs: *const z_loaned_session_t,
    _options: *const zp_send_keep_alive_options_t,
) -> ZResult {
    guarded(
        || match session_handle(zs).map(|handle| handle.drive.send_keep_alive()) {
            Some(Ok(())) => Z_OK,
            _ => Z_ERR_SESSION_CLOSED,
        },
    )
}

/// pico `zp_send_join_options_default`.
#[cfg(not(feature = "multi-thread"))]
#[no_mangle]
pub unsafe extern "C" fn zp_send_join_options_default(options: *mut zp_send_join_options_t) {
    if !options.is_null() {
        (*options).__dummy = 0;
    }
}

/// pico `zp_send_join`: send a Join now. Upstream sends one only on a multicast or
/// raw-ethernet transport and answers `_Z_RES_OK` on a unicast one without sending
/// (`vendor/zenoh-pico/src/transport/common/lease.c` @ `z_result_t _z_send_join(`). A
/// session that joined a group asks the group's loop for its JOIN, which then keeps its
/// cadence from it; a session with none sends nothing. A live session answers `Z_OK`.
#[cfg(not(feature = "multi-thread"))]
#[no_mangle]
pub unsafe extern "C" fn zp_send_join(
    zs: *const z_loaned_session_t,
    _options: *const zp_send_join_options_t,
) -> ZResult {
    guarded(|| {
        let live = live_session_result(zs);
        // Either engine's groups, through the port.
        #[cfg(feature = "multicast-transport")]
        if live == Z_OK {
            if let Some(handle) = session_handle(zs) {
                engine_ref(handle).send_join_on_groups();
            }
        }
        live
    })
}

/// What `zp_send_join` answers for `zs`: `Z_OK` for an open session,
/// `_Z_ERR_SESSION_CLOSED` for a null or closed one.
#[cfg(not(feature = "multi-thread"))]
unsafe fn live_session_result(zs: *const z_loaned_session_t) -> ZResult {
    match session_handle(zs) {
        Some(handle) if !handle.drive.is_closed() => Z_OK,
        _ => Z_ERR_SESSION_CLOSED,
    }
}

// --- TX batching (pico `zp_batch_*`) ---------------------------------------

/// Open a TX batching window (pico `zp_batch_start`).
///
/// pico drives ONE transport, so its batch control is a single call
/// (`src/api/api.c:2444-2450` into `_z_transport_start_batching`). wz holds N
/// faces, so the window opens on each — the same fan-out every other
/// session-level export here performs. Upstream's `z_pub_thr.c` brackets its
/// publish loop with `zp_batch_start` / `zp_batch_stop`, which is what makes it
/// a THROUGHPUT benchmark rather than a publish loop.
#[no_mangle]
pub unsafe extern "C" fn zp_batch_start(zs: *const z_loaned_session_t) -> ZResult {
    guarded(|| match session_handle(zs) {
        Some(handle) => {
            let engine = engine_ref(handle);
            if !engine.has_transport() {
                return Z_ERR_TRANSPORT_NOT_AVAILABLE;
            }
            engine.batch_start_all();
            Z_OK
        }
        // pico: `if (_Z_RC_IS_NULL(zs)) _Z_ERROR_RETURN(_Z_ERR_SESSION_CLOSED);` -- a null
        // session is answered as a closed one, for all three batch calls.
        None => Z_ERR_SESSION_CLOSED,
    })
}

/// Flush every open batch window without closing it (pico `zp_batch_flush`).
///
/// Shipped alongside its two siblings even though no upstream example calls it:
/// an asymmetric family fails to link for the NEXT program rather than this one,
/// which is the lesson this crate already paid for once with
/// `z_put_options_default`.
#[no_mangle]
pub unsafe extern "C" fn zp_batch_flush(zs: *const z_loaned_session_t) -> ZResult {
    guarded(|| match session_handle(zs) {
        Some(handle) => {
            let engine = engine_ref(handle);
            if !engine.has_transport() {
                return Z_ERR_TRANSPORT_NOT_AVAILABLE;
            }
            engine.batch_flush_all();
            Z_OK
        }
        None => Z_ERR_SESSION_CLOSED,
    })
}

/// Close every batch window, draining what it holds (pico `zp_batch_stop`).
#[no_mangle]
pub unsafe extern "C" fn zp_batch_stop(zs: *const z_loaned_session_t) -> ZResult {
    guarded(|| match session_handle(zs) {
        Some(handle) => {
            let engine = engine_ref(handle);
            if !engine.has_transport() {
                return Z_ERR_TRANSPORT_NOT_AVAILABLE;
            }
            engine.batch_stop_all();
            Z_OK
        }
        None => Z_ERR_SESSION_CLOSED,
    })
}

// --- R311y559: the entity-identity accessors --------------------------------
//
// Every zenoh entity a program declares has a GLOBAL id — the session's zid
// paired with a session-scope entity id — and upstream exports one accessor per
// entity kind. The census found the whole family missing, which is why they
// live together here rather than beside each handle type: they are one claim
// with five spellings, and splitting them across five modules is how the
// `zid` half ends up read from a different place in each.

/// The global id of an entity declared on `zs`, or the empty id when the
/// session is gone.
///
/// The `zid` half always comes from the SESSION, never from the handle: an
/// entity's identity is `(this session's zid, this entity's eid)`, and reading
/// the zid per-handle would be a second source for a fact that has one.
#[cfg(feature = "unstable-api")]
pub(crate) unsafe fn entity_global_id(
    zs: &PicoSessionHandle,
    eid: wz_session_core::wire_id::EntityId,
) -> crate::entity::z_entity_global_id_t {
    crate::entity::z_entity_global_id_t {
        zid: crate::zid::z_id_t { id: zs.drive.zid() },
        eid,
    }
}

/// The session's own global id (pico `z_session_id`) — its zid with entity id
/// 0, which is what upstream reports for the session entity itself.
///
/// # Safety
/// `zs` must be null or a live loaned session.
#[cfg(feature = "unstable-api")]
#[no_mangle]
pub unsafe extern "C" fn z_session_id(
    zs: *const z_loaned_session_t,
) -> crate::entity::z_entity_global_id_t {
    crate::ffi::guard_val(
        crate::entity::z_entity_global_id_t {
            zid: crate::zid::z_id_t::empty(),
            eid: 0,
        },
        || match session_handle(zs) {
            Some(handle) => entity_global_id(handle, 0),
            None => crate::entity::z_entity_global_id_t {
                zid: crate::zid::z_id_t::empty(),
                eid: 0,
            },
        },
    )
}

/// Whether the session has been closed (pico `z_session_is_closed`).
///
/// A NULL / spent handle reports CLOSED. That is the safe direction and it is
/// also the truthful one: a program holding a session it has already dropped
/// has no open session, and reporting "open" would invite it to publish
/// through a dead handle.
///
/// # Safety
/// `zs` must be null or a live loaned session.
#[no_mangle]
pub unsafe extern "C" fn z_session_is_closed(zs: *const z_loaned_session_t) -> bool {
    crate::ffi::guard_val(true, || match session_handle(zs) {
        Some(handle) => handle.drive.is_closed(),
        None => true,
    })
}

/// Borrow a publisher's keyexpr (pico `z_publisher_keyexpr`).
///
/// # Safety
/// `publisher` must be null or a live loaned publisher.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_keyexpr(
    publisher: *const crate::pubsub::z_loaned_publisher_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::ffi::guard_val(core::ptr::null(), || {
        match crate::abi::handle_ref::<
            crate::pubsub::z_loaned_publisher_t,
            crate::pubsub::PublisherState,
        >(publisher)
        {
            Some(state) => state.loaned_keyexpr(),
            None => core::ptr::null(),
        }
    })
}

/// A publisher's global entity id (pico `z_publisher_id`).
///
/// # Safety
/// `publisher` must be null or a live loaned publisher.
#[cfg(feature = "unstable-api")]
#[no_mangle]
pub unsafe extern "C" fn z_publisher_id(
    publisher: *const crate::pubsub::z_loaned_publisher_t,
) -> crate::entity::z_entity_global_id_t {
    entity_id_of(
        crate::abi::handle_ref::<
            crate::pubsub::z_loaned_publisher_t,
            crate::pubsub::PublisherState,
        >(publisher)
        .map(|s| (s.shared_zid(), s.entity_id())),
    )
}

/// Borrow a querier's keyexpr (pico `z_querier_keyexpr`).
///
/// # Safety
/// `querier` must be null or a live loaned querier.
#[cfg(feature = "query")]
#[no_mangle]
pub unsafe extern "C" fn z_querier_keyexpr(
    querier: *const crate::querier::z_loaned_querier_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::ffi::guard_val(core::ptr::null(), || {
        match crate::abi::handle_ref::<
            crate::querier::z_loaned_querier_t,
            crate::querier::QuerierState,
        >(querier)
        {
            Some(state) => state.loaned_keyexpr(),
            None => core::ptr::null(),
        }
    })
}

/// A querier's global entity id (pico `z_querier_id`).
///
/// # Safety
/// `querier` must be null or a live loaned querier.
#[cfg(all(feature = "query", feature = "unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_querier_id(
    querier: *const crate::querier::z_loaned_querier_t,
) -> crate::entity::z_entity_global_id_t {
    entity_id_of(
        crate::abi::handle_ref::<crate::querier::z_loaned_querier_t, crate::querier::QuerierState>(
            querier,
        )
        .map(|s| (s.shared_zid(), s.entity_id())),
    )
}

/// Borrow a subscriber's keyexpr (pico `z_subscriber_keyexpr`).
///
/// # Safety
/// `subscriber` must be null or a live loaned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_keyexpr(
    subscriber: *const crate::pubsub::z_loaned_subscriber_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::ffi::guard_val(core::ptr::null(), || {
        match crate::abi::handle_ref::<
            crate::pubsub::z_loaned_subscriber_t,
            crate::pubsub::SubscriberState,
        >(subscriber)
        {
            Some(state) => &state.loaned_keyexpr as *const crate::abi::z_loaned_keyexpr_t,
            None => core::ptr::null(),
        }
    })
}

/// A subscriber's global entity id (pico `z_subscriber_id`).
///
/// The `eid` is the registry's own `SubId` rather than a fresh allocation:
/// subscriptions already have a session-scope id, and minting a second one
/// would leave the handle and the registry naming the same entity differently.
///
/// # Safety
/// `subscriber` must be null or a live loaned subscriber.
#[cfg(feature = "unstable-api")]
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_id(
    subscriber: *const crate::pubsub::z_loaned_subscriber_t,
) -> crate::entity::z_entity_global_id_t {
    entity_id_of(
        crate::abi::handle_ref::<
            crate::pubsub::z_loaned_subscriber_t,
            crate::pubsub::SubscriberState,
        >(subscriber)
        .map(|s| (s.shared.zid(), s.id)),
    )
}

/// A queryable's global entity id (pico `z_queryable_id`).
///
/// # Safety
/// `queryable` must be null or a live loaned queryable.
#[cfg(all(feature = "queryable", feature = "unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_queryable_id(
    queryable: *const crate::query::z_loaned_queryable_t,
) -> crate::entity::z_entity_global_id_t {
    entity_id_of(crate::query::queryable_identity(queryable))
}

/// An advanced publisher's global entity id (pico `ze_advanced_publisher_id`).
///
/// # Safety
/// `pub_` must be null or a live loaned advanced publisher.
#[cfg(feature = "advanced")]
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_id(
    pub_: *const crate::advanced::ze_loaned_advanced_publisher_t,
) -> crate::entity::z_entity_global_id_t {
    entity_id_of(crate::advanced::advanced_publisher_identity(pub_))
}

/// Borrow an advanced publisher's keyexpr (pico
/// `ze_advanced_publisher_keyexpr`).
///
/// # Safety
/// `pub_` must be null or a live loaned advanced publisher.
#[cfg(feature = "advanced")]
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_publisher_keyexpr(
    pub_: *const crate::advanced::ze_loaned_advanced_publisher_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::advanced::advanced_publisher_keyexpr(pub_)
}

/// An advanced subscriber's global entity id (pico
/// `ze_advanced_subscriber_id`).
///
/// # Safety
/// `sub` must be null or a live loaned advanced subscriber.
#[cfg(feature = "advanced")]
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_id(
    sub: *const crate::advanced::ze_loaned_advanced_subscriber_t,
) -> crate::entity::z_entity_global_id_t {
    entity_id_of(crate::advanced::advanced_subscriber_identity(sub))
}

/// Borrow an advanced subscriber's keyexpr (pico
/// `ze_advanced_subscriber_keyexpr`).
///
/// # Safety
/// `sub` must be null or a live loaned advanced subscriber.
#[cfg(feature = "advanced")]
#[no_mangle]
pub unsafe extern "C" fn ze_advanced_subscriber_keyexpr(
    sub: *const crate::advanced::ze_loaned_advanced_subscriber_t,
) -> *const crate::abi::z_loaned_keyexpr_t {
    crate::advanced::advanced_subscriber_keyexpr(sub)
}

/// Project an optional `(zid, eid)` into the ABI's global id, with the empty id
/// standing for a null / spent handle.
///
/// One projection for all seven accessors above so the "what does a dead handle
/// report" answer cannot differ between them — the class of asymmetry this
/// crate has already paid for.
#[cfg(feature = "unstable-api")]
fn entity_id_of(
    identity: Option<([u8; 16], wz_session_core::wire_id::EntityId)>,
) -> crate::entity::z_entity_global_id_t {
    match identity {
        Some((zid, eid)) => crate::entity::z_entity_global_id_t {
            zid: crate::zid::z_id_t { id: zid },
            eid,
        },
        None => crate::entity::z_entity_global_id_t {
            zid: crate::zid::z_id_t::empty(),
            eid: 0,
        },
    }
}

// --- R311y559: the remaining option defaults + the two `zp_` task probes -----

/// pico `z_subscriber_options_t`.
///
/// The struct is `{ z_locality_t allowed_origin; }` under
/// `Z_FEATURE_LOCAL_SUBSCRIBER` (4 B) and `{ uint8_t __dummy; }` without it (1 B
/// MEASURED), and this crate follows the switch with `local-subscriber`. Without
/// it the field a caller could set does not exist and the subscriber is remote
/// only, as pico's is with no local path compiled in.
#[repr(C)]
pub struct z_subscriber_options_t {
    #[cfg(feature = "local-subscriber")]
    pub allowed_origin: crate::locality::z_locality_t,
    #[cfg(not(feature = "local-subscriber"))]
    pub __dummy: u8,
}

crate::locality::locality_option_field!(z_subscriber_options_t, allowed_origin, "local-subscriber");

/// pico `z_open_options_t`, 16 B measured:
/// `{ bool auto_start_read_task; bool auto_start_lease_task; z_task_attr_t* }`.
///
/// `auto_start_read_task` is READ: pico starts its executor in `z_open` only
/// `if (opts.auto_start_read_task)`
/// (`vendor/zenoh-pico/src/api/api.c` @ `if (opts.auto_start_read_task) {`), and
/// so does `z_open` here; a session opened with it off is connected or bound and
/// reads nothing until `zp_start_read_task`.
///
/// `auto_start_lease_task` is not read by pico 1.10.1's `z_open` either (its
/// header calls both flags deprecated and the lease task is a no-op), so its only
/// observable part is the DEFAULT `z_open_options_default` writes, which the
/// options-default leg compares. `executor_task_attributes` are the attributes of
/// pico's executor thread, which this session has no such thread to apply to.
///
/// With `admin-space` the struct gains pico's trailing `bool
/// auto_start_admin_space` (`vendor/zenoh-pico/include/zenoh-pico/api/types.h` @
/// `bool auto_start_admin_space;`), at offset 16 for 24 B, which is the layout a
/// program compiled with `Z_FEATURE_ADMIN_SPACE=1` writes.
///
/// Without `multi-thread` the three task fields do not exist, as they do not in pico's
/// single-threaded header (`#if Z_FEATURE_MULTI_THREAD == 1` around them): the struct is
/// the admin-space flag alone, or with no admin space pico's one-byte `__dummy` that keeps
/// it from being empty. One byte either way, where the multi-threaded struct is 16; a
/// default written as 16 bytes into a single-threaded program's struct overran it.
#[repr(C)]
pub struct z_open_options_t {
    #[cfg(feature = "multi-thread")]
    pub auto_start_read_task: bool,
    #[cfg(feature = "multi-thread")]
    pub auto_start_lease_task: bool,
    #[cfg(feature = "multi-thread")]
    pub executor_task_attributes: *mut crate::sync::z_task_attr_t,
    #[cfg(feature = "admin-space")]
    pub auto_start_admin_space: bool,
    #[cfg(not(any(feature = "multi-thread", feature = "admin-space")))]
    pub __dummy: u8,
}

/// pico `z_close_options_t` — a one-byte dummy, 1 B measured.
#[repr(C)]
pub struct z_close_options_t {
    pub __dummy: u8,
}

/// pico `zp_task_read_options_t`, 8 B measured.
#[cfg(feature = "multi-thread")]
#[repr(C)]
pub struct zp_task_read_options_t {
    pub task_attributes: *mut crate::sync::z_task_attr_t,
}

/// pico `zp_task_lease_options_t`, 8 B measured.
#[cfg(feature = "multi-thread")]
#[repr(C)]
pub struct zp_task_lease_options_t {
    pub task_attributes: *mut crate::sync::z_task_attr_t,
}

// The LP64 header's numbers (the crate root says how a 32-bit image is pinned).
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(
        core::mem::size_of::<z_subscriber_options_t>()
            == if cfg!(feature = "local-subscriber") {
                4
            } else {
                1
            }
    );
    assert!(
        core::mem::size_of::<z_open_options_t>()
            == match (
                cfg!(feature = "multi-thread"),
                cfg!(feature = "admin-space")
            ) {
                (true, true) => 24,
                (true, false) => 16,
                (false, _) => 1,
            }
    );
    assert!(core::mem::size_of::<z_close_options_t>() == 1);
};

#[cfg(all(feature = "multi-thread", target_pointer_width = "64"))]
const _: () = {
    assert!(core::mem::size_of::<zp_task_read_options_t>() == 8);
    assert!(core::mem::size_of::<zp_task_lease_options_t>() == 8);
};

// The flag follows the two task flags and the attributes pointer, which the flags' padding
// aligns: two words in on any host (16 B on a 64-bit one).
#[cfg(feature = "admin-space")]
const _: () = assert!(
    core::mem::offset_of!(z_open_options_t, auto_start_admin_space)
        == if cfg!(feature = "multi-thread") {
            2 * core::mem::size_of::<*mut c_void>()
        } else {
            0
        }
);

/// Fill default subscriber options (pico `z_subscriber_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_options_default(options: *mut z_subscriber_options_t) {
    if !options.is_null() {
        // `options->allowed_origin = z_locality_default();` with the switch on.
        #[cfg(feature = "local-subscriber")]
        {
            (*options).allowed_origin = crate::locality::Z_LOCALITY_ANY;
        }
        #[cfg(not(feature = "local-subscriber"))]
        {
            (*options).__dummy = 0;
        }
    }
}

/// Fill default open options (pico `z_open_options_default`): the read task
/// starts and the lease task does not (`vendor/zenoh-pico/src/api/api.c` @
/// `options->auto_start_lease_task = false;`). The lease flag was written TRUE
/// here, which nothing observed while `z_open` ignored the options and a
/// byte-for-byte comparison with the real library found.
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_open_options_default(options: *mut z_open_options_t) {
    if !options.is_null() {
        *options = z_open_options_t {
            #[cfg(feature = "multi-thread")]
            auto_start_read_task: true,
            #[cfg(feature = "multi-thread")]
            auto_start_lease_task: false,
            #[cfg(feature = "multi-thread")]
            executor_task_attributes: core::ptr::null_mut(),
            // `options->auto_start_admin_space = false;` in pico's default.
            #[cfg(feature = "admin-space")]
            auto_start_admin_space: false,
            // pico's single-threaded default writes nothing to `__dummy`; zero is what a
            // whole-struct write here can say about it.
            #[cfg(not(any(feature = "multi-thread", feature = "admin-space")))]
            __dummy: 0,
        };
    }
}

/// Fill default close options (pico `z_close_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_close_options_default(options: *mut z_close_options_t) {
    if !options.is_null() {
        (*options).__dummy = 0;
    }
}

/// Fill default read-task options (pico `zp_task_read_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn zp_task_read_options_default(options: *mut zp_task_read_options_t) {
    if !options.is_null() {
        (*options).task_attributes = core::ptr::null_mut();
    }
}

/// Fill default lease-task options (pico `zp_task_lease_options_default`).
///
/// # Safety
/// `options` must be null or valid and writable.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn zp_task_lease_options_default(options: *mut zp_task_lease_options_t) {
    if !options.is_null() {
        (*options).task_attributes = core::ptr::null_mut();
    }
}

/// Whether the session's READ task is running (pico `zp_read_task_is_running`):
/// whether its executor is started, which `auto_start_read_task` and
/// `zp_start_read_task` / `zp_stop_read_task` decide, and which a closed session
/// is not.
///
/// pico answers the lease task's question from the same flag
/// (`vendor/zenoh-pico/src/api/api.c` @ `bool zp_lease_task_is_running(`), so
/// [`zp_lease_task_is_running`] is this function: its executor runs both.
///
/// # Safety
/// `zs` must be null or a live loaned session.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn zp_read_task_is_running(zs: *const z_loaned_session_t) -> bool {
    session_handle(zs).is_some_and(|handle| handle.drive.read_task_is_running())
}

/// Whether the session's LEASE task is running (pico
/// `zp_lease_task_is_running`). See [`zp_read_task_is_running`].
///
/// # Safety
/// `zs` must be null or a live loaned session.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn zp_lease_task_is_running(zs: *const z_loaned_session_t) -> bool {
    zp_read_task_is_running(zs)
}

/// pico's default priority (pico `z_priority_default`) — `Z_PRIORITY_DATA`.
#[no_mangle]
pub extern "C" fn z_priority_default() -> crate::qos::z_priority_t {
    crate::qos::Z_PRIORITY_DEFAULT
}

/// pico's default reliability (pico `z_reliability_default`) —
/// `Z_RELIABILITY_RELIABLE`, which is 0 on this ABI and 1 in wz's own enum.
#[cfg(feature = "unstable-api")]
#[no_mangle]
pub extern "C" fn z_reliability_default() -> crate::pubsub::z_reliability_t {
    crate::pubsub::Z_RELIABILITY_RELIABLE
}

#[cfg(test)]
mod build_numbers {
    use super::*;
    use wz_session_core::caps;
    use wz_session_core::limit_binding::{OutsideLimitDomain, Quota};

    /// A value other than `build`, inside the range every limit of these tests declares.
    fn another(build: usize) -> usize {
        if build > 1 {
            build - 1
        } else {
            build + 1
        }
    }

    /// `check` run on the build's snapshot with one limit stated through `select`. A build that
    /// keeps the build's value alone refuses the statement itself and leaves the snapshot as it
    /// was, and that refusal is what such a build is checked for.
    fn stated(
        select: impl FnOnce(&mut SessionLimits) -> Result<(), OutsideLimitDomain>,
        check: impl FnOnce(SessionLimits),
    ) {
        let mut limits = SessionLimits::defaults();
        match select(&mut limits) {
            Ok(()) => check(limits),
            Err(refused) => {
                assert!(
                    refused.domain.is_singleton(),
                    "{} refused {}",
                    refused.limit,
                    refused.value
                );
                assert_eq!(limits, SessionLimits::defaults());
            }
        }
    }

    /// `PICO_UNICAST_BATCH_BYTES` with nothing stated: an open advertises the build's batch size
    /// in its InitSyn, as it did while it read the build's constant.
    #[test]
    fn pico_unicast_batch_bytes_with_nothing_stated_holds_the_builds_value() {
        assert_eq!(
            usize::from(pico_unicast_batch(&SessionLimits::defaults())),
            caps::PICO_UNICAST_BATCH_BYTES
        );
    }

    /// `PICO_UNICAST_BATCH_BYTES` stated: the batch size an open advertises is the stated one.
    #[test]
    fn pico_unicast_batch_bytes_stated_is_the_batch_an_open_advertises() {
        let value = another(caps::PICO_UNICAST_BATCH_BYTES);
        stated(
            |limits| limits.select_pico_unicast_batch_bytes(value),
            |limits| {
                assert_eq!(usize::from(pico_unicast_batch(&limits)), value);
            },
        );
    }

    /// The row of the report named `part`.
    #[cfg(feature = "session-memory")]
    fn memory_row(
        memory: &wz_session_core::session_memory::SessionMemory,
        part: &core::ffi::CStr,
    ) -> wz_session_core::session_memory::MemoryRow {
        *memory
            .rows()
            .iter()
            .find(|row| row.part == part)
            .expect("the report has the part")
    }

    /// `PICO_UNICAST_BATCH_BYTES` stated: the report of a session's memory counts each link's
    /// queued batches at the stated size, as many as the queue the open builds from the same
    /// snapshot, and its tables for that snapshot.
    #[cfg(feature = "session-memory")]
    #[test]
    fn session_memory_counts_the_stated_unicast_batch() {
        let value = another(caps::PICO_UNICAST_BATCH_BYTES);
        stated(
            |limits| limits.select_pico_unicast_batch_bytes(value),
            |limits| {
                let (tx_queue, _) = pico_link_policy(&SessionPolicy::defaults(), &limits);
                let basis = memory_basis(None, &tx_queue, &limits);
                assert_eq!(basis.limits, limits);
                let queue = memory_row(&basis.report(), c"link transmit queues");
                assert_eq!(queue.entry_bytes, value);
                assert_eq!(queue.count, Some(tx_queue.sizes.iter().sum()));
            },
        );
    }

    /// `PICO_FRAG_MAX_BYTES` stated: the report counts each link's two reassemblies at the
    /// stated size, and a snapshot that states no bound leaves the row without a count.
    #[cfg(feature = "session-memory")]
    #[test]
    fn session_memory_counts_the_stated_reassembly() {
        let tx_queue =
            |limits: &SessionLimits| pico_link_policy(&SessionPolicy::defaults(), limits).0;
        let value = another(caps::PICO_FRAG_MAX_BYTES);
        stated(
            |limits| limits.select_pico_frag_max_bytes(Quota::at_most(value)),
            |limits| {
                let memory = memory_basis(None, &tx_queue(&limits), &limits).report();
                let reassembly = memory_row(&memory, c"link reassembly");
                assert_eq!((reassembly.count, reassembly.entry_bytes), (Some(2), value));
            },
        );
        stated(
            |limits| limits.select_pico_frag_max_bytes(Quota::UNBOUNDED),
            |limits| {
                let memory = memory_basis(None, &tx_queue(&limits), &limits).report();
                assert_eq!(memory_row(&memory, c"link reassembly").count, None);
                assert_eq!(memory.total(), None);
            },
        );
    }

    /// `PICO_MULTICAST_BATCH_BYTES` with nothing stated: a group's Join states the build's batch
    /// size.
    #[cfg(feature = "multicast-transport")]
    #[test]
    fn pico_multicast_batch_bytes_with_nothing_stated_holds_the_builds_value() {
        let profile = pico_group(SnResolution::Bits32, &SessionLimits::defaults());
        assert_eq!(
            usize::from(profile.batch_size),
            caps::PICO_MULTICAST_BATCH_BYTES
        );
    }

    /// `PICO_MULTICAST_BATCH_BYTES` stated: a group's Join states the stated batch size, and the
    /// unicast batch keeps the build's.
    #[cfg(feature = "multicast-transport")]
    #[test]
    fn pico_multicast_batch_bytes_stated_is_the_batch_the_join_states() {
        let value = another(caps::PICO_MULTICAST_BATCH_BYTES);
        stated(
            |limits| limits.select_pico_multicast_batch_bytes(value),
            |limits| {
                assert_eq!(
                    usize::from(pico_group(SnResolution::Bits32, &limits).batch_size),
                    value
                );
                assert_eq!(
                    usize::from(pico_unicast_batch(&limits)),
                    caps::PICO_UNICAST_BATCH_BYTES
                );
            },
        );
    }

    /// `PICO_LEASE_MS` with nothing stated: an open advertises the build's lease, and so does a
    /// group's Join.
    #[test]
    fn pico_lease_ms_with_nothing_stated_holds_the_builds_value() {
        let limits = SessionLimits::defaults();
        assert_eq!(pico_lease_ms(&limits), caps::PICO_LEASE_MS as u64);
        #[cfg(feature = "multicast-transport")]
        assert_eq!(
            pico_group(SnResolution::Bits32, &limits).lease_ms,
            caps::PICO_LEASE_MS as u64
        );
    }

    /// `PICO_LEASE_MS` stated: the lease an open advertises, and a group's Join states, is the
    /// stated one.
    #[test]
    fn pico_lease_ms_stated_is_the_lease_an_open_advertises() {
        let value = another(caps::PICO_LEASE_MS);
        stated(
            |limits| limits.select_pico_lease_ms(value),
            |limits| {
                assert_eq!(pico_lease_ms(&limits), value as u64);
                #[cfg(feature = "multicast-transport")]
                assert_eq!(
                    pico_group(SnResolution::Bits32, &limits).lease_ms,
                    value as u64
                );
            },
        );
    }

    /// `PICO_SOCKET_TIMEOUT_MS` with nothing stated: a read step of the cooperative engine waits
    /// the build's time on its links.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    fn pico_socket_timeout_ms_with_nothing_stated_holds_the_builds_value() {
        assert_eq!(
            pico_socket_timeout(&SessionLimits::defaults()) as usize,
            caps::PICO_SOCKET_TIMEOUT_MS
        );
    }

    /// `PICO_SOCKET_TIMEOUT_MS` stated: a read step of the cooperative engine waits the stated
    /// time.
    #[cfg(not(feature = "engine-tokio"))]
    #[test]
    fn pico_socket_timeout_ms_stated_is_the_wait_of_a_read_step() {
        let value = another(caps::PICO_SOCKET_TIMEOUT_MS);
        stated(
            |limits| limits.select_pico_socket_timeout_ms(value),
            |limits| {
                assert_eq!(pico_socket_timeout(&limits) as usize, value);
            },
        );
    }

    /// `PICO_CONNECT_TIMEOUT_MS` with nothing stated: each open of an endpoint, and the
    /// handshake the session machine holds, is bounded by the build's time.
    #[test]
    fn pico_connect_timeout_ms_with_nothing_stated_holds_the_builds_value() {
        let limits = SessionLimits::defaults();
        let build = caps::PICO_CONNECT_TIMEOUT_MS as u64;
        #[cfg(feature = "engine-tokio")]
        assert_eq!(
            pico_dial_phase(&limits).open_timeout,
            core::time::Duration::from_millis(build)
        );
        #[cfg(not(feature = "engine-tokio"))]
        assert_eq!(pico_session_timeouts(&limits).opening_ms, build);
    }

    /// `PICO_CONNECT_TIMEOUT_MS` stated: each open of an endpoint, and its handshake, is bounded
    /// by the stated time.
    #[test]
    fn pico_connect_timeout_ms_stated_is_the_bound_of_an_open() {
        let value = another(caps::PICO_CONNECT_TIMEOUT_MS);
        stated(
            |limits| limits.select_pico_connect_timeout_ms(value),
            |limits| {
                #[cfg(feature = "engine-tokio")]
                assert_eq!(
                    pico_dial_phase(&limits).open_timeout,
                    core::time::Duration::from_millis(value as u64)
                );
                #[cfg(not(feature = "engine-tokio"))]
                assert_eq!(pico_session_timeouts(&limits).opening_ms, value as u64);
            },
        );
    }

    /// `PICO_ACCEPT_TIMEOUT_MS` with nothing stated: a listening session gives an inbound link the
    /// build's time to complete its handshake.
    #[test]
    fn pico_accept_timeout_ms_with_nothing_stated_holds_the_builds_value() {
        let limits = SessionLimits::defaults();
        let build = caps::PICO_ACCEPT_TIMEOUT_MS as u64;
        #[cfg(feature = "engine-tokio")]
        assert_eq!(pico_accept(&limits).timeout_ms, build);
        #[cfg(not(feature = "engine-tokio"))]
        assert_eq!(
            pico_session_timeouts(&limits).accepting_inactivity_ms,
            build
        );
    }

    /// `PICO_ACCEPT_TIMEOUT_MS` stated: a listening session gives an inbound link the stated time,
    /// and the count of pending accepts stays upstream's.
    #[test]
    fn pico_accept_timeout_ms_stated_is_the_time_an_inbound_link_is_given() {
        let value = another(caps::PICO_ACCEPT_TIMEOUT_MS);
        stated(
            |limits| limits.select_pico_accept_timeout_ms(value),
            |limits| {
                #[cfg(feature = "engine-tokio")]
                {
                    let accept = pico_accept(&limits);
                    assert_eq!(accept.timeout_ms, value as u64);
                    assert_eq!(
                        accept.pending,
                        wz_capi_core::runtime::config::ACCEPT_PENDING
                    );
                }
                #[cfg(not(feature = "engine-tokio"))]
                assert_eq!(
                    pico_session_timeouts(&limits).accepting_inactivity_ms,
                    value as u64
                );
            },
        );
    }

    /// `PICO_KEEPALIVES_PER_LEASE` with nothing stated: the keepalive divides the adopted lease
    /// by the build's factor.
    #[test]
    fn pico_keepalives_per_lease_with_nothing_stated_holds_the_builds_value() {
        let keep_alive = pico_keep_alive(&SessionLimits::defaults());
        assert_eq!(
            keep_alive.per_lease as usize,
            caps::PICO_KEEPALIVES_PER_LEASE
        );
    }

    /// `PICO_KEEPALIVES_PER_LEASE` stated: the keepalive divides the adopted lease by the stated
    /// factor.
    #[test]
    fn pico_keepalives_per_lease_stated_is_the_factor_the_keepalive_divides_by() {
        let value = another(caps::PICO_KEEPALIVES_PER_LEASE);
        stated(
            |limits| limits.select_pico_keepalives_per_lease(value),
            |limits| {
                let (own, adopted) = (10_000u64, 6_000u64);
                assert_eq!(
                    pico_keep_alive(&limits).interval_ms(own, adopted),
                    adopted / value as u64
                );
            },
        );
    }

    /// `PICO_FRAG_MAX_BYTES` with nothing stated: an open's links rejoin a chain up to the build's
    /// size, as they did while they read the build's constant.
    #[test]
    fn pico_frag_max_bytes_with_nothing_stated_admits_what_the_build_admitted() {
        assert_eq!(
            pico_link_rx(&SessionLimits::defaults()).max_message_size,
            caps::PICO_FRAG_MAX_BYTES
        );
    }

    /// `PICO_FRAG_MAX_BYTES` stated as two: an open's links rejoin a chain of two bytes and end
    /// one of three, which the session's reassembly holds to the bound it is handed; the rest of
    /// what the links are told is unchanged.
    #[test]
    fn pico_frag_max_bytes_stated_as_two_refuses_the_next() {
        stated(
            |limits| limits.select_pico_frag_max_bytes(Quota::at_most(2)),
            |limits| {
                let link_rx = pico_link_rx(&limits);
                assert_eq!(link_rx.max_message_size, 2);
                assert_eq!(
                    LinkRxConf {
                        max_message_size: caps::PICO_FRAG_MAX_BYTES,
                        ..link_rx
                    },
                    pico_link_rx(&SessionLimits::defaults())
                );
            },
        );
    }

    /// The tokio engine's open holds each open of an endpoint, and its handshake, to the bound the
    /// snapshot states for pico's `Z_TRANSPORT_CONNECT_TIMEOUT`, as the cooperative engine's open
    /// does, and not to zenoh's `transport/unicast/open_timeout`; it re-opens a lost session every
    /// second, and is otherwise the one attempt every open here makes.
    #[cfg(feature = "engine-tokio")]
    #[test]
    fn the_tokio_open_is_held_to_the_connect_timeout_the_snapshot_states() {
        let phase = pico_dial_phase(&SessionLimits::defaults());
        assert_eq!(
            phase.redial,
            Some(wz_capi_core::runtime::retry_period::RetryPolicy::constant(
                1000
            ))
        );
        assert_eq!(
            DialPhase {
                redial: DialPhase::ONCE.redial,
                open_timeout: DialPhase::ONCE.open_timeout,
                ..phase
            },
            DialPhase::ONCE
        );
    }

    /// The keepalive of this ABI divides the ADOPTED lease by the factor the snapshot states for
    /// pico's `Z_TRANSPORT_LEASE_EXPIRE_FACTOR`, as pico's task does, and not the session's own
    /// lease as zenoh does.
    #[test]
    fn the_keepalive_divides_the_adopted_lease_by_the_snapshots_factor() {
        let keep_alive = pico_keep_alive(&SessionLimits::defaults());
        let factor = u64::from(keep_alive.per_lease);
        let (own, adopted) = (10_000u64, 6_000u64);
        assert_eq!(
            keep_alive.interval_ms(own, adopted),
            adopted / factor,
            "pico divides the lease it adopted at the handshake"
        );
        // Control: the zenoh interface divides the other lease, so the number above is the
        // basis this ABI states and not one every interface shares.
        assert_ne!(
            KeepAliveConf::zenoh(keep_alive.per_lease).interval_ms(own, adopted),
            keep_alive.interval_ms(own, adopted)
        );
    }

    /// What an open is given of its links follows the snapshot it is handed and not the build:
    /// the width its handshake advertises and the two policies its transmit queue carries.
    #[test]
    fn the_links_of_an_open_follow_the_snapshot_it_is_handed() {
        let build = SessionPolicy::defaults();
        let other = if build.sn_resolution() == SnResolution::Bits16 {
            SnResolution::Bits8
        } else {
            SnResolution::Bits16
        };
        let mut handed = SessionPolicy::defaults();
        if handed.select_sn_resolution(other).is_err() {
            // The build allows one width: there is no other snapshot to hand.
            return;
        }
        let limits = SessionLimits::defaults();
        let (queue, width) = pico_link_policy(&handed, &limits);
        assert_eq!(width, other);
        assert_eq!(queue, TxQueueConf::pico_of_snapshot(&handed, &limits));
        // Control: the open that resolves its own snapshot is given the build's width.
        let config = ConfigState::default();
        let resolved = resolve_policy(&config.policies).unwrap();
        assert_eq!(
            pico_link_policy(&resolved.policy, &resolved.limits.session).1,
            build.sn_resolution()
        );
    }

    /// Pico's group Join states the width the `sn-resolution` policy states, each value its own
    /// code, and nothing else of pico's Join moves with it: pico refuses a member whose Join
    /// states another batch size or width than its own.
    #[cfg(feature = "multicast-transport")]
    #[test]
    fn the_join_states_the_width_the_sn_resolution_policy_states() {
        use wz_session_core::policy::SnResolution;
        let limits = SessionLimits::defaults();
        let default = pico_group(SnResolution::Bits32, &limits);
        for (width, code) in [
            (SnResolution::Bits32, 0x02),
            (SnResolution::Bits8, 0x00),
            (SnResolution::Bits16, 0x01),
            (SnResolution::Bits64, 0x03),
        ] {
            let profile = pico_group(width, &limits);
            assert_eq!(profile.seq_num_res, code, "{}", width.id());
            assert_eq!(profile.req_id_res, default.req_id_res);
            assert_eq!(profile.batch_size, default.batch_size);
            assert_eq!(profile.lease_ms, default.lease_ms);
        }
    }

    /// Pico states no cap on a group's members, and neither does its preset, whatever the width:
    /// the face it joins then holds the rows of its table and no more, which is where the preset
    /// departs from pico by decision (`docs/upstream-parity.md` section 7).
    #[cfg(feature = "multicast-transport")]
    #[test]
    fn the_pico_group_states_no_member_cap() {
        use wz_session_core::policy::SnResolution;
        let limits = SessionLimits::defaults();
        assert_eq!(
            pico_group(SessionPolicy::defaults().sn_resolution(), &limits).max_sessions,
            None
        );
        for width in [SnResolution::Bits8, SnResolution::Bits64] {
            assert_eq!(
                pico_group(width, &limits).max_sessions,
                None,
                "{}",
                width.id()
            );
        }
    }
}

#[cfg(all(test, feature = "multi-thread"))]
mod read_task_start_codes {
    use super::*;

    /// Each answer of a start of the read task is the code zenoh-pico's start answers: a start
    /// made from the task's own thread `_Z_ERR_INVALID`, and a system that gave no thread
    /// `_Z_ERR_SYSTEM_GENERIC`
    /// (`vendor/zenoh-pico/include/zenoh-pico/utils/result.h` @ `_Z_ERR_SYSTEM_GENERIC = -80,`),
    /// which is what `pthread_create`'s refusal becomes there.
    #[test]
    fn each_answer_of_a_start_is_picos_code() {
        assert_eq!(read_task_start_code(Ok(())), Z_OK);
        assert_eq!(
            read_task_start_code(Err(ReadTaskStartRefused::CalledFromReadTask)),
            Z_EINVAL
        );
        assert_eq!(
            read_task_start_code(Err(ReadTaskStartRefused::NoThread)),
            -80
        );
    }
}

#[cfg(all(test, not(feature = "engine-tokio"), feature = "peer"))]
mod session_place_tests {
    use super::*;
    use crate::abi::z_owned_config_t;
    use crate::config::{
        z_config_default, z_config_loan_mut, z_config_move, zp_config_insert, Z_CONFIG_LISTEN_KEY,
    };

    /// A copy of an owned session kept past `z_session_drop`, while the session's memory still
    /// stands (here a hold on the engine the test keeps, as a declared entity keeps one), finds the
    /// handle's place vacant: it is refused by `z_close` and by every door that reads the handle,
    /// and dropping it again lets go of nothing.
    #[test]
    fn a_session_kept_past_its_drop_is_refused_not_read() {
        // SAFETY: every pointer is to a live owned value of this frame, and the copy is read only
        // while the engine the test holds keeps the session's arena standing.
        unsafe {
            let mut config: z_owned_config_t = core::mem::zeroed();
            assert_eq!(z_config_default(&mut config), Z_OK);
            assert_eq!(
                zp_config_insert(
                    z_config_loan_mut(&mut config),
                    Z_CONFIG_LISTEN_KEY,
                    c"tcp/127.0.0.1:0".as_ptr()
                ),
                Z_OK
            );
            let mut session = z_owned_session_t::null_value();
            assert_eq!(
                z_open(&mut session, z_config_move(&mut config), core::ptr::null()),
                Z_OK
            );
            let engine = engine_of(
                session_handle(z_session_loan(&session)).expect("an open session has its handle"),
            );
            let mut copy = z_owned_session_t {
                _val: session._val,
                _cnt: session._cnt,
            };
            z_session_drop(z_session_move(&mut session));
            assert!(session._val.is_null(), "the owned session is emptied");
            assert!(engine.is_closed(), "the drop closed the session");
            assert!(
                session_handle(z_session_loan(&copy)).is_none(),
                "the copy finds the handle's place vacant"
            );
            assert_eq!(
                z_close(z_session_loan_mut(&mut copy), core::ptr::null()),
                Z_ERR_SESSION_CLOSED
            );
            z_session_drop(z_session_move(&mut copy));
            assert!(copy._val.is_null(), "dropping the copy lets go of nothing");
            drop(engine);
        }
    }
}

#[cfg(all(test, not(feature = "engine-tokio"), not(feature = "app-transport")))]
mod static_dispatch_tests {
    use core::any::TypeId;

    use super::{Engine, HeldDrive, HostLinks, SessionClockOf};

    /// A build of one engine reaches it as its own type: the engine an entity keeps and the drive
    /// the handle holds are the cooperative engine over the links the open composes, not the
    /// port's trait objects, so no table of the engine's functions is made.
    #[test]
    fn a_build_of_one_engine_reaches_it_as_its_own_type() {
        assert_eq!(
            TypeId::of::<Engine>(),
            TypeId::of::<wz_capi_coop::CoopEngine<HostLinks, SessionClockOf>>()
        );
        assert_ne!(
            TypeId::of::<Engine>(),
            TypeId::of::<dyn wz_capi_port::SessionEngine>()
        );
        assert_eq!(
            TypeId::of::<HeldDrive>(),
            TypeId::of::<wz_capi_coop::CoopDrive<HostLinks, SessionClockOf>>()
        );
    }
}
