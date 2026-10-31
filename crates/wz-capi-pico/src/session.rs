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

use std::ffi::c_void;

use crate::abi::{z_moved_config_t, z_owned_config_t};
use crate::config::{
    ConfigState, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY,
    Z_CONFIG_SESSION_ZID_KEY,
};
// The twelve TLS key constants are consumed ONLY by `resolve_tls_config`, which
// exists only when a certificate has a backend that could consume it. Importing
// them at module scope would make the no-backend build carry twelve unused
// imports, which `-D warnings` rejects — so the import rides the same cfg as its
// single consumer rather than the consumer being widened to justify the import.
#[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
use crate::config::{
    Z_CONFIG_TLS_CONNECT_CERTIFICATE_BASE64_KEY, Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY,
    Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_BASE64_KEY, Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY,
    Z_CONFIG_TLS_ENABLE_MTLS_KEY, Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY,
    Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY, Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY,
    Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY, Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY,
    Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY, Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY,
};
use crate::ffi::{guard_val, guarded};
// The read-task doors' refusal, which only the multi-threaded arm has.
#[cfg(feature = "multi-thread")]
use crate::result::Z_EINVAL;
#[cfg(feature = "engine-tokio")]
use crate::result::Z_ERR_GENERIC;
use crate::result::{ZResult, Z_ERR_NULL, Z_ERR_SESSION_CLOSED, Z_OK};
#[cfg(feature = "engine-tokio")]
use wz_capi_core::drive::{
    open_blocking, CapiTlsConfig, DialPhase, OpenError, OpenStance, SessionState,
};
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

/// A batch size of this ABI as the wire carries it, in two bytes: a number of
/// [`wz_session_core::caps`], refused when the build is made if it states one past `u16::MAX`.
const fn pico_batch(bytes: usize) -> u16 {
    assert!(
        bytes <= u16::MAX as usize,
        "a zenoh-pico batch size is at most 65535 bytes"
    );
    bytes as u16
}

/// What a session of this ABI rejoins from fragments, unicast and in a group, on either engine:
/// pico's `FRAG_MAX_SIZE` as the build states it, whose rule is upstream's
/// `transport/link/rx/max_message_size` (a chain a fragment would take past it is dropped,
/// `vendor/zenoh-pico/src/transport/unicast/rx.c` @
/// `if ((_z_wbuf_len(dbuf) + msg->_payload.len) > Z_FRAG_MAX_SIZE) {`).
const PICO_LINK_RX: LinkRxConf = LinkRxConf {
    max_message_size: wz_session_core::caps::PICO_FRAG_MAX_BYTES,
};

/// How long a listening session of this ABI gives an inbound link, pico's
/// `Z_TRANSPORT_ACCEPT_TIMEOUT` as the build states it. pico bounds no count of pending accepts
/// (it accepts one link at a time on its read task), so the count is upstream's rather than
/// none: a bound pico never refused on is no worse than zenoh's.
#[cfg(feature = "engine-tokio")]
const PICO_ACCEPT: wz_capi_core::runtime::accept_bounds::AcceptBounds =
    wz_capi_core::runtime::accept_bounds::AcceptBounds {
        timeout_ms: wz_session_core::caps::PICO_ACCEPT_TIMEOUT_MS as u64,
        pending: wz_capi_core::runtime::config::ACCEPT_PENDING,
    };

/// How often a session of this ABI sends a keepalive on an idle link, on either engine: pico's
/// `Z_TRANSPORT_LEASE_EXPIRE_FACTOR` as the build states it, dividing the adopted lease. Refused
/// when the build is made if the build states none (a division by zero in pico's own task).
const PICO_KEEP_ALIVE: KeepAliveConf = KeepAliveConf::pico(pico_keepalives_per_lease(
    wz_session_core::caps::PICO_KEEPALIVES_PER_LEASE,
));

/// The factor as a `u32`, at least 1.
const fn pico_keepalives_per_lease(factor: usize) -> u32 {
    assert!(
        factor >= 1 && factor <= u32::MAX as usize,
        "zenoh-pico divides its lease by a factor of at least 1"
    );
    factor as u32
}

/// The cooperative engine's read wait, in milliseconds: a number of [`wz_session_core::caps`],
/// refused when the build is made if it is past what the engine's wait holds.
#[cfg(not(feature = "engine-tokio"))]
const fn pico_socket_timeout(ms: usize) -> u32 {
    assert!(
        ms <= u32::MAX as usize,
        "a zenoh-pico socket timeout is at most u32::MAX ms"
    );
    ms as u32
}

/// What pico's JOIN advertises on a group (`vendor/zenoh-pico/src/protocol/definitions/transport.c`
/// @ `_z_transport_message_t _z_t_msg_make_join(`): its `Z_TRANSPORT_LEASE`, beaconed every
/// `Z_JOIN_INTERVAL` (2500 ms), its `Z_SN_RESOLUTION` and `Z_REQ_RESOLUTION` (0x02 each), its
/// `Z_BATCH_MULTICAST_SIZE`, and no per-priority conduits. The lease and the batch size are build
/// switches of pico's (`BATCH_MULTICAST_SIZE`, `Z_TRANSPORT_LEASE` in its CMakeLists), so they are
/// the numbers this build states for them ([`wz_session_core::caps::PICO_LEASE_MS`],
/// [`wz_session_core::caps::PICO_MULTICAST_BATCH_BYTES`]), pico's own by default: pico refuses a
/// member whose Join states another batch size. The join interval and the two resolutions are
/// fixed in pico's config template, not switches; the build's `sn-resolution` policy
/// ([`wz_session_core::policy::SnResolution`]) states another width of the sequence number for a
/// group whose members are built with one, as pico refuses a Join that states another than its own.
#[cfg(feature = "multicast-transport")]
const fn pico_group(
    sn_resolution: wz_session_core::policy::SnResolution,
) -> wz_capi_core::drive::GroupProfile {
    wz_capi_core::drive::GroupProfile {
        lease_ms: wz_session_core::caps::PICO_LEASE_MS as u64,
        join_interval_ms: 2_500,
        seq_num_res: sn_resolution.wire_code(),
        req_id_res: 0x02,
        batch_size: pico_batch(wz_session_core::caps::PICO_MULTICAST_BATCH_BYTES),
        is_qos: false,
        compression: false,
    }
}

/// The group profile of this build.
#[cfg(feature = "multicast-transport")]
const PICO_GROUP: wz_capi_core::drive::GroupProfile =
    pico_group(wz_session_core::policy::SessionPolicy::from_build().sn_resolution);

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
#[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
fn resolve_pem(
    cfg: &ConfigState,
    path_key: u8,
    base64_key: u8,
) -> Result<Option<Vec<u8>>, ZResult> {
    if let Some(path) = cfg.get(path_key) {
        return wz_capi_core::runtime::tls_config::read_pem_file(path)
            .map(Some)
            .map_err(|_| crate::result::Z_ERR_INVALID);
    }
    if let Some(b64) = cfg.get(base64_key) {
        return wz_capi_core::runtime::tls_config::decode_base64_pem(b64)
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
#[cfg(any(feature = "transport-link-tls", feature = "transport-link-quic"))]
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
    not(any(feature = "transport-link-tls", feature = "transport-link-quic"))
))]
pub(crate) fn resolve_tls_config(_cfg: &ConfigState) -> Result<CapiTlsConfig, ZResult> {
    Ok(CapiTlsConfig::default())
}

/// The files [`resolve_tls_config`] reads: each of its keys that names the PEM by path, the
/// client certificate's two only when mTLS is on, as it reads them. Read by
/// `wz_ext_config_device_requires` only, so it is part of the unstable surface.
#[cfg(all(
    feature = "unstable-api",
    any(feature = "transport-link-tls", feature = "transport-link-quic")
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
    not(any(feature = "transport-link-tls", feature = "transport-link-quic"))
))]
pub(crate) fn tls_files_named(_cfg: &ConfigState) -> Vec<String> {
    Vec::new()
}

// --- ABI structs (session owned = pico rc `{ void* _val; void* _cnt }`) ----

/// Owned session (pico `z_owned_session_t`, 16 B rc). `_val` carries our
/// `Box<PicoSessionHandle>`; `_cnt` is unused.
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
            _val: std::ptr::null_mut(),
            _cnt: std::ptr::null_mut(),
        }
    }
}

/// What a C session handle points at: the engine's session, behind the port, and what this ABI
/// keeps per session itself (`docs/capi-pico-on-coop-engine.md`, decision D7).
pub(crate) struct PicoSessionHandle {
    /// The session as the engine runs it. Made by the engine (`into_drive`), so its drop glue is
    /// the engine crate's and not a second copy here.
    pub(crate) drive: Box<dyn wz_capi_port::SessionDrive>,
    /// The session's role, clock, connectivity listeners and admin space.
    pub(crate) ext: crate::session_ext::PicoSessionExt,
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
/// `Box::into_raw::<PicoSessionHandle>` pointer (what [`z_open`] installs).
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
    Some(&*(val as *const PicoSessionHandle))
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
pub(crate) type Engine = dyn wz_capi_port::SessionEngine;

/// The engine behind a session handle, to keep: what an entity declared on the session holds for
/// its own life. The engine hands itself out, so this crate never turns an engine's own type into
/// the port's, which would instantiate the engine's drop glue a second time here.
pub(crate) fn engine_of(handle: &PicoSessionHandle) -> std::sync::Arc<Engine> {
    handle.drive.engine()
}

/// The engine behind a session handle, for the length of one call: a put or a delete reaches the
/// engine without touching its reference count.
pub(crate) fn engine_ref(handle: &PicoSessionHandle) -> &Engine {
    handle.drive.engine_ref()
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
        if zs.is_null() || config.is_null() {
            return Z_ERR_NULL;
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
            return Z_ERR_NULL;
        }
        // z_open consumes the config: take ownership and null the source so a
        // defensive later `z_config_drop` is a safe no-op.
        let cfg = Box::from_raw(cfg_handle as *mut ConfigState);
        (*config)._this = z_owned_config_t::null_value();

        let open = open_config(&cfg);
        // The id the session opens on, refused here if the config names one pico's reader cannot
        // take (see [`session_zid`]).
        let zid = match session_zid(&open) {
            Ok(zid) => zid,
            Err(code) => return code,
        };
        let OpenConfig {
            connect,
            listen,
            dial_whatami,
            zid: _,
        } = open;
        // R311y406 / R311y534 — the TLS material, RESOLVED here (path or inline
        // base64 -> PEM bytes) because the key numbers are this ABI's knowledge.
        // A malformed value fails the open rather than degrading to a plaintext
        // or trust-free session: a caller that asked for TLS and silently got
        // something else is the one outcome worse than a failed z_open.
        #[cfg(feature = "engine-tokio")]
        let tls = match resolve_tls_config(&cfg) {
            Ok(tls) => tls,
            Err(code) => return code,
        };
        // The connect locators: the configured one, or with neither locator configured the
        // first scouted node's (`vendor/zenoh-pico/src/net/session.c` @
        // `ret = _z_locators_by_scout(config, zid, &connect_locators);`), whose build without
        // scouting answers `_Z_ERR_SCOUT_NO_RESULTS`. A session that is re-dialled after it
        // lost its link dials the locators found here again. pico re-runs the whole open,
        // scouting included (`_z_client_reopen_task_fn` calls `_z_open`), so a router that
        // comes back on another locator is found there and not here.
        let connect: Vec<String> = match (connect, &listen) {
            (Some(connect), _) => vec![connect],
            (None, Some(_)) => Vec::new(),
            #[cfg(feature = "scout")]
            (None, None) => match crate::scout::locators_by_scout(&cfg) {
                Ok(locators) => locators,
                Err(code) => return code,
            },
            #[cfg(not(feature = "scout"))]
            (None, None) => return crate::result::Z_ERR_SCOUT_NO_RESULTS,
        };
        drop(cfg);
        // A build without the `peer` feature is a client build: it opens to the endpoint it is
        // given, and a listener or `mode=peer` is a role it does not have. (zenoh-pico's own
        // `Z_FEATURE_UNICAST_PEER` gates less: a build without it still takes a lone listener,
        // refusing only the combined listen and connect and a second connect locator. This
        // feature is the stronger cut, for a device that only ever dials out.)
        #[cfg(not(feature = "peer"))]
        if listen.is_some() || dial_whatami != WhatAmI::Client {
            return crate::result::Z_ERR_INVALID;
        }
        // A config carrying BOTH connect and listen is pico's dual-role listen-and-dial peer:
        // `_z_locators_by_config` refuses the pair only in a build without unicast peers and
        // otherwise forces the mode to peer for any listen config and goes on
        // (`vendor/zenoh-pico/src/net/session.c` @ `static z_result_t _z_locators_by_config(`).
        // The core runs it (a listener bound before the dial, an accept loop beside the dial
        // face), so it is not refused. Until R3090 it was, with `Z_ERR_INVALID`, and the comment
        // called it a follow-up.
        let dial_whatami = if listen.is_some() {
            WhatAmI::Peer
        } else {
            dial_whatami
        };
        let request = OpenRequest {
            connect,
            listen,
            dial_whatami,
            zid,
            start_read_task,
            #[cfg(feature = "admin-space")]
            start_admin_space,
            #[cfg(feature = "engine-tokio")]
            tls,
        };
        #[cfg(feature = "engine-tokio")]
        return open_on_tokio(zs, request);
        #[cfg(not(feature = "engine-tokio"))]
        return open_on_coop(zs, request);
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
    match open.zid.as_deref() {
        None => Ok(None),
        Some(text) => pico_uuid_wire(text)
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

/// Read [`OpenConfig`] off `cfg`. The dial role's whatami is config-driven, mirroring pico's
/// `_z_config_get_mode` (`~/zenoh-pico/src/net/session.c:120-140`, default CLIENT): `mode=peer`
/// opens a dialing PEER, otherwise CLIENT. (The listen role forces PEER regardless — pico
/// force-inserts `MODE=PEER` for any listen config, session.c:98.)
pub(crate) fn open_config(cfg: &ConfigState) -> OpenConfig {
    OpenConfig {
        connect: cfg.get(Z_CONFIG_CONNECT_KEY).map(str::to_owned),
        listen: cfg.get(Z_CONFIG_LISTEN_KEY).map(str::to_owned),
        dial_whatami: match cfg.get(Z_CONFIG_MODE_KEY) {
            Some("peer") => WhatAmI::Peer,
            _ => WhatAmI::Client,
        },
        zid: cfg.get(Z_CONFIG_SESSION_ZID_KEY).map(str::to_owned),
    }
}

/// What `z_open` read off the C config and its options, for the engine that opens it.
struct OpenRequest {
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
    #[cfg(feature = "engine-tokio")]
    tls: CapiTlsConfig,
}

/// Open `request` on the tokio engine and install the session in `zs`.
///
/// # Safety
/// `zs` is a valid, null-initialised `z_owned_session_t`.
#[cfg(feature = "engine-tokio")]
unsafe fn open_on_tokio(zs: *mut z_owned_session_t, request: OpenRequest) -> ZResult {
    let OpenRequest {
        connect,
        listen,
        dial_whatami,
        zid,
        start_read_task,
        #[cfg(feature = "admin-space")]
        start_admin_space,
        tls,
    } = request;
    // This ABI stays on one attempt: the retry the zenoh-c open gained reads
    // zenoh's `connect/retry` and `connect/timeout_ms`, which are zenoh-c
    // config keys, and this shim resolves pico's numeric keys instead.
    // pico's transmit model, not zenoh's: a pico put writes on the
    // caller's thread and a full socket slows it rather than dropping it
    // (see `TxQueueConf::pico`). zenoh's 1 ms drop wait here discarded the
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
            vec![wz_capi_core::drive::GroupJoin {
                endpoint,
                profile: PICO_GROUP,
                is_shm: false,
                // pico declares its entities over whatever transport it holds, a group too
                // (MEASURED off the group's wire: `decl_subscriber(1, ..)`), and with
                // `Z_FEATURE_MULTICAST_DECLARATIONS` its keyexprs and write filters as well
                // (MEASURED: `decl_kexpr(1, demo/mc/zp)`, `Interest(3, .., 1:)`).
                #[cfg(not(feature = "multicast-declarations"))]
                declarations: wz_capi_core::drive::GroupDeclarations::Entities,
                #[cfg(feature = "multicast-declarations")]
                declarations: wz_capi_core::drive::GroupDeclarations::Mapped,
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
        // R2948 — pico re-opens a lost client session by default
        // (`Z_FEATURE_AUTO_RECONNECT`), every 1000 ms
        // (`vendor/zenoh-pico/src/net/session.c` @
        // `return _z_fut_fn_result_wake_up_after(1000);`).
        DialPhase {
            redial: Some(wz_capi_core::runtime::retry_period::RetryPolicy::constant(
                1000,
            )),
            ..DialPhase::ONCE
        },
        OpenStance {
            tx_queue: TxQueueConf::pico(),
            // pico's batch size and lease are build switches of its, not config keys
            // (`BATCH_UNICAST_SIZE`, `Z_TRANSPORT_LEASE`): its InitSyn carries
            // `Z_BATCH_UNICAST_SIZE` (`vendor/zenoh-pico/src/protocol/definitions/transport.c` @
            // `msg._body._init._batch_size = Z_BATCH_UNICAST_SIZE;`), 2048 by default and not
            // zenoh's 65535, so this advertises the numbers the build states for them.
            batch_size: pico_batch(wz_session_core::caps::PICO_UNICAST_BATCH_BYTES),
            lease_ms: wz_session_core::caps::PICO_LEASE_MS as u64,
            keep_alive: PICO_KEEP_ALIVE,
            sn_resolution: wz_session_core::policy::SessionPolicy::from_build().sn_resolution,
            link_rx: PICO_LINK_RX,
            accept: PICO_ACCEPT,
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
            let ext = crate::session_ext::PicoSessionExt::new(session_mode, &zid, &drive.engine());
            #[cfg(not(feature = "connectivity"))]
            let ext = crate::session_ext::PicoSessionExt::new(session_mode, &zid);
            #[cfg(feature = "admin-space")]
            let ext = ext.with_transport_endpoint(transport_endpoint);
            let handle = PicoSessionHandle { drive, ext };
            *zs = z_owned_session_t {
                _val: Box::into_raw(Box::new(handle)) as *mut c_void,
                _cnt: std::ptr::null_mut(),
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
    }
}

/// Open `request` on the cooperative engine and install the session in `zs`: a session dialled
/// over the host's sockets, and with `peer` one that listens on the `tcp/` endpoint of its
/// `listen` key as well, opened on this thread before `z_open` returns, as the tokio engine's is.
/// A listener is open once its port is bound, as pico's `z_open(listen)` returns, and takes each
/// inbound link as a face of the session (`wz-capi-coop`'s `listen`). A group (a `udp/` endpoint
/// with an interface) is the tokio engine's alone: a build that joins one selects that engine, so
/// this one answers it as a build without the multicast transport does.
///
/// What zenoh-pico's client advertises, as the tokio engine's open does: zenoh's default batch
/// size (`transport/link/tx/batch_size`, 65535, which the link's own capacity caps), pico's lease
/// (`Z_TRANSPORT_LEASE`, 10000 ms) and pico's transmit model ([`TxQueueConf::pico`]). The zid is
/// the one `Z_CONFIG_SESSION_ZID_KEY` names, and otherwise minted, as this ABI's tokio open does.
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
    #[cfg(feature = "peer")]
    if request.listen.as_deref().is_some_and(is_group_endpoint) {
        return crate::result::Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN;
    }
    let dial_whatami = request.dial_whatami;
    let connect = request.connect;
    // The engine takes the id as the config states it, up to sixteen bytes: the form an INIT
    // carries.
    let zid = request.zid;
    // pico's config carries ONE listen locator, so the set is that one or none.
    let listen: Vec<String> = request.listen.into_iter().collect();
    // The locator pico's one transport is opened on, which its admin space reports as the
    // transport's link: the listen locator when there is one, the first connect locator
    // otherwise (`vendor/zenoh-pico/src/net/session.c` @
    // `// First, try to open the optional listen locator.`).
    #[cfg(feature = "admin-space")]
    let transport_endpoint = listen.first().or_else(|| connect.first()).cloned();
    let opened = wz_capi_coop::CoopEngine::open(
        wz_runtime_posix::links::PosixLinks::new([0; 4], wz_runtime_posix::stream::PosixTcpDial)
            .waited_by_owner(),
        wz_runtime_posix::PosixClock,
        wz_runtime_posix::PosixEntropy,
        wz_capi_coop::CoopConfig {
            endpoints: connect,
            whatami: dial_whatami,
            zid,
            // The numbers of pico's value build switches, as this build states them: the
            // batch size and lease its InitSyn carries (`BATCH_UNICAST_SIZE`,
            // `Z_TRANSPORT_LEASE`), the largest message it rejoins (`FRAG_MAX_SIZE`), how often
            // its keepalive speaks (`Z_TRANSPORT_LEASE_EXPIRE_FACTOR`) and its handshake's
            // receive deadline (`Z_TRANSPORT_CONNECT_TIMEOUT`).
            batch_size: pico_batch(wz_session_core::caps::PICO_UNICAST_BATCH_BYTES),
            lease_ms: wz_session_core::caps::PICO_LEASE_MS as u64,
            keep_alive: PICO_KEEP_ALIVE,
            sn_resolution: wz_session_core::policy::SessionPolicy::from_build().sn_resolution,
            link_rx: PICO_LINK_RX,
            tx_queue: TxQueueConf::pico(),
            // How long an inbound link may take to complete its handshake is pico's
            // `Z_TRANSPORT_ACCEPT_TIMEOUT` as the build states it, as the tokio engine's
            // `PICO_ACCEPT` says.
            timeouts: wz_session_core::session_timeouts::SessionTimeouts {
                accepting_inactivity_ms: wz_session_core::caps::PICO_ACCEPT_TIMEOUT_MS as u64,
                ..wz_session_core::session_timeouts::SessionTimeouts::spec_defaults()
            },
            open_timeout_ms: wz_session_core::caps::PICO_CONNECT_TIMEOUT_MS as u64,
            // pico tries again every 1000 ms while the reopen fails
            // (`vendor/zenoh-pico/src/net/session.c` @
            // `return _z_fut_fn_result_wake_up_after(1000);`).
            redial_ms: Some(1000),
            // A read waits on the link as long as pico's socket receive times out, its
            // `Z_CONFIG_SOCKET_TIMEOUT` as this build states it.
            idle_wait_ms: pico_socket_timeout(wz_session_core::caps::PICO_SOCKET_TIMEOUT_MS),
            // The bounds of an accept are upstream's, as the tokio engine's are
            // (`PICO_ACCEPT`): pico bounds no count of pending accepts or of sessions.
            listen,
            accept_pending: wz_capi_coop::DEFAULT_ACCEPT_PENDING,
            max_faces: wz_capi_coop::DEFAULT_MAX_FACES,
        },
    );
    let engine = match opened {
        Ok(engine) => engine,
        Err(wz_capi_coop::OpenError::EntropyUnavailable) => return crate::result::Z_ERR_GENERIC,
        Err(_) => return crate::result::Z_ERR_TRANSPORT_OPEN_FAILED,
    };
    let zid = wz_capi_port::SessionDrive::zid(&*engine);
    let drive = wz_capi_coop::CoopEngine::into_drive(engine);
    #[cfg(feature = "connectivity")]
    let ext = crate::session_ext::PicoSessionExt::new(dial_whatami, &zid, &drive.engine());
    #[cfg(not(feature = "connectivity"))]
    let ext = crate::session_ext::PicoSessionExt::new(dial_whatami, &zid);
    #[cfg(feature = "admin-space")]
    let ext = ext.with_transport_endpoint(transport_endpoint);
    let handle = PicoSessionHandle { drive, ext };
    // The multi-threaded arm's read task starts with the open unless the options say not to.
    #[cfg(feature = "multi-thread")]
    if request.start_read_task {
        let _ = handle.drive.start_read_task();
    }
    *zs = z_owned_session_t {
        _val: Box::into_raw(Box::new(handle)) as *mut c_void,
        _cnt: std::ptr::null_mut(),
    };
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

/// Close a session (pico `z_close`): stop the drive loop and join the driver
/// thread. Does not free the owned struct — that is `z_session_drop`.
#[no_mangle]
pub unsafe extern "C" fn z_close(zs: *mut z_loaned_session_t, _options: *const c_void) -> ZResult {
    guarded(|| {
        if zs.is_null() || (*zs)._val.is_null() {
            return Z_ERR_NULL;
        }
        let handle = &*((*zs)._val as *const PicoSessionHandle);
        handle.drive.close();
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
            // The engine's session closes as it drops (idempotent), through the
            // drop glue its own crate holds: the drive is the engine's trait object.
            drop(Box::from_raw(val as *mut PicoSessionHandle));
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
/// thread.
#[cfg(feature = "multi-thread")]
#[no_mangle]
pub unsafe extern "C" fn zp_start_read_task(
    zs: *mut z_loaned_session_t,
    _options: *const c_void,
) -> ZResult {
    match session_handle(zs) {
        Some(handle) => match handle.drive.start_read_task() {
            Ok(()) => Z_OK,
            Err(_) => Z_EINVAL,
        },
        None => Z_ERR_NULL,
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
        #[cfg(feature = "multicast-transport")]
        if live == Z_OK {
            if let Some(state) = session_state(zs) {
                state.shared.send_join_on_groups();
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
            engine_ref(handle).batch_start_all();
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
            engine_ref(handle).batch_flush_all();
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
            engine_ref(handle).batch_stop_all();
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
    eid: u64,
) -> crate::entity::z_entity_global_id_t {
    crate::entity::z_entity_global_id_t {
        zid: crate::zid::z_id_t { id: zs.drive.zid() },
        // TRUNCATING, and that is upstream's width rather than a loss: zenoh's
        // `_z_entity_global_id_t.eid` is a `uint32_t`, so the wire cannot carry
        // more. A session declaring 2^32 entities would wrap, which is the same
        // thing upstream does.
        eid: eid as u32,
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
    crate::ffi::guard_val(std::ptr::null(), || {
        match crate::abi::handle_ref::<
            crate::pubsub::z_loaned_publisher_t,
            crate::pubsub::PublisherState,
        >(publisher)
        {
            Some(state) => state.loaned_keyexpr(),
            None => std::ptr::null(),
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
    crate::ffi::guard_val(std::ptr::null(), || {
        match crate::abi::handle_ref::<
            crate::querier::z_loaned_querier_t,
            crate::querier::QuerierState,
        >(querier)
        {
            Some(state) => state.loaned_keyexpr(),
            None => std::ptr::null(),
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
    crate::ffi::guard_val(std::ptr::null(), || {
        match crate::abi::handle_ref::<
            crate::pubsub::z_loaned_subscriber_t,
            crate::pubsub::SubscriberState,
        >(subscriber)
        {
            Some(state) => &state.loaned_keyexpr as *const crate::abi::z_loaned_keyexpr_t,
            None => std::ptr::null(),
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
fn entity_id_of(identity: Option<([u8; 16], u64)>) -> crate::entity::z_entity_global_id_t {
    match identity {
        Some((zid, eid)) => crate::entity::z_entity_global_id_t {
            zid: crate::zid::z_id_t { id: zid },
            eid: eid as u32,
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

const _: () = {
    assert!(
        std::mem::size_of::<z_subscriber_options_t>()
            == if cfg!(feature = "local-subscriber") {
                4
            } else {
                1
            }
    );
    assert!(
        std::mem::size_of::<z_open_options_t>()
            == match (
                cfg!(feature = "multi-thread"),
                cfg!(feature = "admin-space")
            ) {
                (true, true) => 24,
                (true, false) => 16,
                (false, _) => 1,
            }
    );
    assert!(std::mem::size_of::<z_close_options_t>() == 1);
};

#[cfg(feature = "multi-thread")]
const _: () = {
    assert!(std::mem::size_of::<zp_task_read_options_t>() == 8);
    assert!(std::mem::size_of::<zp_task_lease_options_t>() == 8);
};

#[cfg(feature = "admin-space")]
const _: () = assert!(
    std::mem::offset_of!(z_open_options_t, auto_start_admin_space)
        == if cfg!(feature = "multi-thread") {
            16
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
            executor_task_attributes: std::ptr::null_mut(),
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
        (*options).task_attributes = std::ptr::null_mut();
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
        (*options).task_attributes = std::ptr::null_mut();
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
pub extern "C" fn z_priority_default() -> std::ffi::c_int {
    crate::qos::Z_PRIORITY_DEFAULT
}

/// pico's default reliability (pico `z_reliability_default`) —
/// `Z_RELIABILITY_RELIABLE`, which is 0 on this ABI and 1 in wz's own enum.
#[cfg(feature = "unstable-api")]
#[no_mangle]
pub extern "C" fn z_reliability_default() -> std::ffi::c_int {
    crate::pubsub::Z_RELIABILITY_RELIABLE
}

#[cfg(test)]
mod build_numbers {
    use super::*;

    /// The keepalive of this ABI divides the ADOPTED lease by the factor the build states for
    /// pico's `Z_TRANSPORT_LEASE_EXPIRE_FACTOR`, as pico's task does, and not the session's own
    /// lease as zenoh does.
    #[test]
    fn the_keepalive_divides_the_adopted_lease_by_the_builds_factor() {
        let factor = wz_session_core::caps::PICO_KEEPALIVES_PER_LEASE as u64;
        let (own, adopted) = (10_000u64, 6_000u64);
        assert_eq!(
            PICO_KEEP_ALIVE.interval_ms(own, adopted),
            adopted / factor,
            "pico divides the lease it adopted at the handshake"
        );
        // Control: the zenoh interface divides the other lease, so the number above is the
        // basis this ABI states and not one every interface shares.
        assert_ne!(
            KeepAliveConf::zenoh(factor as u32).interval_ms(own, adopted),
            PICO_KEEP_ALIVE.interval_ms(own, adopted)
        );
    }

    /// Pico's group Join states the width the `sn-resolution` policy states, each value its own
    /// code, and nothing else of pico's Join moves with it: pico refuses a member whose Join
    /// states another batch size or width than its own.
    #[cfg(feature = "multicast-transport")]
    #[test]
    fn the_join_states_the_width_the_sn_resolution_policy_states() {
        use wz_session_core::policy::SnResolution;
        let default = pico_group(SnResolution::Bits32);
        for (width, code) in [
            (SnResolution::Bits32, 0x02),
            (SnResolution::Bits8, 0x00),
            (SnResolution::Bits16, 0x01),
            (SnResolution::Bits64, 0x03),
        ] {
            let profile = pico_group(width);
            assert_eq!(profile.seq_num_res, code, "{}", width.id());
            assert_eq!(profile.req_id_res, default.req_id_res);
            assert_eq!(profile.batch_size, default.batch_size);
            assert_eq!(profile.lease_ms, default.lease_ms);
        }
    }
}
