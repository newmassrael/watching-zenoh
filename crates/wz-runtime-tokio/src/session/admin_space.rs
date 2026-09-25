// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2860 (§5.23 `adminspace-core`) — a Session-hosted adminspace as ONE handle,
//! holding both declarations upstream's `AdminSpace::start` makes.
//!
//! The pin declares the `@/<zid>/<whatami>/**` queryable AND a subscriber on
//! `@/<zid>/<whatami>/config/**` (`zenoh/src/net/runtime/adminspace.rs` @
//! `wire_expr: [&root_key, "/config/**"].concat().into(),`), and its push
//! handler writes each PUT into the runtime config the GET handler reads
//! (`zenoh/src/net/runtime/adminspace.rs` @ `.try_insert_json5_array_item(key, json)`).
//! `Session::declare_adminspace` declared only the queryable, so a remote
//! config write to a Session-hosted node reached nothing, and the one
//! Session host that did take writes (`wz-ap-demo`'s storage host)
//! re-implemented the handler inline.
//!
//! [`apply_admin_config_write`](crate::session::apply_admin_config_write) is
//! that handler, once, in the library: the permit gate, the decode, and the
//! write into the shared [`WzConfig`](crate::config::WzConfig) the GET
//! also reads. What a Session cannot apply by itself (a storage intent, the
//! ACL verb, a `plugins/...` key whose validator is a running plugin) goes to
//! the host through `on_intent`, so a host adds what it owns rather than
//! re-spelling what the library already does.

use std::sync::{Arc, Mutex};

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;

use super::{Queryable, QueryableError, SubscribeError};
use crate::config::WzConfig;
use crate::runtime_impl::{TokioRuntime, TokioTime};

#[cfg(feature = "adminspace-write")]
use super::Subscriber;
#[cfg(feature = "adminspace-write")]
use crate::sink::SampleView;
#[cfg(feature = "adminspace-write")]
use wz_session_core::adminspace::{AdminConfigWrite, AdminConfigWriteSpace};

/// The RAII handle for a Session-hosted adminspace: dropping it undeclares
/// both the admin queryable and the config-write subscriber, the pair
/// upstream's `AdminSpace::start` declares together.
///
/// The config-write subscriber exists only under `adminspace-write`, the
/// feature that decides whether a node HAS a config-write surface at all
/// (`crate::admin_write_permit`'s doc, R2822): a build without it declares
/// the queryable alone, which is what it means.
pub struct AdminSpace<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    queryable: Queryable<R, T>,
    #[cfg(feature = "adminspace-write")]
    config_writer: Subscriber<R>,
    config: Arc<Mutex<WzConfig>>,
}

impl<R: SessionRuntime, T: TimeSource> AdminSpace<R, T> {
    #[cfg(feature = "adminspace-core")]
    pub(super) fn new(
        queryable: Queryable<R, T>,
        #[cfg(feature = "adminspace-write")] config_writer: Subscriber<R>,
        config: Arc<Mutex<WzConfig>>,
    ) -> Self {
        Self {
            queryable,
            #[cfg(feature = "adminspace-write")]
            config_writer,
            config,
        }
    }

    /// The live config this adminspace answers from and writes into — the
    /// analogue of upstream's `runtime.config()`. A remote PUT the subscriber
    /// applies is visible here, and an embedder's own change is what the next
    /// GET reports.
    pub fn config(&self) -> &Arc<Mutex<WzConfig>> {
        &self.config
    }

    /// The admin queryable half.
    pub fn queryable(&self) -> &Queryable<R, T> {
        &self.queryable
    }

    /// The config-write subscriber half, on
    /// `@/<zid>/<whatami>/config/**`.
    #[cfg(feature = "adminspace-write")]
    pub fn config_writer(&self) -> &Subscriber<R> {
        &self.config_writer
    }
}

/// Why a Session-hosted adminspace could not be declared: which of its two
/// declarations was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminSpaceError {
    /// The admin queryable was refused. Nothing was declared.
    Queryable(QueryableError),
    /// The config-write subscriber was refused. The queryable declared just
    /// before it has been undeclared again, so nothing is left half-hosted.
    ConfigWriter(SubscribeError),
}

impl std::fmt::Display for AdminSpaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminSpaceError::Queryable(e) => write!(f, "admin queryable refused: {e}"),
            AdminSpaceError::ConfigWriter(e) => {
                write!(f, "admin config-write subscriber refused: {e}")
            }
        }
    }
}

impl std::error::Error for AdminSpaceError {}

/// What one admin GET reads of a config, taken together so the permit and the
/// rendering a reply reports come from one moment.
#[cfg(feature = "adminspace-core")]
pub(super) struct AdminConfigView {
    pub(super) permissions: wz_session_core::adminspace::AdminSpacePermissions,
    pub(super) config_json: String,
    pub(super) metadata_json: String,
}

#[cfg(feature = "adminspace-core")]
impl AdminConfigView {
    /// Read `config` under ONE lock. A poisoned lock grants nothing and
    /// reports nothing (`{}` and `null`): a host reports nothing it cannot
    /// read.
    pub(super) fn of(config: &Mutex<WzConfig>) -> Self {
        match config.lock() {
            Ok(c) => Self {
                permissions: c.admin_permissions(),
                config_json: c.to_admin_json(),
                metadata_json: String::from(c.admin_metadata_json()),
            },
            Err(_) => Self {
                permissions: wz_session_core::adminspace::AdminSpacePermissions {
                    read: false,
                    write: false,
                },
                config_json: String::from("{}"),
                metadata_json: String::from("null"),
            },
        }
    }
}

/// The permits a shared config grants, read under its lock. A poisoned lock
/// grants nothing: a config that cannot be read cannot say a request is
/// allowed.
#[cfg(feature = "adminspace-write")]
fn admin_permissions_of(
    config: &Mutex<WzConfig>,
) -> wz_session_core::adminspace::AdminSpacePermissions {
    match config.lock() {
        Ok(c) => c.admin_permissions(),
        Err(_) => wz_session_core::adminspace::AdminSpacePermissions {
            read: false,
            write: false,
        },
    }
}

/// Whether a decoded config key is the HOST's to apply rather than this
/// handler's: a `plugins/...` key is judged by the running plugin
/// (`WzConfig::set_by_key_with`'s `PluginsSink`), which only the host holds.
#[cfg(all(feature = "adminspace-write", feature = "zenoh-config"))]
fn key_is_the_hosts(key: &str) -> bool {
    #[cfg(feature = "adminspace-config-hotreload")]
    {
        crate::config::is_plugins_key(key)
    }
    #[cfg(not(feature = "adminspace-config-hotreload"))]
    {
        let _ = key;
        false
    }
}

/// Apply one sample arriving on `space`'s config-write subscription to
/// `config`: upstream's admin `send_push` handler
/// (`zenoh/src/net/runtime/adminspace.rs` @ `fn send_push_consume(&self, msg: &mut Push, _reliability: Reliability, _consume: bool) {`).
///
/// * The permit is read off `config` PER SAMPLE, under the same lock the GET
///   gate reads it through, as upstream takes the config lock inside its
///   handler.
/// * A config-key PUT or DELETE is written into `config` through
///   [`WzConfig::set_by_key`] / [`WzConfig::remove_by_key`], so the next GET
///   serves it; a refusal is logged by name.
/// * The legacy `admin-read` verb writes the read permit into the same slice.
/// * Every other decoded intent is handed to `on_intent`.
///
/// Denials and malformed writes are logged at the severities upstream uses.
#[cfg(feature = "adminspace-write")]
pub fn apply_admin_config_write(
    space: &AdminConfigWriteSpace,
    config: &Mutex<WzConfig>,
    sample: &dyn SampleView,
    on_intent: &mut dyn FnMut(AdminConfigWrite),
) {
    use wz_session_core::adminspace::{
        parse_admin_config_write, AdminConfigWriteBody, AdminConfigWriteOutcome,
    };

    let permitted = crate::admin_write_permit(&admin_permissions_of(config));
    match parse_admin_config_write(
        space,
        sample.keyexpr(),
        AdminConfigWriteBody::of_sample(sample),
        permitted,
        &crate::admin_write_knows_config_key,
    ) {
        AdminConfigWriteOutcome::Apply(AdminConfigWrite::AdminReadPermit(read)) => {
            match config.lock() {
                Ok(mut c) => {
                    let mut permissions = c.admin_permissions();
                    permissions.read = read;
                    c.set_admin_permissions(permissions);
                    log::info!("adminspace config-write: read permit set to {read}");
                }
                Err(_) => log::warn!(
                    "adminspace config-write: admin-read ignored; the config lock is poisoned"
                ),
            }
        }
        #[cfg(feature = "zenoh-config")]
        AdminConfigWriteOutcome::Apply(AdminConfigWrite::SetKey { key, value })
            if !key_is_the_hosts(&key) =>
        {
            match config.lock() {
                Ok(mut c) => match c.set_by_key(&key, &value) {
                    Ok(()) => log::info!("adminspace config-write: {key} written"),
                    Err(err) => log::warn!("adminspace config-write: {key} refused: {err:?}"),
                },
                Err(_) => log::warn!(
                    "adminspace config-write: {key} ignored; the config lock is poisoned"
                ),
            }
        }
        #[cfg(feature = "zenoh-config")]
        AdminConfigWriteOutcome::Apply(AdminConfigWrite::RemoveKey { key })
            if !key_is_the_hosts(&key) =>
        {
            match config.lock() {
                Ok(mut c) => match c.remove_by_key(&key) {
                    Ok(()) => log::info!(
                        "adminspace config-write: {key} deleted (restored to its schema default)"
                    ),
                    Err(err) => {
                        log::warn!("adminspace config-write: {key} delete refused: {err:?}")
                    }
                },
                Err(_) => log::warn!(
                    "adminspace config-write: {key} delete ignored; the config lock is poisoned"
                ),
            }
        }
        AdminConfigWriteOutcome::Apply(intent) => on_intent(intent),
        // Upstream logs a denied write at error, naming the permission.
        AdminConfigWriteOutcome::Denied => log::error!(
            "Received PUT on '{}' but adminspace.permissions.write=false in configuration",
            sample.keyexpr()
        ),
        AdminConfigWriteOutcome::Malformed => log::warn!(
            "adminspace config-write: malformed payload on {}; ignored",
            sample.keyexpr()
        ),
        AdminConfigWriteOutcome::UnknownKey(key) => log::warn!(
            "adminspace config-write: unknown key '{key}' (neither a config key this build \
             carries nor one of wz's config-write actions); ignored"
        ),
        AdminConfigWriteOutcome::NotDeletable(key) => log::warn!(
            "adminspace config-write: DELETE of '{key}' has no meaning (it names an action, \
             not a config key); ignored"
        ),
        // Upstream refuses a non-utf8 value at error.
        AdminConfigWriteOutcome::NotUtf8 => log::error!(
            "Received non utf8 conf value on {}; ignored",
            sample.keyexpr()
        ),
        AdminConfigWriteOutcome::AmbiguousSpaceAddress => log::error!(
            "adminspace config-write: key addresses a SET of config spaces (`**` in the zid or \
             whatami chunk), so its config sub-key is not determined; ignored {}",
            sample.keyexpr()
        ),
        // The bare `.../config` key the `/**` subscription also matches.
        AdminConfigWriteOutcome::NotAWrite => {}
    }
}
