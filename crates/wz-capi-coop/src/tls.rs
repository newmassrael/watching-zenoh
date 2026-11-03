// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `tls/` link of the cooperative engine on a host (step T4 of L6 in
//! `docs/capi-pico-on-coop-engine.md`): the secure channel `wz-tls-mbedtls` runs, made from the
//! PEM material a C ABI's config resolved ([`CapiTlsConfig`]) and handed to a stack as its
//! `tls/` dial.
//!
//! What the channel was built for is an image: the library starts once on a static arena, an
//! identity and the roots are made once and lent for the program, and the time a chain's dates
//! are held to is the caller's. A host program that opens sessions over its life has none of
//! those fixed, so this module is where they are settled:
//!
//! - The library is started on an arena of its own on the first use ([`HOST_ARENA`]).
//! - An identity or a set of roots is made once for each distinct PEM and lent for the program
//!   (the channel borrows `'static`), so a program that opens the same session a thousand times
//!   makes one of each.
//! - The time of each dial and of each accept is stated to the roots first
//!   ([`Trust::set_now`]), so a certificate that lapsed while the program ran is refused at the
//!   next handshake and not accepted for as long as the program lives.
//!
//! A dial and a listen present different material in one pico program (`connect_*` and `listen_*`
//! keys), and the channel's policy holds one identity, so the value holds a dial for each role.

#[cfg(feature = "event-ring")]
use std::cell::Cell;
use std::ffi::CString;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use wz_capi_port::tls_material::CapiTlsConfig;
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use wz_tls_mbedtls::channel::{self, Identity, TlsError, Trust};
use wz_tls_mbedtls::stream::{AcceptBudget, ChainTrust, TlsDial, TlsListener, TlsStream};

/// The bytes the library's allocations come from on a host. The memory is zeroed and so reserved
/// and not touched until the library uses it; a session's use is measured by
/// [`channel::arena_peak`]. The size is a host program's room for sessions, not an image's
/// budget.
///
/// Measured against a count of sessions (a listener holding sessions from an OpenSSL client, with
/// an RSA-2048 certificate): a held session takes about 20 KB of the arena, and the arena took
/// 198 of them (4,040,772 B at the last) before it refused the next handshake. What bounds a
/// program first is the library's store of keys, four to a session, which the host build sizes to
/// this arena (`WZ_TLS_HOST` in `wz-tls-mbedtls`'s `wz_tls_crypto_config.h`); at the library's
/// default of 32 the same listener held 7. A handshake the arena or the store has no room for is
/// dropped and the peer sees a close, so a program that expects more than about 190 sessions at
/// once is the reason to raise this.
pub const HOST_ARENA: usize = 4 << 20;

/// Why a [`HostTls`] could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostTlsError {
    /// The config states material that cannot make a channel, for this reason.
    Config(&'static str),
    /// The library refused the material or could not start.
    Tls(TlsError),
}

impl core::fmt::Display for HostTlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(why) => write!(f, "tls config: {why}"),
            Self::Tls(e) => write!(f, "tls library: {e:?}"),
        }
    }
}

impl std::error::Error for HostTlsError {}

impl From<TlsError> for HostTlsError {
    fn from(e: TlsError) -> Self {
        Self::Tls(e)
    }
}

/// A value the library made and the program keeps, lent for the program's life.
///
/// SAFETY of the marker traits: the library's state is process-wide and it keeps no lock of its
/// own; this module is only built with `wz-tls-mbedtls/host-lock`, which puts one mutex around
/// every call into it, so reaching a value from two threads is two calls that never overlap.
struct Kept<T>(T);

unsafe impl<T> Send for Kept<T> {}
unsafe impl<T> Sync for Kept<T> {}

/// Start the library on an arena of this program's, once. A library already started by the
/// program (it is `State`) is the program's to have started, and is used as it is.
fn ensure_started() -> Result<(), HostTlsError> {
    static STARTED: OnceLock<Result<(), TlsError>> = OnceLock::new();
    let started = STARTED.get_or_init(|| {
        let arena: &'static mut [u8] = vec![0u8; HOST_ARENA].leak();
        match channel::start(arena) {
            Err(TlsError::State) => Ok(()),
            other => other,
        }
    });
    started.map_err(HostTlsError::Tls)
}

fn c_string(pem: &[u8]) -> Result<CString, HostTlsError> {
    CString::new(pem).map_err(|_| HostTlsError::Config("a PEM holds a NUL byte"))
}

/// The identity made from `chain` and `key`, made once for each distinct pair.
fn identity(chain: &[u8], key: &[u8]) -> Result<&'static Identity, HostTlsError> {
    type Entry = (Vec<u8>, Vec<u8>, &'static Kept<Identity>);
    static MADE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
    let mut made = MADE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, kept)) = made.iter().find(|(c, k, _)| c == chain && k == key) {
        return Ok(&kept.0);
    }
    let id = Identity::from_pem(&c_string(chain)?, &c_string(key)?)?;
    let kept: &'static Kept<Identity> = Box::leak(Box::new(Kept(id)));
    made.push((chain.to_vec(), key.to_vec(), kept));
    Ok(&kept.0)
}

/// The roots made from `roots` (PEM), made once for each distinct bundle.
fn trust(roots: &[u8]) -> Result<&'static Trust, HostTlsError> {
    type Entry = (Vec<u8>, &'static Kept<Trust>);
    static MADE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
    let mut made = MADE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, kept)) = made.iter().find(|(r, _)| r == roots) {
        return Ok(&kept.0);
    }
    let made_now = Trust::roots(&c_string(roots)?, unix_now())?;
    let kept: &'static Kept<Trust> = Box::leak(Box::new(Kept(made_now)));
    made.push((roots.to_vec(), kept));
    Ok(&kept.0)
}

/// The wall clock in seconds since the Unix epoch, which every certificate of a chain is held
/// to; `None` for a clock set before the epoch, for which no date is a verdict.
fn unix_now() -> Option<i64> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(since.as_secs()).ok()
}

/// A monotonic clock in milliseconds, the one an inbound handshake is timed by.
fn host_clock_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// State the time of this dial or accept to the roots it verifies against.
fn state_the_time(roots: Option<&'static Trust>) {
    if let Some(roots) = roots {
        roots.set_now(unix_now());
    }
}

/// The `tls/` dial of a host stack: the secure channel over the streams `D` connects, under the
/// material a config resolved.
///
/// A role the config gives no material for is not carried: a `tls/` dial without roots, or a
/// `tls/` listen without a certificate chain and key, is [`LinkOpenError::Unsupported`], as the
/// tokio engine reports it, and never a connection in the clear.
#[derive(Clone, Copy)]
pub struct HostTls<D> {
    dialer: Option<TlsDial<D>>,
    dial_roots: Option<&'static Trust>,
    listener: Option<TlsDial<D>>,
    listen_roots: Option<&'static Trust>,
}

impl<D: StreamDial + Copy> HostTls<D>
where
    D::Stream: 'static,
{
    /// The dial over `inner`'s streams that `config` states. An inbound handshake that takes
    /// longer than `accept_timeout_ms` is dropped.
    ///
    /// A config with no TLS material makes a value that carries no `tls/` link.
    pub fn from_config(
        inner: D,
        config: &CapiTlsConfig,
        accept_timeout_ms: u64,
    ) -> Result<Self, HostTlsError> {
        let has_material = config.root_ca_pem.is_some()
            || config.listen_cert_pem.is_some()
            || config.listen_key_pem.is_some();
        if has_material {
            ensure_started()?;
        }
        let mutual = config.require_client_auth;

        // The dial verifies the server against the roots; under mutual TLS it presents the
        // `connect_*` pair, and a pair that is not whole is not presented, which the channel
        // refuses (a mutual policy missing its identity never connects).
        let (dialer, dial_roots) = match config.root_ca_pem.as_deref() {
            None => (None, None),
            Some(bundle) => {
                let roots = trust(bundle)?;
                let own = match config.client_auth_pair() {
                    Some((chain, key)) if mutual => Some(identity(chain, key)?),
                    _ => None,
                };
                let dial = TlsDial::chain(
                    inner,
                    ChainTrust {
                        identity: own,
                        roots: Some(roots),
                        mutual,
                        verify_name: config.verify_name_on_connect,
                    },
                );
                (Some(dial), Some(roots))
            }
        };

        // The listen presents the `listen_*` pair; under mutual TLS it also requires a client
        // chain the roots vouch for.
        let (listener, listen_roots) = match (&config.listen_cert_pem, &config.listen_key_pem) {
            (None, None) => (None, None),
            (Some(chain), Some(key)) => {
                let roots = match (mutual, config.root_ca_pem.as_deref()) {
                    (true, Some(bundle)) => Some(trust(bundle)?),
                    (true, None) => {
                        return Err(HostTlsError::Config(
                            "mutual TLS on a listener needs the roots that vouch for a client",
                        ))
                    }
                    (false, _) => None,
                };
                let dial = TlsDial::chain(
                    inner,
                    ChainTrust {
                        identity: Some(identity(chain, key)?),
                        roots,
                        mutual,
                        verify_name: false,
                    },
                )
                .with_accept(AcceptBudget {
                    clock: host_clock_ms,
                    timeout_ms: accept_timeout_ms,
                });
                (Some(dial), roots)
            }
            _ => {
                return Err(HostTlsError::Config(
                    "a listener needs both its certificate chain and its key",
                ))
            }
        };

        Ok(Self {
            dialer,
            dial_roots,
            listener,
            listen_roots,
        })
    }

    /// Whether the config gave this value any `tls/` link to carry.
    pub fn carries_any(&self) -> bool {
        self.dialer.is_some() || self.listener.is_some()
    }

    /// The roots a dial verifies the server against, which the time of each dial is stated to;
    /// one set of roots is made for each distinct bundle, so two values made from the same bundle
    /// lend the same one.
    pub fn dial_roots(&self) -> Option<&'static Trust> {
        self.dial_roots
    }

    /// The roots a listener verifies a client against under mutual TLS, as [`Self::dial_roots`].
    pub fn listen_roots(&self) -> Option<&'static Trust> {
        self.listen_roots
    }
}

impl<D: StreamDial + Copy> StreamDial for HostTls<D>
where
    D::Stream: 'static,
{
    type Stream = TlsStream<D::Stream>;

    fn dial(&self, addr: [u8; 4], port: u16) -> Result<Self::Stream, LinkOpenError> {
        let dialer = self.dialer.as_ref().ok_or(LinkOpenError::Unsupported)?;
        state_the_time(self.dial_roots);
        dialer.dial(addr, port)
    }

    fn listen(
        &self,
        addr: [u8; 4],
        port: u16,
    ) -> Result<Box<dyn StreamListen<Stream = Self::Stream>>, LinkOpenError> {
        let listener = self.listener.as_ref().ok_or(LinkOpenError::Unsupported)?;
        state_the_time(self.listen_roots);
        let inner = listener.listen_counted(addr, port)?;
        Ok(Box::new(Timed {
            inner,
            roots: self.listen_roots,
            #[cfg(feature = "event-ring")]
            told: Cell::new(0),
        }))
    }
}

/// A listener that states the time to its roots before each accept, so a client chain that
/// lapsed while the program ran is refused at its handshake, and that tells the node's event log
/// of each connection the channel took and ended without a stream (`event-ring`).
struct Timed<S: StreamSocket + 'static> {
    inner: TlsListener<Box<dyn StreamListen<Stream = S>>>,
    roots: Option<&'static Trust>,
    /// How many of the inner listener's drops the event log has been told of.
    #[cfg(feature = "event-ring")]
    told: Cell<u32>,
}

impl<S: StreamSocket + 'static> StreamListen for Timed<S> {
    type Stream = TlsStream<S>;

    fn local(&self) -> ([u8; 4], u16) {
        self.inner.local()
    }

    fn accept(&self) -> Result<Option<Self::Stream>, LinkOpenError> {
        state_the_time(self.roots);
        let accepted = self.inner.accept();
        self.tell_the_log();
        accepted
    }
}

impl<S: StreamSocket + 'static> Timed<S> {
    /// One event for each drop since the last accept: why the connection ended, and the
    /// channel's own code. An arena or a key store with no room is `TLS_DROP_NO_ROOM`: both reach
    /// the channel as `OutOfMemory` (an arena that ran out was measured to, in
    /// `wz-tls-mbedtls/tests/arena_exhaustion.rs`; a key store with no free slot returns PSA's
    /// insufficient-memory code, `psa_crypto_slot_management.c`, which the channel maps to it).
    #[cfg(feature = "event-ring")]
    fn tell_the_log(&self) {
        use wz_capi_port::observation::events::{
            emit_tls_handshake_dropped, TLS_DROP_NO_ROOM, TLS_DROP_OTHER, TLS_DROP_STALLED,
        };

        let dropped = self.inner.dropped();
        let new = dropped.saturating_sub(self.told.get());
        if new == 0 {
            return;
        }
        self.told.set(dropped);
        // At most one connection ends in an accept, so `last_drop` is the one just ended.
        let (why, code) = match self.inner.last_drop() {
            None => (TLS_DROP_STALLED, 0),
            Some(TlsError::OutOfMemory) => (TLS_DROP_NO_ROOM, 0),
            Some(TlsError::Code(code)) => (TLS_DROP_OTHER, code as u32),
            Some(_) => (TLS_DROP_OTHER, 0),
        };
        emit_tls_handshake_dropped(why, code);
    }

    #[cfg(not(feature = "event-ring"))]
    fn tell_the_log(&self) {}
}
