// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_config_*` / `zp_config_insert` — the pico key/value session config.
//!
//! pico's config is an int-keyed string map; the keys wz Round 1 consumes are
//! `Z_CONFIG_MODE_KEY = 0x40` (`"client"` / `"peer"`),
//! `Z_CONFIG_CONNECT_KEY = 0x41` (a dial endpoint like `tcp/127.0.0.1:7447`)
//! and `Z_CONFIG_LISTEN_KEY = 0x42` (a listen endpoint). `z_open` reads these
//! to pick the dial vs accept role. Values verified against
//! `~/zenoh-pico/include/zenoh-pico/config.h.in:84-103`.
//!
//! zenoh-pico keeps the same map of numbered keys on its heap
//! (`vendor/zenoh-pico/include/zenoh-pico/utils/config.h` @ `typedef _z_str_intmap_t _z_config_t;`),
//! one allocation for each value. Here a config is one object of a size the build fixes: a table of
//! `CONFIG_ENTRIES` keys and a text of `CONFIG_TEXT_BYTES` their values lie in, so an insert
//! allocates nothing and a config made before an open is all the memory it will ever take.

use core::ffi::{c_char, c_void, CStr};
use core::ptr::addr_of_mut;

use wz_session_core::caps;

use crate::prelude::*;

use crate::abi::{
    handle_ref, impl_value_ownership, z_loaned_config_t, z_moved_config_t, z_owned_config_t,
};
use crate::ffi::guarded;
use crate::result::{
    ZResult, Z_ERR_CONFIG_FAILED_INSERT, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_SYSTEM_OUT_OF_MEMORY,
    Z_OK,
};

/// pico `Z_CONFIG_MODE_KEY` (config.h.in:84).
pub const Z_CONFIG_MODE_KEY: u8 = 0x40;
/// pico `Z_CONFIG_CONNECT_KEY` (config.h.in:95).
pub const Z_CONFIG_CONNECT_KEY: u8 = 0x41;
/// pico `Z_CONFIG_LISTEN_KEY` (config.h.in:103).
pub const Z_CONFIG_LISTEN_KEY: u8 = 0x42;
/// pico `Z_CONFIG_SESSION_ZID_KEY` (config.h.in:155) — the session zid as a UUID
/// (`8-4-4-4-12` hex digits, read by `_z_uuid_to_bytes`). Scouting reads it for the zid it
/// scouts with, and `z_open` for the zid the session opens on.
pub const Z_CONFIG_SESSION_ZID_KEY: u8 = 0x49;
/// pico `Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY` (config.h.in:168) — the private-key PEM
/// FILE PATH a cert-bearing listener presents. R311y406: value mirrors zenoh-pico's
/// native key. The name is zenoh's tls-block key, which zenoh reuses for quic;
/// wz-capi-pico wires it into the QUIC acceptor (it ships `transport-link-quic`, not a
/// tls acceptor), so today it keys a `quic/` listen.
pub const Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY: u8 = 0x4D;
/// pico `Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY` (config.h.in:170) — the cert-chain PEM
/// FILE PATH a cert-bearing listener presents (the peer of
/// [`Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY`]). R311y406, value mirrors zenoh-pico's.
pub const Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY: u8 = 0x4F;

// --- the rest of pico's TLS key block (R311y534) ---------------------------
//
// The two constants above were added when the QUIC acceptor needed a cert, and
// they are two of TWELVE (`config.h.in:166-177`). The other ten are what the
// upstream `z_pub_tls.c` / `z_sub_tls.c` examples actually set, and the shape of
// what was missing is worth stating: every certificate value comes in a PATH
// form AND a `*_BASE64` inline form, and the stock examples default to the
// INLINE one — their CA, cert and key are base64 blobs compiled into the
// program, used unless `-C`/`-P`/`-Q`/`-R`/`-S` overrides them. So a shim that
// reads only the path forms reads none of the values a stock run supplies.
//
// The BASE64 halves decode to exactly the bytes the path halves would have read
// out of a file, so both forms resolve to the same PEM bytes at `z_open` and
// nothing downstream can tell them apart.

/// pico `Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY` (config.h.in:166) — FILE PATH of the
/// trust bundle a `tls/...` dial verifies the peer's server cert against.
pub const Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY: u8 = 0x4B;
/// pico `Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY` (config.h.in:167) — the same
/// trust bundle, base64-wrapped inline. What the stock examples use by default.
pub const Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY: u8 = 0x4C;
/// pico `Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY` (config.h.in:169) — inline form
/// of [`Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY`].
pub const Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY: u8 = 0x4E;
/// pico `Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY` (config.h.in:171) — inline form
/// of [`Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY`].
pub const Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY: u8 = 0x50;
/// pico `Z_CONFIG_TLS_ENABLE_MTLS_KEY` (config.h.in:172) — `"true"` turns on MUTUAL
/// TLS: the dialer presents a client cert, and a listener requires one.
pub const Z_CONFIG_TLS_ENABLE_MTLS_KEY: u8 = 0x51;
/// pico `Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY` (config.h.in:173) — FILE PATH of the
/// private key an mTLS DIALER presents.
pub const Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY: u8 = 0x52;
/// pico `Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_BASE64_KEY` (config.h.in:174) — inline form
/// of [`Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY`].
pub const Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_BASE64_KEY: u8 = 0x53;
/// pico `Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY` (config.h.in:175) — FILE PATH of the
/// cert chain an mTLS DIALER presents.
pub const Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY: u8 = 0x54;
/// pico `Z_CONFIG_TLS_CONNECT_CERTIFICATE_BASE64_KEY` (config.h.in:176) — inline form
/// of [`Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY`].
pub const Z_CONFIG_TLS_CONNECT_CERTIFICATE_BASE64_KEY: u8 = 0x55;
/// pico `Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY` (config.h.in:177) — `"true"`
/// requires the peer cert's SAN to match the dialed host. pico's DEFAULT is
/// `false`, and the stock examples depend on it: they dial a numeric
/// `tls/127.0.0.1:<port>` while their bundled cert names `localhost`.
pub const Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY: u8 = 0x56;

/// One key of a config and the place of its value in the config's text.
#[derive(Clone, Copy)]
struct Row {
    key: u8,
    /// The value's first byte.
    start: u32,
    /// The value's bytes with its terminator.
    len: u32,
    /// The bytes its place holds: a later value of the key that fits is written over it.
    room: u32,
}

impl Row {
    const EMPTY: Self = Self {
        key: 0,
        start: 0,
        len: 0,
        room: 0,
    };

    /// The first byte past the value's place.
    fn place_end(&self) -> usize {
        self.start as usize + self.room as usize
    }
}

/// The numbered keys of a config and their values, each value NUL-terminated in one text.
///
/// The terminator is stored rather than appended per read because [`zp_config_get`] hands the C
/// side a `const char *` into this text: zenoh-pico's contract is a borrow of the config, not a
/// rendered copy, and a borrow is a C string only if the stored bytes are one. A value's place
/// never moves while the config lives, so a borrow of one key is not disturbed by an insert of
/// another; a key's new value is written over its old place when it fits there, which zenoh-pico
/// frees on a replacement, and otherwise after the last place, the old one left unused.
#[derive(Clone)]
pub(crate) struct ConfigEntries {
    /// The keys held, the first `held` of the rows, in the order each was first inserted.
    rows: [Row; caps::CONFIG_ENTRIES],
    held: usize,
    /// The values' places, from the start up to `end`.
    text: [u8; caps::CONFIG_TEXT_BYTES],
    end: usize,
}

impl Default for ConfigEntries {
    fn default() -> Self {
        Self {
            rows: [Row::EMPTY; caps::CONFIG_ENTRIES],
            held: 0,
            text: [0; caps::CONFIG_TEXT_BYTES],
            end: 0,
        }
    }
}

impl ConfigEntries {
    /// Writes an empty table at `at` in place: the text is most of a config, and a value built on
    /// the stack and moved would take its size twice.
    ///
    /// # Safety
    /// `at` is a place for a `ConfigEntries` that holds none.
    unsafe fn write_empty(at: *mut Self) {
        addr_of_mut!((*at).rows).write([Row::EMPTY; caps::CONFIG_ENTRIES]);
        addr_of_mut!((*at).held).write(0);
        addr_of_mut!((*at).end).write(0);
        addr_of_mut!((*at).text)
            .cast::<u8>()
            .write_bytes(0, caps::CONFIG_TEXT_BYTES);
    }

    /// Writes a copy of `self` at `at` in place. Every field is plain data, so the copy of its bytes
    /// is the clone.
    ///
    /// # Safety
    /// As [`Self::write_empty`].
    unsafe fn write_copy(&self, at: *mut Self) {
        core::ptr::copy_nonoverlapping(self as *const Self, at, 1);
    }

    fn row(&self, key: u8) -> Option<&Row> {
        self.rows[..self.held].iter().find(|row| row.key == key)
    }

    /// The value of `key`, without its terminator.
    pub(crate) fn get(&self, key: u8) -> Option<&str> {
        let row = self.row(key)?;
        let start = row.start as usize;
        core::str::from_utf8(&self.text[start..start + row.len as usize - 1]).ok()
    }

    /// The value of `key` as the C string [`zp_config_get`] lends.
    fn c_str(&self, key: u8) -> Option<*const c_char> {
        self.row(key)
            .map(|row| self.text[row.start as usize..].as_ptr().cast::<c_char>())
    }

    /// Keeps `value` under `key`, in place of the value the key held, or
    /// `Z_ERR_CONFIG_FAILED_INSERT` when a new key finds no row or the value no room, the table
    /// then as it was.
    pub(crate) fn insert(&mut self, key: u8, value: &str) -> ZResult {
        let need = value.len() + 1;
        let found = self.rows[..self.held].iter().position(|row| row.key == key);
        if found.is_none() && self.held == self.rows.len() {
            return Z_ERR_CONFIG_FAILED_INSERT;
        }
        let old = found.map(|at| self.rows[at]);
        let start = match old {
            Some(row) if need <= row.room as usize => row.start as usize,
            // The last place grows into the free text after it rather than leaving itself unused.
            Some(row)
                if row.place_end() == self.end && row.start as usize + need <= self.text.len() =>
            {
                row.start as usize
            }
            _ if need <= self.text.len() - self.end => self.end,
            _ => return Z_ERR_CONFIG_FAILED_INSERT,
        };
        self.text[start..start + value.len()].copy_from_slice(value.as_bytes());
        self.text[start + value.len()] = 0;
        let room = match old {
            Some(row) if row.start as usize == start => need.max(row.room as usize),
            _ => need,
        };
        self.end = self.end.max(start + room);
        let row = Row {
            key,
            start: start as u32,
            len: need as u32,
            room: room as u32,
        };
        match found {
            Some(at) => self.rows[at] = row,
            None => {
                self.rows[self.held] = row;
                self.held += 1;
            }
        }
        Z_OK
    }
}

/// The payload behind a `z_owned_config_t` handle.
#[derive(Clone, Default)]
pub(crate) struct ConfigState {
    pub(crate) entries: ConfigEntries,
    /// What wz's own doors state about the session's policies, which no numbered key carries
    /// (`wz_ext_config_policy`, `wz_ext_config_profile`, `wz_ext_config_document`); nothing in a
    /// build without `config-policy`.
    pub(crate) policies: crate::config_policy::PolicyStatements,
    /// The transport the program supplies (`wz_ext_config_transport`), which the session opened
    /// from this config uses for every link in place of the system's sockets.
    #[cfg(feature = "app-transport")]
    pub(crate) transport: Option<alloc::sync::Arc<wz_session_core::app_transport::AppTransport>>,
    /// The key ids every node of the deployment shares (`wz_ext_config_key_ids`) and the
    /// endpoints whose key-wire form is stated apart (`wz_ext_config_key_wire_form_for`), which
    /// the open hands the engine.
    #[cfg(feature = "shared-key-ids")]
    pub(crate) key_ids: wz_session_core::shared_key_ids::KeyIdsAtOpen,
    /// The time base the program supplies (`wz_ext_config_time_base`), which the session opened
    /// from this config times its deadlines by in place of the system's clock.
    #[cfg(feature = "time-base")]
    pub(crate) time_base: Option<wz_node_time::time_base::TimeBaseHold>,
}

impl ConfigState {
    #[inline]
    pub(crate) fn get(&self, key: u8) -> Option<&str> {
        self.entries.get(key)
    }

    /// Record `value` under `key` (see [`ConfigEntries::insert`]): `Z_OK`, or
    /// `Z_ERR_CONFIG_FAILED_INSERT` with the config as it was.
    pub(crate) fn insert(&mut self, key: u8, value: &str) -> ZResult {
        self.entries.insert(key, value)
    }

    /// A config of its own allocation, empty or a copy of `from`, written in place; `None` when the
    /// allocation is refused. Released by [`free_config`], as a `Box` of one is.
    fn place(from: Option<&ConfigState>) -> Option<*mut ConfigState> {
        // SAFETY: a `ConfigState` is never zero-sized: its table counts its rows.
        let at = unsafe { alloc::alloc::alloc(core::alloc::Layout::new::<ConfigState>()) }
            .cast::<ConfigState>();
        if at.is_null() {
            return None;
        }
        // SAFETY: `at` is a fresh allocation sized and aligned for a `ConfigState`.
        unsafe { Self::write_at(at, from) };
        Some(at)
    }

    /// Writes a config at `at` field by field.
    ///
    /// # Safety
    /// `at` is a place for a `ConfigState` that holds none.
    unsafe fn write_at(at: *mut ConfigState, from: Option<&ConfigState>) {
        let Some(from) = from else {
            ConfigEntries::write_empty(addr_of_mut!((*at).entries));
            addr_of_mut!((*at).policies).write(Default::default());
            #[cfg(feature = "app-transport")]
            addr_of_mut!((*at).transport).write(None);
            #[cfg(feature = "shared-key-ids")]
            addr_of_mut!((*at).key_ids).write(Default::default());
            #[cfg(feature = "time-base")]
            addr_of_mut!((*at).time_base).write(None);
            return;
        };
        // Destructured whole, so a field added to the struct is refused here until it is written
        // in both arms.
        let ConfigState {
            entries,
            policies,
            #[cfg(feature = "app-transport")]
            transport,
            #[cfg(feature = "shared-key-ids")]
            key_ids,
            #[cfg(feature = "time-base")]
            time_base,
        } = from;
        entries.write_copy(addr_of_mut!((*at).entries));
        addr_of_mut!((*at).policies).write(policies.clone());
        #[cfg(feature = "app-transport")]
        addr_of_mut!((*at).transport).write(transport.clone());
        #[cfg(feature = "shared-key-ids")]
        addr_of_mut!((*at).key_ids).write(key_ids.clone());
        #[cfg(feature = "time-base")]
        addr_of_mut!((*at).time_base).write(time_base.clone());
    }
}

/// Free-fn for the ownership macro.
///
/// # Safety
/// `h` must be a live config [`ConfigState::place`] made, or a `Box::into_raw::<ConfigState>`.
unsafe fn free_config(h: *mut c_void) {
    drop(Box::from_raw(h as *mut ConfigState));
}

impl_value_ownership!(
    z_owned_config_t,
    z_loaned_config_t,
    z_moved_config_t,
    free_config,
    z_internal_config_null,
    z_internal_config_check,
    z_config_loan,
    z_config_loan_mut,
    z_config_move,
    z_config_take,
    z_config_drop,
    z_config_take_from_loaned
);

/// Initialise an empty default config (pico `z_config_default`).
#[no_mangle]
pub unsafe extern "C" fn z_config_default(config: *mut z_owned_config_t) -> ZResult {
    guarded(|| {
        if config.is_null() {
            return Z_ERR_NULL;
        }
        let Some(state) = ConfigState::place(None) else {
            return Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        *config = z_owned_config_t {
            handle: state as *mut c_void,
            _pad: [core::ptr::null_mut(); 3],
        };
        Z_OK
    })
}

/// Insert a string value under an int key (pico `zp_config_insert`), in place of the value the
/// key held. A new key past the config's `CONFIG_ENTRIES` rows, or a value its `CONFIG_TEXT_BYTES`
/// of text have no room for, is refused with `_Z_ERR_CONFIG_FAILED_INSERT`, pico's code for an
/// insert it could not make (`vendor/zenoh-pico/src/protocol/config.c` @
/// `ret = _Z_ERR_CONFIG_FAILED_INSERT;`), and the config keeps what it held.
#[no_mangle]
pub unsafe extern "C" fn zp_config_insert(
    config: *mut z_loaned_config_t,
    key: u8,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if config.is_null() || value.is_null() {
            return Z_ERR_NULL;
        }
        let handle = (*config).handle;
        if handle.is_null() {
            return Z_ERR_NULL;
        }
        let state = &mut *(handle as *mut ConfigState);
        let val = match CStr::from_ptr(value).to_str() {
            Ok(s) => s,
            Err(_) => return Z_ERR_INVALID,
        };
        state.insert(key, val)
    })
}

/// Read a config value by int key (pico `zp_config_get`), or NULL when unset.
///
/// R311y559 — a symbol the census found missing. The returned pointer borrows
/// the config's OWN storage, which is upstream's contract and is why the value
/// is not rendered into a temporary: a caller holds it for as long as it holds
/// the config and does not insert the same key again (zenoh-pico frees the old
/// value then). An insert of another key never moves it (`ConfigEntries`).
///
/// The stored bytes carry the terminator, which is what makes the borrow a
/// valid C string.
///
/// # Safety
/// `config` must be null or a live loaned config; the result must not outlive
/// it.
#[no_mangle]
pub unsafe extern "C" fn zp_config_get(config: *const z_loaned_config_t, key: u8) -> *const c_char {
    crate::ffi::guard_val(core::ptr::null(), || {
        if config.is_null() {
            return core::ptr::null();
        }
        let handle = (*config).handle;
        if handle.is_null() {
            return core::ptr::null();
        }
        let state = &*(handle as *const ConfigState);
        state.entries.c_str(key).unwrap_or(core::ptr::null())
    })
}

/// Deep-copy a config (pico `z_config_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_config_clone(
    dst: *mut z_owned_config_t,
    src: *const z_loaned_config_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        let Some(state) = handle_ref::<z_loaned_config_t, ConfigState>(src) else {
            return Z_ERR_NULL;
        };
        let Some(cloned) = ConfigState::place(Some(state)) else {
            return Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        *dst = z_owned_config_t {
            handle: cloned as *mut c_void,
            _pad: [core::ptr::null_mut(); 3],
        };
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::ffi::CString;

    /// A config the C doors made, dropped through them.
    struct Config(z_owned_config_t);

    impl Config {
        fn new() -> Self {
            let mut owned = z_owned_config_t::null_value();
            // SAFETY: `owned` is a live local.
            assert_eq!(unsafe { z_config_default(&mut owned) }, Z_OK);
            Self(owned)
        }

        fn insert(&mut self, key: u8, value: &str) -> ZResult {
            let value = CString::new(value).expect("no NUL");
            // SAFETY: a live config and a live string.
            unsafe { zp_config_insert(z_config_loan_mut(&mut self.0), key, value.as_ptr()) }
        }

        fn get(&self, key: u8) -> *const c_char {
            // SAFETY: a live config.
            unsafe { zp_config_get(z_config_loan(&self.0), key) }
        }

        fn text(&self, key: u8) -> Option<String> {
            let at = self.get(key);
            // SAFETY: a value the config lends is a C string while the config lives.
            (!at.is_null()).then(|| unsafe { CStr::from_ptr(at) }.to_str().unwrap().to_owned())
        }
    }

    impl Drop for Config {
        fn drop(&mut self) {
            // SAFETY: the owned config is live or already null.
            unsafe { z_config_drop(z_config_move(&mut self.0)) }
        }
    }

    /// A value of `len` bytes, none of them NUL.
    fn value_of(len: usize, byte: u8) -> String {
        String::from_utf8(vec![byte; len]).expect("ASCII")
    }

    /// An inserted value is read back, as the C string the config lends and through the reader of
    /// the Rust side; an unset key reads as none.
    #[test]
    fn an_inserted_value_is_read_back_and_an_unset_key_is_none() {
        let mut config = Config::new();
        assert!(config.get(Z_CONFIG_MODE_KEY).is_null());
        assert_eq!(config.insert(Z_CONFIG_MODE_KEY, "client"), Z_OK);
        assert_eq!(config.text(Z_CONFIG_MODE_KEY).as_deref(), Some("client"));
        // SAFETY: the config is live and holds a `ConfigState`.
        let state = unsafe { &*(config.0.handle as *const ConfigState) };
        assert_eq!(state.get(Z_CONFIG_MODE_KEY), Some("client"));
        assert_eq!(state.get(Z_CONFIG_CONNECT_KEY), None);
    }

    /// An insert replaces the key's value, and one that fits is written over the old place, as
    /// zenoh-pico's insert frees the value it replaces: a config replaced in a loop takes no more
    /// text.
    #[test]
    fn a_value_that_fits_is_written_over_the_place_it_replaces() {
        let mut config = Config::new();
        assert_eq!(
            config.insert(Z_CONFIG_CONNECT_KEY, "tcp/127.0.0.1:7447"),
            Z_OK
        );
        let place = config.get(Z_CONFIG_CONNECT_KEY);
        assert_eq!(config.insert(Z_CONFIG_CONNECT_KEY, "tcp/10.0.0.1:1"), Z_OK);
        assert_eq!(config.get(Z_CONFIG_CONNECT_KEY), place);
        assert_eq!(
            config.text(Z_CONFIG_CONNECT_KEY).as_deref(),
            Some("tcp/10.0.0.1:1")
        );
        // Every byte of the text taken by one key, replaced many times, still fits.
        let whole = value_of(
            caps::CONFIG_TEXT_BYTES - 1 - "tcp/127.0.0.1:7447".len() - 1,
            b'a',
        );
        assert_eq!(config.insert(Z_CONFIG_LISTEN_KEY, &whole), Z_OK);
        for _ in 0..4 {
            assert_eq!(
                config.insert(Z_CONFIG_CONNECT_KEY, "tcp/127.0.0.1:7447"),
                Z_OK
            );
        }
    }

    /// A longer value of a key that is not the last one written goes after the last place, and the
    /// value another key lends does not move or change.
    #[test]
    fn a_longer_value_leaves_every_other_borrow_where_it_was() {
        let mut config = Config::new();
        assert_eq!(config.insert(Z_CONFIG_MODE_KEY, "peer"), Z_OK);
        assert_eq!(config.insert(Z_CONFIG_LISTEN_KEY, "udp/0.0.0.0:7447"), Z_OK);
        let listen = config.get(Z_CONFIG_LISTEN_KEY);
        assert_eq!(config.insert(Z_CONFIG_MODE_KEY, "client"), Z_OK);
        assert_eq!(config.get(Z_CONFIG_LISTEN_KEY), listen);
        assert_eq!(
            config.text(Z_CONFIG_LISTEN_KEY).as_deref(),
            Some("udp/0.0.0.0:7447")
        );
        assert_eq!(config.text(Z_CONFIG_MODE_KEY).as_deref(), Some("client"));
    }

    /// The last place written grows into the free text after it: a key replaced by a longer value
    /// still fits when only its own growth is left, which an append past the old place would not.
    #[test]
    fn the_last_value_grows_in_its_own_place() {
        let mut config = Config::new();
        assert_eq!(config.insert(Z_CONFIG_SESSION_ZID_KEY, "a"), Z_OK);
        let longest = value_of(caps::CONFIG_TEXT_BYTES - 1, b'b');
        assert_eq!(config.insert(Z_CONFIG_SESSION_ZID_KEY, &longest), Z_OK);
        assert_eq!(config.text(Z_CONFIG_SESSION_ZID_KEY), Some(longest));
    }

    /// A value the text has no room for is refused with pico's code for a failed insert, and the
    /// config keeps what it held: the key's old value and no new key.
    #[test]
    fn a_value_past_the_text_is_refused_and_the_config_kept() {
        let mut config = Config::new();
        assert_eq!(config.insert(Z_CONFIG_MODE_KEY, "client"), Z_OK);
        let past = value_of(caps::CONFIG_TEXT_BYTES, b'c');
        assert_eq!(
            config.insert(Z_CONFIG_MODE_KEY, &past),
            Z_ERR_CONFIG_FAILED_INSERT
        );
        assert_eq!(config.text(Z_CONFIG_MODE_KEY).as_deref(), Some("client"));
        assert_eq!(
            config.insert(Z_CONFIG_CONNECT_KEY, &past),
            Z_ERR_CONFIG_FAILED_INSERT
        );
        assert!(config.get(Z_CONFIG_CONNECT_KEY).is_null());
        // What is left of the text is still taken whole.
        let rest = value_of(caps::CONFIG_TEXT_BYTES - "client".len() - 2, b'd');
        assert_eq!(config.insert(Z_CONFIG_CONNECT_KEY, &rest), Z_OK);
        assert_eq!(
            config.insert(Z_CONFIG_LISTEN_KEY, ""),
            Z_ERR_CONFIG_FAILED_INSERT
        );
    }

    /// A key past the config's rows is refused and the keys it holds keep their values; a key it
    /// holds is still replaced.
    #[test]
    fn a_key_past_the_rows_is_refused_and_a_held_one_still_replaced() {
        let mut entries = ConfigEntries::default();
        let keys = u8::try_from(caps::CONFIG_ENTRIES).expect("rows fit the key space");
        for key in 0..keys {
            assert_eq!(entries.insert(key, ""), Z_OK, "key {key}");
        }
        assert_eq!(entries.insert(keys, ""), Z_ERR_CONFIG_FAILED_INSERT);
        assert_eq!(entries.get(keys), None);
        assert_eq!(entries.insert(0, "x"), Z_OK);
        assert_eq!(entries.get(0), Some("x"));
        assert_eq!(entries.get(keys - 1), Some(""));
    }

    /// A clone holds the values of its source in a text of its own: an insert into one is not read
    /// through the other.
    #[test]
    fn a_clone_holds_its_own_copy_of_the_values() {
        let mut config = Config::new();
        assert_eq!(config.insert(Z_CONFIG_MODE_KEY, "peer"), Z_OK);
        let mut clone = Config(z_owned_config_t::null_value());
        // SAFETY: a live destination and a live source.
        assert_eq!(
            unsafe { z_config_clone(&mut clone.0, z_config_loan(&config.0)) },
            Z_OK
        );
        assert_eq!(clone.text(Z_CONFIG_MODE_KEY).as_deref(), Some("peer"));
        assert_eq!(clone.insert(Z_CONFIG_MODE_KEY, "client"), Z_OK);
        assert_eq!(config.text(Z_CONFIG_MODE_KEY).as_deref(), Some("peer"));
        assert_eq!(config.insert(Z_CONFIG_LISTEN_KEY, "tcp/0.0.0.0:7447"), Z_OK);
        assert!(clone.get(Z_CONFIG_LISTEN_KEY).is_null());
        assert_ne!(clone.get(Z_CONFIG_MODE_KEY), config.get(Z_CONFIG_MODE_KEY));
    }

    /// The doors refuse a null config and a null value, and a value that is not UTF-8.
    #[test]
    fn the_doors_refuse_what_they_cannot_read() {
        let mut config = Config::new();
        // SAFETY: null arguments are refused before they are read.
        unsafe {
            assert_eq!(
                zp_config_insert(core::ptr::null_mut(), 0, c"v".as_ptr()),
                Z_ERR_NULL
            );
            assert_eq!(
                zp_config_insert(z_config_loan_mut(&mut config.0), 0, core::ptr::null()),
                Z_ERR_NULL
            );
            assert!(zp_config_get(core::ptr::null(), 0).is_null());
            assert_eq!(z_config_default(core::ptr::null_mut()), Z_ERR_NULL);
        }
        let invalid = [0xFFu8, 0];
        // SAFETY: a live config and a NUL-terminated buffer.
        let code = unsafe {
            zp_config_insert(z_config_loan_mut(&mut config.0), 0, invalid.as_ptr().cast())
        };
        assert_eq!(code, Z_ERR_INVALID);
        assert!(config.get(0).is_null());
    }
}
