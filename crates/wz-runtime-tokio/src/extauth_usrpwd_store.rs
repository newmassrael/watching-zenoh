// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2567 — the SHARED usrpwd credential store: the wz analogue of zenoh's
//! `RwLock<AuthUsrPwd>`, and the thing whose absence made two of this atom's
//! residuals inexpressible.
//!
//! # Why it lives here and not in the session kernel
//!
//! `wz-session-core` is `no_std`-shaped. It owns the SEAM
//! ([`CredentialSource`]) and the pure dictionary PARSER; this crate owns the
//! machinery that needs `std` — a lock and a filesystem. That split is what lets
//! the parse be tested without a filesystem and keeps file I/O out of a kernel
//! that must build for MCUs.
//!
//! # Why a store at all
//!
//! `UsrPwdMethod` used to OWN its `(user, password)` table by value, so every
//! session got a private copy. Runtime mutation could not be expressed against
//! that shape at all: adding a user to one session's copy says nothing about the
//! next handshake. zenoh's per-handshake FSM instead holds a REFERENCE to a
//! shared store (`io/zenoh-transport/src/unicast/establishment/ext/auth/usrpwd.rs`
//!  @ `inner: &'a RwLock<AuthUsrPwd>`), which is exactly why its `add_user` /
//! `del_user` take effect at all. This is that store.
//!
//! # Locking
//!
//! `std::sync::Mutex`, not the `wz_runtime_core` mutex abstraction, and not an
//! async lock. This crate IS the concrete tokio runtime, so there is no runtime
//! to abstract over here; and the seam is consumed from
//! `AuthMethod::accept_recv_open_syn`, which is SYNCHRONOUS — an async lock
//! would force the whole auth plane async for one lookup. Upstream's is async
//! only because its own FSM is.

use std::path::Path;
use std::sync::{Arc, Mutex};

use wz_session_core::extauth_usrpwd::{
    parse_dictionary, CredentialSource, CredentialTable, DictionaryError,
};

/// Why a dictionary file could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The file was read but its contents are not a valid dictionary.
    Parse(DictionaryError),
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read the usrpwd dictionary file: {e}"),
            Self::Parse(e) => write!(f, "invalid usrpwd dictionary file: {e:?}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// A shared, mutable `(user, password)` table.
///
/// Cloning shares the table rather than copying it — that is the entire point:
/// every session's [`UsrPwdMethod`](wz_session_core::extauth_usrpwd::UsrPwdMethod)
/// holds a clone, so a later [`add_user`](Self::add_user) is visible to the next
/// handshake without anyone re-installing a dispatch.
#[derive(Clone)]
pub struct UsrPwdStore {
    inner: Arc<Mutex<CredentialTable>>,
}

impl UsrPwdStore {
    /// An empty store — no users, so a responder built on it admits nobody.
    ///
    /// ⚠ Note this is NOT the same as "not a responder": that distinction lives
    /// in `UsrPwdMethod::responder`, which folds an empty TABLE to no source at
    /// all. A store handed over explicitly is a deliberate act, so an empty one
    /// here means "configured, currently zero users" — which is exactly the
    /// state `del_user` leaves behind and must not be confused with unconfigured.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CredentialTable::new())),
        }
    }

    /// A store seeded from an existing table.
    pub fn with_table(table: CredentialTable) -> Self {
        Self {
            inner: Arc::new(Mutex::new(table)),
        }
    }

    /// Load a `user:password` dictionary file — residual 2's I/O half.
    ///
    /// The PARSE is `wz-session-core`'s, so the rules (first-colon split, blank
    /// lines skipped, a malformed line failing the whole load) are the ones its
    /// tests pin against upstream's own. This function only reads bytes.
    pub fn from_dictionary_file(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path).map_err(LoadError::Io)?;
        let table = parse_dictionary(&text).map_err(LoadError::Parse)?;
        Ok(Self::with_table(table))
    }

    /// Register (or replace) a user — the wz analogue of zenoh
    /// `AuthUsrPwd::add_user`.
    ///
    /// Replaces on a duplicate user rather than appending, matching upstream,
    /// whose `lookup.insert(user, password)` is a map insert. Appending would
    /// leave the OLD password still able to authenticate, since the lookup is a
    /// linear scan that stops at the first match.
    pub fn add_user(&self, user: Vec<u8>, password: Vec<u8>) {
        let mut table = self.lock();
        match table.iter_mut().find(|(u, _)| *u == user) {
            Some(entry) => entry.1 = password,
            None => table.push((user, password)),
        }
    }

    /// Remove a user — the wz analogue of zenoh `AuthUsrPwd::del_user`.
    ///
    /// Returns whether anything was removed, so a caller can tell "deleted" from
    /// "was never there" without a second query.
    pub fn del_user(&self, user: &[u8]) -> bool {
        let mut table = self.lock();
        let before = table.len();
        table.retain(|(u, _)| u.as_slice() != user);
        table.len() != before
    }

    /// How many users are registered. For tests and operator introspection.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store holds no users.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The lock, recovered from poisoning rather than propagating a panic.
    ///
    /// A poisoned credential table is still a correct table: the panic that
    /// poisoned it happened in some other thread's critical section, and the
    /// data it guards is a plain `Vec` with no invariant a panic could break
    /// half-way. Refusing every subsequent handshake because an unrelated thread
    /// panicked would turn one fault into a total authentication outage.
    fn lock(&self) -> std::sync::MutexGuard<'_, CredentialTable> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for UsrPwdStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialSource for UsrPwdStore {
    /// Lend the password to `f` WHILE HOLDING THE LOCK, so it is never copied
    /// out. This is the whole reason the seam is a callback: upstream likewise
    /// hands `hmac::sign` a borrow taken under its read lock.
    fn with_password_for(&self, user: &[u8], f: &mut dyn FnMut(&[u8]) -> bool) -> Option<bool> {
        let table = self.lock();
        table
            .iter()
            .find(|(u, _)| u.as_slice() == user)
            .map(|(_, p)| f(p.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clone_shares_the_table_rather_than_copying_it() {
        // The property the whole store exists for: a method built from one
        // clone must see a user added through another. A copy-on-clone store
        // would pass every other test here and fail only in production, where
        // the two clones are a session and its operator.
        let store = UsrPwdStore::new();
        let held_by_a_session = store.clone();
        assert_eq!(held_by_a_session.len(), 0);

        store.add_user(b"alice".to_vec(), b"s3cret".to_vec());

        let mut seen = None;
        held_by_a_session.with_password_for(b"alice", &mut |pw| {
            seen = Some(pw.to_vec());
            true
        });
        assert_eq!(
            seen,
            Some(b"s3cret".to_vec()),
            "an add through one handle must be visible through another"
        );
    }

    #[test]
    fn add_user_replaces_rather_than_shadows() {
        // Appending would leave the OLD password still authenticating, because
        // the scan stops at the first match -- a credential rotation that does
        // not actually revoke anything.
        let store = UsrPwdStore::new();
        store.add_user(b"alice".to_vec(), b"old".to_vec());
        store.add_user(b"alice".to_vec(), b"new".to_vec());
        assert_eq!(store.len(), 1, "a replace must not grow the table");

        let mut matched_old = false;
        store.with_password_for(b"alice", &mut |pw| {
            matched_old = pw == b"old";
            true
        });
        assert!(!matched_old, "the OLD password must no longer be present");
    }

    #[test]
    fn del_user_reports_whether_it_removed_anything() {
        let store = UsrPwdStore::with_table(vec![(b"alice".to_vec(), b"s3cret".to_vec())]);
        assert!(store.del_user(b"alice"), "removing a present user is true");
        assert!(!store.del_user(b"alice"), "removing it again is false");
        assert!(store.is_empty());
        assert_eq!(
            store.with_password_for(b"alice", &mut |_| true),
            None,
            "a deleted user must not authenticate"
        );
    }

    #[test]
    fn an_unknown_user_lends_nothing() {
        let store = UsrPwdStore::with_table(vec![(b"alice".to_vec(), b"s3cret".to_vec())]);
        let mut called = false;
        let out = store.with_password_for(b"bob", &mut |_| {
            called = true;
            true
        });
        assert_eq!(out, None);
        assert!(!called, "the callback must not run for an unknown user");
    }

    #[test]
    fn a_dictionary_file_loads_through_the_cores_parser() {
        let dir = std::env::temp_dir().join(format!("wz-usrpwd-dict-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("dict.txt");
        std::fs::write(&path, "alice:s3cret\n\nbob:hunter2\n").expect("write dict");

        let store = UsrPwdStore::from_dictionary_file(&path).expect("loads");
        assert_eq!(store.len(), 2, "both entries, blank line skipped");

        // A malformed file fails the WHOLE load rather than loading what parsed.
        std::fs::write(&path, "alice:s3cret\nbroken\n").expect("write dict");
        assert!(
            matches!(
                UsrPwdStore::from_dictionary_file(&path),
                Err(LoadError::Parse(_))
            ),
            "a malformed line must fail the load"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
