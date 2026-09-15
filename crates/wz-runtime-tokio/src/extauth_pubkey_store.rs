// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2627 — the SHARED pubkey lookup + the RSA identity loader: the two halves of
//! `access-extauth-pubkey`'s remaining residual.
//!
//! # Why a store at all (the same shape R2567 found for usrpwd)
//!
//! [`PubKeyMethod`](crate::extauth_pubkey::PubKeyMethod) OWNED its accepted-key
//! set by value, so every handshake got a private copy. Runtime mutation could
//! not be expressed against that shape at all: adding a key to one handshake's
//! copy says nothing about the next one. That is why the atom's residual read
//! "no runtime `add_pubkey`/`del_pubkey`" — not because two methods were missing,
//! but because there was no object for them to mutate.
//!
//! zenoh holds ONE `AuthPubKey` per transport manager behind a lock and hands the
//! per-handshake FSM a reference to it, which is exactly what makes its own
//! `add_pubkey` observable to a later handshake:
//!
//! `io/zenoh-transport/src/unicast/establishment/ext/auth/mod.rs` @ `pubkey: AuthPubKey::from_config(auth.pubkey())?.map(RwLock::new)`
//!
//! Upstream drives that path through the handle its manager exposes:
//!
//! `io/zenoh-transport/tests/unicast_authenticator.rs` @ `.add_pubkey(client02_pub_key.into())`
//!
//! [`PubKeyLookup`] is that object.
//!
//! ⚠ This is NOT the `key_size` / `known_keys_file` case R2336 disposed of. Those
//! are declared upstream and read by nothing — one occurrence each, on their own
//! declaration line. `add_pubkey`, `del_pubkey` and `disable_lookup` are reachable
//! API with callers, and `AuthPubKey::from_config` is called in production by the
//! line quoted above. The discriminator this register keeps arriving at is whether
//! upstream HONOURS a surface, and here it does.
//!
//! # Why the loader lives here and not in the wire module
//!
//! [`extauth_pubkey`](crate::extauth_pubkey) is the wire method: encode, encrypt,
//! decide. This module is where a lock and a filesystem are allowed to be, so the
//! method stays testable without either — the same split
//! [`extauth_usrpwd_store`](crate::extauth_usrpwd_store) draws, for the same
//! reason.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// A SHARED, mutable accepted-peer-key policy — the wz analogue of zenoh's
/// `RwLock<AuthPubKey>` lookup field.
///
/// Cloning shares the set rather than copying it, which is the entire point:
/// every handshake's [`PubKeyMethod`](crate::extauth_pubkey::PubKeyMethod) holds
/// a clone, so a later [`add_pubkey`](Self::add_pubkey) is visible to the NEXT
/// handshake without anyone re-installing a dispatch.
///
/// The inner `Option` is upstream's, and its two states are not "empty or not":
/// `None` is lookup DISABLED (admit any peer key, zenoh `disable_lookup`), while
/// `Some(set)` gates — and `Some(empty)` means different things on the two sides
/// of the handshake. That asymmetry is documented where it is read, on
/// [`admits_initiator`](Self::admits_initiator) and
/// [`admits_responder`](Self::admits_responder).
#[derive(Clone)]
pub struct PubKeyLookup {
    inner: Arc<Mutex<Option<Vec<RsaPublicKey>>>>,
}

impl PubKeyLookup {
    /// A DISABLED lookup: admits any peer key on either side. zenoh's
    /// `disable_lookup` state, and what `PubKeyMethod::initiator` has always
    /// meant.
    pub fn disabled() -> Self {
        Self::from_option(None)
    }

    /// A GATING lookup seeded with `keys`.
    ///
    /// ⚠ `gated(vec![])` is not "no policy" — on the responder side it rejects
    /// every initiator, which is precisely the state a stock pubkey zenohd is in
    /// (`AuthPubKey::new` seeds `Some(HashSet::new())`).
    pub fn gated(keys: Vec<RsaPublicKey>) -> Self {
        Self::from_option(Some(keys))
    }

    /// Build from the `Option` the existing constructors take, so the shared
    /// store is an addition to this module's surface rather than a change to it.
    pub fn from_option(keys: Option<Vec<RsaPublicKey>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(keys)),
        }
    }

    /// Register a peer key — the wz analogue of zenoh `AuthPubKey::add_pubkey`.
    ///
    /// Returns whether the set actually changed, so a caller can tell "added"
    /// from "already present" without a second query.
    ///
    /// Two behaviours are upstream's rather than choices made here. A DISABLED
    /// lookup is a no-op (upstream's `if let Some(lookup) = self.lookup.as_mut()`
    /// falls through and returns `Ok(())`), because a disabled lookup admits
    /// everyone already and silently re-enabling it would tighten a policy the
    /// caller never asked to tighten. And a duplicate does not append: upstream's
    /// lookup is a `HashSet`, so `insert` of a present key is a no-op. Appending
    /// would not change who is admitted — every read is a membership test and
    /// [`del_pubkey`](Self::del_pubkey) removes every copy — but it would break
    /// this method's own contract: a re-add would report that the set changed,
    /// and `len()` would count the key twice.
    pub fn add_pubkey(&self, key: RsaPublicKey) -> bool {
        let mut guard = self.lock();
        let Some(set) = guard.as_mut() else {
            return false;
        };
        if set.contains(&key) {
            return false;
        }
        set.push(key);
        true
    }

    /// Remove a peer key — the wz analogue of zenoh `AuthPubKey::del_pubkey`.
    ///
    /// Returns whether anything was removed. A DISABLED lookup is a no-op, for
    /// the reason [`add_pubkey`](Self::add_pubkey) gives.
    pub fn del_pubkey(&self, key: &RsaPublicKey) -> bool {
        let mut guard = self.lock();
        let Some(set) = guard.as_mut() else {
            return false;
        };
        let before = set.len();
        set.retain(|k| k != key);
        set.len() != before
    }

    /// Disable the lookup — the wz analogue of zenoh `AuthPubKey::disable_lookup`,
    /// which a multilink join calls so it does not re-check a key the first link
    /// already gated:
    ///
    /// `io/zenoh-transport/src/unicast/establishment/ext/multilink.rs` @ `auth.disable_lookup()`
    ///
    /// ⚠ This DISCARDS the gated set. Upstream's is the same one-way move: its
    /// field becomes `None` and the `HashSet` is dropped. There is no re-enable,
    /// here or upstream, because restoring a policy from nothing is not a thing
    /// either side can do.
    pub fn disable(&self) {
        *self.lock() = None;
    }

    /// Whether the lookup is disabled (admits any peer key).
    pub fn is_disabled(&self) -> bool {
        self.lock().is_none()
    }

    /// How many keys are gated, or `None` when the lookup is disabled. For tests
    /// and operator introspection — note `Some(0)` and `None` are opposite
    /// policies, which is why this is not a bare `usize`.
    pub fn len(&self) -> Option<usize> {
        self.lock().as_ref().map(Vec::len)
    }

    /// Whether the lookup gates an empty set. `false` for a DISABLED lookup,
    /// which holds no set at all rather than an empty one.
    pub fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }

    /// Whether a RESPONDER admits the initiator key `peer`. Mirrors zenoh
    /// `recv_init_syn`'s `if let Some(lookup) { contains }`: `None` accepts any
    /// key; `Some(set)` requires membership, so an empty `Some` rejects all.
    pub fn admits_initiator(&self, peer: &RsaPublicKey) -> bool {
        match self.lock().as_ref() {
            None => true,
            Some(set) => set.contains(peer),
        }
    }

    /// Whether an INITIATOR admits the responder key `peer`. The SAME field under
    /// a DIFFERENT rule: zenoh's `recv_init_ack` guards its membership test with
    /// `!lookup.is_empty()`, so an empty `Some` accepts every key here where on
    /// the responder side it rejects every key.
    ///
    /// The divergence is upstream's, not wz's, and it is why a stock zenohd
    /// (whose lookup is `Some(empty)`) can dial into an authenticated session
    /// while admitting nobody who dials it.
    pub fn admits_responder(&self, peer: &RsaPublicKey) -> bool {
        match self.lock().as_ref() {
            None => true,
            Some(set) => set.is_empty() || set.contains(peer),
        }
    }

    /// The lock, recovered from poisoning rather than propagating a panic.
    ///
    /// A poisoned key set is still a correct key set: the panic that poisoned it
    /// happened in another thread's critical section, and the data it guards has
    /// no invariant a panic could break half-way. Refusing every subsequent
    /// handshake because an unrelated thread panicked would turn one fault into a
    /// total authentication outage.
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Vec<RsaPublicKey>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for PubKeyLookup {
    /// A DISABLED lookup — the permissive default, matching
    /// `PubKeyMethod::initiator`.
    fn default() -> Self {
        Self::disabled()
    }
}

/// The four upstream `transport/auth/pubkey` config keys that name an RSA
/// identity, borrowed rather than owned so a caller can pass a parsed config
/// without cloning it.
///
/// A struct rather than four positional arguments deliberately: the four are two
/// interchangeable-looking pairs, and a transposed `public`/`private` would build
/// a node that advertises its private key.
#[derive(Debug, Default, Clone, Copy)]
pub struct PubKeyPemConfig<'a> {
    /// `transport/auth/pubkey/public_key_pem` — the PEM text itself.
    pub public_key_pem: Option<&'a str>,
    /// `transport/auth/pubkey/private_key_pem` — the PEM text itself.
    pub private_key_pem: Option<&'a str>,
    /// `transport/auth/pubkey/public_key_file` — a path to a PEM file.
    pub public_key_file: Option<&'a str>,
    /// `transport/auth/pubkey/private_key_file` — a path to a PEM file.
    pub private_key_file: Option<&'a str>,
}

/// Why an RSA identity could not be built from config.
#[derive(Debug)]
pub enum PubKeyLoadError {
    /// A public key was given without its private half.
    MissingPrivateKey {
        /// Whether the half that WAS given came from `*_pem` or `*_file`.
        from_file: bool,
    },
    /// A private key was given without its public half.
    MissingPublicKey {
        /// Whether the half that WAS given came from `*_pem` or `*_file`.
        from_file: bool,
    },
    /// The public key could not be decoded (or its file could not be read).
    PublicKey(rsa::pkcs1::Error),
    /// The private key could not be decoded (or its file could not be read).
    PrivateKey(rsa::pkcs1::Error),
    /// The configured public key is not the public half of the configured
    /// private key. See [`keypair_from_config`] for why this is refused here.
    Mismatched,
}

impl core::fmt::Display for PubKeyLoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let src = |from_file: &bool| if *from_file { "file" } else { "PEM" };
        match self {
            Self::MissingPrivateKey { from_file } => {
                write!(f, "missing Rsa Private Key: {}", src(from_file))
            }
            Self::MissingPublicKey { from_file } => {
                write!(f, "missing Rsa Public Key: {}", src(from_file))
            }
            Self::PublicKey(e) => write!(f, "invalid Rsa Public Key: {e}"),
            Self::PrivateKey(e) => write!(f, "invalid Rsa Private Key: {e}"),
            Self::Mismatched => write!(
                f,
                "the configured Rsa Public Key is not the public half of the \
                 configured Rsa Private Key"
            ),
        }
    }
}

impl std::error::Error for PubKeyLoadError {}

/// Build the node's RSA identity from the four config keys — the wz analogue of
/// zenoh `AuthPubKey::from_config`.
///
/// `Ok(None)` means "pubkey is not configured", which is upstream's answer when
/// none of the four keys is present; the caller decides whether that is fine.
///
/// # Precedence and the asymmetric refusals are upstream's
///
/// The inline PEM pair is tried FIRST and the file pair second, and giving one
/// half of either pair is an ERROR rather than a fall-through to the other pair.
/// Both are load-bearing: an operator who sets `public_key_pem` and misspells
/// `private_key_pem` must be told, not silently demoted to the file pair or to no
/// identity at all.
///
/// # The one stated divergence: a mismatched pair is refused HERE
///
/// Upstream stores the configured public key ALONGSIDE the private one and
/// advertises it on the wire, so a mismatched pair is accepted by `from_config`
/// and fails later — the peer encrypts its challenge under a key this node has no
/// private half for, and the handshake dies on a decrypt error with no mention of
/// config. wz's [`PubKeyMethod`](crate::extauth_pubkey::PubKeyMethod) DERIVES its
/// public key from its private one (`RsaPublicKey::from(&private_key)`), so the
/// same mismatched config would otherwise be silently repaired here and diverge
/// the other way — wz completing a handshake upstream refuses.
///
/// Refusing at load is the only one of the three that is both faithful in OUTCOME
/// (the pair authenticates nobody either way) and honest about WHY. It moves the
/// refusal earlier and names the cause; it never accepts a configuration upstream
/// rejects, nor rejects one upstream accepts and uses.
pub fn keypair_from_config(
    config: PubKeyPemConfig<'_>,
) -> Result<Option<RsaPrivateKey>, PubKeyLoadError> {
    // First, inline PEM text — upstream's first arm.
    match (config.public_key_pem, config.private_key_pem) {
        (Some(public), Some(private)) => {
            let public =
                RsaPublicKey::from_pkcs1_pem(public).map_err(PubKeyLoadError::PublicKey)?;
            let private =
                RsaPrivateKey::from_pkcs1_pem(private).map_err(PubKeyLoadError::PrivateKey)?;
            return checked_pair(public, private).map(Some);
        }
        (Some(_), None) => return Err(PubKeyLoadError::MissingPrivateKey { from_file: false }),
        (None, Some(_)) => return Err(PubKeyLoadError::MissingPublicKey { from_file: false }),
        (None, None) => {}
    }

    // Second, PEM files — upstream's second arm.
    match (config.public_key_file, config.private_key_file) {
        (Some(public), Some(private)) => {
            let public = RsaPublicKey::read_pkcs1_pem_file(Path::new(public))
                .map_err(PubKeyLoadError::PublicKey)?;
            let private = RsaPrivateKey::read_pkcs1_pem_file(Path::new(private))
                .map_err(PubKeyLoadError::PrivateKey)?;
            return checked_pair(public, private).map(Some);
        }
        (Some(_), None) => return Err(PubKeyLoadError::MissingPrivateKey { from_file: true }),
        (None, Some(_)) => return Err(PubKeyLoadError::MissingPublicKey { from_file: true }),
        (None, None) => {}
    }

    Ok(None)
}

/// Refuse a public key that is not the public half of `private`. See
/// [`keypair_from_config`] for the argument.
fn checked_pair(
    public: RsaPublicKey,
    private: RsaPrivateKey,
) -> Result<RsaPrivateKey, PubKeyLoadError> {
    if RsaPublicKey::from(&private) == public {
        Ok(private)
    } else {
        Err(PubKeyLoadError::Mismatched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};

    /// A fresh 512-bit RSA keypair — small for test speed. The PEM format is
    /// key-size-agnostic; production keys are 2048+.
    fn keypair() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut OsRng, 512).expect("512-bit test RSA key")
    }

    fn pem_pair(private: &RsaPrivateKey) -> (String, String) {
        let public = RsaPublicKey::from(private)
            .to_pkcs1_pem(LineEnding::LF)
            .expect("public PEM");
        let secret = private
            .to_pkcs1_pem(LineEnding::LF)
            .expect("private PEM")
            .to_string();
        (public, secret)
    }

    // ── The store ────────────────────────────────────────────────────────

    #[test]
    fn a_clone_shares_the_set_rather_than_copying_it() {
        // The property the whole store exists for: a method built from one clone
        // must see a key added through another. A copy-on-clone set would pass
        // every other test in this module and fail exactly this one, which is the
        // shape the residual described.
        let lookup = PubKeyLookup::gated(vec![]);
        let held_by_a_handshake = lookup.clone();
        let key = RsaPublicKey::from(&keypair());

        assert!(!held_by_a_handshake.admits_initiator(&key));
        assert!(lookup.add_pubkey(key.clone()));
        assert!(
            held_by_a_handshake.admits_initiator(&key),
            "a key added through one clone must be visible through another"
        );
    }

    #[test]
    fn add_pubkey_does_not_duplicate_and_del_pubkey_actually_admits_nobody() {
        // Upstream's lookup is a HashSet, so a re-add is a no-op. Two assertions
        // below catch an appending `add_pubkey`, and it is worth being exact
        // about which, because the obvious story is wrong here: `del_pubkey` is
        // a `retain`, which removes EVERY copy, so an appending add would NOT
        // leave a deleted key admitted. What it breaks is the CONTRACT -- the
        // re-add would return `true` ("the set changed") and `len()` would read
        // 2. R2627's control confirmed it: with the duplicate check removed,
        // this test failed on those, not on the delete.
        // The delete half is pinned separately and for its own reason: a delete
        // must leave the key refused, and deleting twice must report nothing.
        let lookup = PubKeyLookup::gated(vec![]);
        let key = RsaPublicKey::from(&keypair());

        assert!(lookup.add_pubkey(key.clone()));
        assert!(!lookup.add_pubkey(key.clone()), "a re-add is a no-op");
        assert_eq!(lookup.len(), Some(1));

        assert!(lookup.del_pubkey(&key));
        assert!(!lookup.admits_initiator(&key));
        assert!(!lookup.del_pubkey(&key), "deleting twice removes nothing");
    }

    #[test]
    fn a_disabled_lookup_is_inert_to_mutation_rather_than_becoming_gated() {
        // Upstream's add/del fall through on `None` and return Ok. If wz instead
        // created a set on first add, one `add_pubkey` on a permissive method
        // would silently start REJECTING every other peer -- a policy the caller
        // never asked for, and the failure would look like an unrelated outage.
        let lookup = PubKeyLookup::disabled();
        let key = RsaPublicKey::from(&keypair());
        let stranger = RsaPublicKey::from(&keypair());

        assert!(!lookup.add_pubkey(key.clone()));
        assert!(lookup.is_disabled());
        assert_eq!(lookup.len(), None);
        assert!(!lookup.del_pubkey(&key));
        assert!(
            lookup.admits_initiator(&stranger),
            "a disabled lookup still admits any key after a no-op add"
        );
    }

    #[test]
    fn disable_drops_the_gate_for_both_sides() {
        // zenoh's multilink calls `disable_lookup()` on a live authenticator, so
        // the transition has to be observable on a store already gating.
        let stranger = RsaPublicKey::from(&keypair());
        let lookup = PubKeyLookup::gated(vec![RsaPublicKey::from(&keypair())]);

        assert!(!lookup.admits_initiator(&stranger));
        lookup.disable();
        assert!(lookup.is_disabled());
        assert!(lookup.admits_initiator(&stranger));
        assert!(lookup.admits_responder(&stranger));
    }

    #[test]
    fn an_empty_gate_means_opposite_things_to_the_two_sides() {
        // The asymmetry is upstream's and is the reason a stock pubkey zenohd
        // dials out successfully while admitting nobody who dials it. Collapsing
        // the two rules onto one would break that direction silently.
        let lookup = PubKeyLookup::gated(vec![]);
        let stranger = RsaPublicKey::from(&keypair());

        assert!(!lookup.admits_initiator(&stranger), "responder rejects all");
        assert!(lookup.admits_responder(&stranger), "initiator accepts any");
        assert!(!lookup.is_disabled(), "an empty gate is not a disabled one");
        assert!(lookup.is_empty());
    }

    // ── The loader ───────────────────────────────────────────────────────

    #[test]
    fn nothing_configured_is_not_an_error() {
        let loaded =
            keypair_from_config(PubKeyPemConfig::default()).expect("no keys is not a fault");
        assert!(loaded.is_none());
    }

    #[test]
    fn an_inline_pem_pair_round_trips_to_the_same_key() {
        let private = keypair();
        let (public_pem, private_pem) = pem_pair(&private);
        let loaded = keypair_from_config(PubKeyPemConfig {
            public_key_pem: Some(&public_pem),
            private_key_pem: Some(&private_pem),
            ..Default::default()
        })
        .expect("a matched inline pair loads")
        .expect("and is configured");
        assert_eq!(loaded, private);
    }

    #[test]
    fn a_pem_file_pair_round_trips_to_the_same_key() {
        let dir = std::env::temp_dir().join(format!("wz-pubkey-pem-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let private = keypair();
        let (public_pem, private_pem) = pem_pair(&private);
        let public_path = dir.join("pub.pem");
        let private_path = dir.join("pri.pem");
        std::fs::write(&public_path, &public_pem).expect("write public");
        std::fs::write(&private_path, &private_pem).expect("write private");

        let loaded = keypair_from_config(PubKeyPemConfig {
            public_key_file: public_path.to_str(),
            private_key_file: private_path.to_str(),
            ..Default::default()
        })
        .expect("a matched file pair loads")
        .expect("and is configured");
        assert_eq!(loaded, private);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn half_a_pair_is_refused_rather_than_falling_through() {
        // Upstream bails on each half-pair. The fall-through this pins against is
        // the dangerous one: an operator who misspells `private_key_pem` would
        // otherwise get `Ok(None)` -- a node that starts, reports pubkey
        // configured, and authenticates with nothing.
        let private = keypair();
        let (public_pem, private_pem) = pem_pair(&private);

        assert!(matches!(
            keypair_from_config(PubKeyPemConfig {
                public_key_pem: Some(&public_pem),
                ..Default::default()
            }),
            Err(PubKeyLoadError::MissingPrivateKey { from_file: false })
        ));
        assert!(matches!(
            keypair_from_config(PubKeyPemConfig {
                private_key_pem: Some(&private_pem),
                ..Default::default()
            }),
            Err(PubKeyLoadError::MissingPublicKey { from_file: false })
        ));
        assert!(matches!(
            keypair_from_config(PubKeyPemConfig {
                public_key_file: Some("/nonexistent/pub.pem"),
                ..Default::default()
            }),
            Err(PubKeyLoadError::MissingPrivateKey { from_file: true })
        ));
        assert!(matches!(
            keypair_from_config(PubKeyPemConfig {
                private_key_file: Some("/nonexistent/pri.pem"),
                ..Default::default()
            }),
            Err(PubKeyLoadError::MissingPublicKey { from_file: true })
        ));
    }

    #[test]
    fn the_inline_pair_wins_over_the_file_pair() {
        // Upstream tries inline PEM first and returns before reaching the files.
        // The files here do not exist, so if the precedence were reversed this
        // would fail to READ rather than quietly pick the other key -- which is
        // what makes the assertion about precedence and not about equality.
        let private = keypair();
        let (public_pem, private_pem) = pem_pair(&private);
        let loaded = keypair_from_config(PubKeyPemConfig {
            public_key_pem: Some(&public_pem),
            private_key_pem: Some(&private_pem),
            public_key_file: Some("/nonexistent/pub.pem"),
            private_key_file: Some("/nonexistent/pri.pem"),
        })
        .expect("the inline pair is used and the files are never opened")
        .expect("and is configured");
        assert_eq!(loaded, private);
    }

    #[test]
    fn a_mismatched_pair_is_refused_at_load() {
        // wz's stated divergence: it derives its public key from its private one,
        // so without this check a mismatched config would be silently repaired
        // and wz would complete a handshake upstream refuses.
        let private = keypair();
        let (_, private_pem) = pem_pair(&private);
        let (other_public_pem, _) = pem_pair(&keypair());

        assert!(matches!(
            keypair_from_config(PubKeyPemConfig {
                public_key_pem: Some(&other_public_pem),
                private_key_pem: Some(&private_pem),
                ..Default::default()
            }),
            Err(PubKeyLoadError::Mismatched)
        ));
    }

    #[test]
    fn malformed_pem_names_which_half_was_malformed() {
        // `exit code is not a diagnosis` applies to error types too: a single
        // opaque `InvalidPem` would leave an operator re-checking both files.
        let private = keypair();
        let (public_pem, private_pem) = pem_pair(&private);

        assert!(matches!(
            keypair_from_config(PubKeyPemConfig {
                public_key_pem: Some("not a pem"),
                private_key_pem: Some(&private_pem),
                ..Default::default()
            }),
            Err(PubKeyLoadError::PublicKey(_))
        ));
        assert!(matches!(
            keypair_from_config(PubKeyPemConfig {
                public_key_pem: Some(&public_pem),
                private_key_pem: Some("not a pem"),
                ..Default::default()
            }),
            Err(PubKeyLoadError::PrivateKey(_))
        ));
    }
}
