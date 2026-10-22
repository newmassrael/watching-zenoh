// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The authentication a node's config asks for, held by the node and installed on each of its
//! sessions before the first wire byte.
//!
//! `transport/auth/usrpwd/*` was parsed into the node's config and then went nowhere: nothing a
//! program could reach built an authenticating session from it, so a node configured to demand
//! credentials started without a word and admitted everyone, and a node told what to present
//! dialled without it. This module is where the keys become behaviour, for both halves:
//!
//!   * `dictionary_file` makes the node a RESPONDER: a peer it accepts reaches Established only
//!     by presenting a user of that dictionary;
//!   * `user` and `password` make the node an INITIATOR: a peer it dials is shown that
//!     credential when it asks.
//!
//! `transport/auth/pubkey/*` names an RSA identity, and a node that states one uses it on both
//! sides, as upstream's does: it presents the key to the peers it dials and asks a key of the
//! peers it accepts. The set of peer keys it admits is upstream's from-config set, which is EMPTY
//! and shared by every session of the node; on the two sides an empty set means opposite things
//! (`PubKeyLookup::admits_initiator` and `admits_responder` carry the two rules), so such a node
//! reaches any peer it dials and admits no peer that dials it.
//!
//! # What a bad config does
//!
//! It fails the open. A node told to demand credentials from a file it cannot read, or from a
//! file that holds nobody, is not one that should start and hope: the alternative to refusing is
//! a node that believes it is protected and admits every peer. (Upstream folds an empty
//! dictionary to "no authentication" and opens; that is the same hole reached by a quieter road,
//! and this surface reports it as the configuration error it is.) A user without a password, or
//! a password without a user, is half a credential and is refused for the same reason: it cannot
//! authenticate to anything, and the node would only discover that when a peer refuses it. An RSA
//! identity that cannot be loaded (half a pair, a key that does not parse, a public key that is
//! not the private key's) is refused by the loader the runtime keeps for it
//! (`extauth_pubkey_store::keypair_from_config`).
//!
//! # Why the type exists in every build
//!
//! [`NodeAuth`] is a field of the node's open parameters, which the zenoh-pico ABI fills in too
//! (with `None`). Cargo unifies features across a workspace, so a field that existed only under
//! the credential features would break that ABI's literal in any build that also built zenoh-c's.
//! The type is therefore always there and carries nothing without them; only what builds one and
//! what it does with the credentials is gated.

#[cfg(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey"))]
use std::sync::Arc;

#[cfg(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey"))]
use wz_runtime_tokio::accept_loop::{AuthRole, SessionAuth};
#[cfg(feature = "access-extauth-pubkey")]
use wz_runtime_tokio::extauth_pubkey::PubKeyMethod;
#[cfg(feature = "access-extauth-pubkey")]
use wz_runtime_tokio::extauth_pubkey_store::{
    keypair_from_config, PubKeyLoadError, PubKeyLookup, PubKeyPemConfig,
};
#[cfg(feature = "access-extauth-usrpwd")]
use wz_runtime_tokio::extauth_usrpwd_store::{LoadError, UsrPwdStore};
#[cfg(feature = "access-extauth-pubkey")]
use wz_runtime_tokio::rsa::RsaPrivateKey;
#[cfg(feature = "access-extauth-usrpwd")]
use wz_runtime_tokio::zenoh_config::SecretText;
#[cfg(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey"))]
use wz_session_core::auth_dispatch::{AuthDispatch, AuthMethod};
#[cfg(feature = "access-extauth-usrpwd")]
use wz_session_core::extauth_usrpwd::UsrPwdMethod;

/// Why a node's authentication could not be built from its config.
#[cfg(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey"))]
#[derive(Debug)]
pub enum NodeAuthError {
    /// The dictionary file could not be read or parsed.
    #[cfg(feature = "access-extauth-usrpwd")]
    Dictionary(LoadError),
    /// The dictionary parsed and holds no user, so it would admit nobody and its node would be a
    /// listener no peer can reach.
    #[cfg(feature = "access-extauth-usrpwd")]
    EmptyDictionary,
    /// One of `user` and `password` is stated without the other.
    #[cfg(feature = "access-extauth-usrpwd")]
    IncompleteCredential,
    /// The RSA identity the pubkey keys name could not be loaded.
    #[cfg(feature = "access-extauth-pubkey")]
    PubKey(PubKeyLoadError),
}

#[cfg(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey"))]
impl core::fmt::Display for NodeAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "access-extauth-usrpwd")]
            Self::Dictionary(e) => write!(f, "the usrpwd dictionary cannot be loaded: {e}"),
            #[cfg(feature = "access-extauth-usrpwd")]
            Self::EmptyDictionary => f.write_str("the usrpwd dictionary holds no user"),
            #[cfg(feature = "access-extauth-usrpwd")]
            Self::IncompleteCredential => {
                f.write_str("the usrpwd user and password must be stated together")
            }
            #[cfg(feature = "access-extauth-pubkey")]
            Self::PubKey(e) => write!(f, "the pubkey identity cannot be loaded: {e}"),
        }
    }
}

#[cfg(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey"))]
impl std::error::Error for NodeAuthError {}

/// The RSA identity a node's pubkey keys name, and the set of peer keys it admits.
#[cfg(feature = "access-extauth-pubkey")]
#[derive(Clone)]
struct PubKeyIdentity {
    /// The node's private key; its public half is derived from it by the method.
    key: RsaPrivateKey,
    /// The peer keys the node admits, one set for every session of the node, as upstream holds
    /// one per transport manager.
    lookup: PubKeyLookup,
}

/// The authentication one node holds: what it verifies of the peers it accepts and what it
/// presents to the peers it dials. Never printed: it holds a password and a private key.
#[derive(Clone)]
pub struct NodeAuth {
    /// The credentials a peer must hold a user of to be accepted. Shared by every session's
    /// method, so a user added to it is admitted by the next handshake.
    #[cfg(feature = "access-extauth-usrpwd")]
    responder: Option<UsrPwdStore>,
    /// The user and password this node presents when it dials.
    #[cfg(feature = "access-extauth-usrpwd")]
    initiator: Option<(String, SecretText)>,
    /// The RSA identity this node presents when it dials and asks of the peers it accepts.
    #[cfg(feature = "access-extauth-pubkey")]
    pubkey: Option<PubKeyIdentity>,
}

#[cfg(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey"))]
impl NodeAuth {
    /// What this node presents to a peer it dials: the methods of the credentials it states, or
    /// `None` for a node that states none. A fresh value for each session, so no handshake shares
    /// state.
    pub fn dial_dispatch(&self) -> Option<AuthDispatch> {
        let mut methods: Vec<Box<dyn AuthMethod>> = Vec::new();
        #[cfg(feature = "access-extauth-pubkey")]
        if let Some(identity) = self.pubkey.as_ref() {
            methods.push(Box::new(PubKeyMethod::initiator_with_store(
                identity.key.clone(),
                identity.lookup.clone(),
            )));
        }
        #[cfg(feature = "access-extauth-usrpwd")]
        if let Some((user, password)) = self.initiator.as_ref() {
            methods.push(Box::new(UsrPwdMethod::initiator(
                user.as_bytes().to_vec(),
                password.expose().as_bytes().to_vec(),
            )));
        }
        (!methods.is_empty()).then(|| AuthDispatch::new(methods))
    }

    /// What this node verifies of a peer it accepts: the methods of the credentials it states,
    /// or `None` for a node that states none.
    pub fn accept_dispatch(&self) -> Option<AuthDispatch> {
        let mut methods: Vec<Box<dyn AuthMethod>> = Vec::new();
        #[cfg(feature = "access-extauth-pubkey")]
        if let Some(identity) = self.pubkey.as_ref() {
            // The challenge is drawn by the session itself at each InitAck, for this method
            // alone.
            methods.push(Box::new(PubKeyMethod::responder_with_store(
                identity.key.clone(),
                identity.lookup.clone(),
            )));
        }
        #[cfg(feature = "access-extauth-usrpwd")]
        if let Some(store) = self.responder.as_ref() {
            // The challenge nonce is drawn by the session itself at each InitAck, from OS
            // entropy; the `0` is the sentinel the method is built with.
            methods.push(Box::new(UsrPwdMethod::responder_with_source(
                Box::new(store.clone()),
                0,
            )));
        }
        (!methods.is_empty()).then(|| AuthDispatch::new(methods))
    }

    /// How each session of the node builds its authentication, for the accept loop
    /// ([`SessionAuth`]): by the side of the handshake the session is opened from.
    pub fn session_auth(&self) -> SessionAuth {
        let auth = self.clone();
        Arc::new(move |role| match role {
            AuthRole::Accept => auth.accept_dispatch(),
            AuthRole::Dial => auth.dial_dispatch(),
        })
    }
}

#[cfg(feature = "access-extauth-usrpwd")]
impl NodeAuth {
    /// The authentication a node's `transport/auth/usrpwd/*` keys ask for, or `None` for a node
    /// that states none of them.
    pub fn from_usrpwd_config(
        dictionary_file: Option<&str>,
        user: Option<&str>,
        password: Option<&SecretText>,
    ) -> Result<Option<Self>, NodeAuthError> {
        let initiator = match (user, password) {
            (None, None) => None,
            (Some(user), Some(password)) => Some((user.to_owned(), password.clone())),
            _ => return Err(NodeAuthError::IncompleteCredential),
        };
        let responder = match dictionary_file {
            None => None,
            Some(path) => {
                let store =
                    UsrPwdStore::from_dictionary_file(path).map_err(NodeAuthError::Dictionary)?;
                if store.is_empty() {
                    return Err(NodeAuthError::EmptyDictionary);
                }
                Some(store)
            }
        };
        if responder.is_none() && initiator.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            responder,
            initiator,
            #[cfg(feature = "access-extauth-pubkey")]
            pubkey: None,
        }))
    }
}

#[cfg(feature = "access-extauth-pubkey")]
impl NodeAuth {
    /// A node that asks nothing and presents nothing, for an identity to be added to.
    fn nothing() -> Self {
        Self {
            #[cfg(feature = "access-extauth-usrpwd")]
            responder: None,
            #[cfg(feature = "access-extauth-usrpwd")]
            initiator: None,
            pubkey: None,
        }
    }

    /// `auth` with the RSA identity the four `transport/auth/pubkey` keys name added to it, or
    /// `auth` unchanged for a node that states none of them.
    ///
    /// The identity is loaded by the runtime's loader, which applies upstream's precedence (the
    /// inline PEM pair before the file pair) and its refusals; a pair that cannot be loaded is
    /// an error and not a node without the identity.
    pub fn with_pubkey_config(
        auth: Option<Self>,
        config: PubKeyPemConfig<'_>,
    ) -> Result<Option<Self>, NodeAuthError> {
        let Some(key) = keypair_from_config(config).map_err(NodeAuthError::PubKey)? else {
            return Ok(auth);
        };
        let mut auth = auth.unwrap_or_else(Self::nothing);
        auth.pubkey = Some(PubKeyIdentity {
            key,
            lookup: PubKeyLookup::gated(Vec::new()),
        });
        Ok(Some(auth))
    }
}

#[cfg(all(test, feature = "access-extauth-usrpwd"))]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn file(text: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("a temp file");
        f.write_all(text.as_bytes()).expect("write");
        f
    }

    fn secret(text: &str) -> SecretText {
        SecretText::new(text)
    }

    #[test]
    fn a_config_that_states_nothing_builds_nothing() {
        assert!(NodeAuth::from_usrpwd_config(None, None, None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_dictionary_with_a_user_builds_a_responder_and_no_initiator() {
        let f = file("alice:s3cret\n");
        let auth = NodeAuth::from_usrpwd_config(Some(f.path().to_str().unwrap()), None, None)
            .unwrap()
            .expect("a dictionary asks for authentication");
        assert!(auth.accept_dispatch().is_some());
        assert!(auth.dial_dispatch().is_none());
    }

    #[test]
    fn a_user_and_password_build_an_initiator_and_no_responder() {
        let auth = NodeAuth::from_usrpwd_config(None, Some("alice"), Some(&secret("s3cret")))
            .unwrap()
            .expect("a credential asks for authentication");
        assert!(auth.dial_dispatch().is_some());
        assert!(auth.accept_dispatch().is_none());
    }

    #[test]
    fn half_a_credential_is_an_error_whichever_half_it_is() {
        assert!(matches!(
            NodeAuth::from_usrpwd_config(None, Some("alice"), None),
            Err(NodeAuthError::IncompleteCredential)
        ));
        assert!(matches!(
            NodeAuth::from_usrpwd_config(None, None, Some(&secret("s3cret"))),
            Err(NodeAuthError::IncompleteCredential)
        ));
    }

    #[test]
    fn a_missing_dictionary_is_an_error_and_not_an_unprotected_node() {
        let built = NodeAuth::from_usrpwd_config(Some("/nonexistent/wz-dictionary"), None, None);
        assert!(matches!(built, Err(NodeAuthError::Dictionary(_))));
    }

    #[test]
    fn a_dictionary_that_holds_nobody_is_an_error() {
        let f = file("\n\n");
        let built = NodeAuth::from_usrpwd_config(Some(f.path().to_str().unwrap()), None, None);
        assert!(matches!(built, Err(NodeAuthError::EmptyDictionary)));
    }

    #[test]
    fn a_session_builds_by_the_side_it_is_opened_from() {
        let f = file("alice:s3cret\n");
        let auth = NodeAuth::from_usrpwd_config(
            Some(f.path().to_str().unwrap()),
            Some("bob"),
            Some(&secret("hunter2")),
        )
        .unwrap()
        .expect("both halves");
        let build = auth.session_auth();
        let accepted = build(AuthRole::Accept).expect("an accepted session verifies");
        let dialled = build(AuthRole::Dial).expect("a dialled session presents");
        assert_eq!(accepted.method_count(), 1);
        assert_eq!(dialled.method_count(), 1);
    }
}

#[cfg(all(test, feature = "access-extauth-pubkey"))]
mod pubkey_tests {
    use super::*;
    use wz_runtime_tokio::extauth_pubkey::generate_keypair;
    use wz_runtime_tokio::rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    use wz_runtime_tokio::rsa::RsaPublicKey;

    /// A fresh identity as the two inline PEM texts the config carries, public first.
    fn pem_pair() -> (String, String) {
        let private = generate_keypair(512).expect("a 512-bit test key");
        let public = RsaPublicKey::from(&private)
            .to_pkcs1_pem(LineEnding::LF)
            .expect("public PEM");
        let private = private
            .to_pkcs1_pem(LineEnding::LF)
            .expect("private PEM")
            .to_string();
        (public, private)
    }

    /// The config of an identity stated as inline PEM text.
    fn inline<'a>(public: Option<&'a String>, private: Option<&'a String>) -> PubKeyPemConfig<'a> {
        PubKeyPemConfig {
            public_key_pem: public.map(String::as_str),
            private_key_pem: private.map(String::as_str),
            ..PubKeyPemConfig::default()
        }
    }

    #[test]
    fn a_config_that_names_no_identity_leaves_the_node_as_it_was() {
        assert!(
            NodeAuth::with_pubkey_config(None, PubKeyPemConfig::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn an_identity_builds_a_method_on_both_sides() {
        let (public, private) = pem_pair();
        let auth = NodeAuth::with_pubkey_config(None, inline(Some(&public), Some(&private)))
            .unwrap()
            .expect("an identity asks for authentication");
        let build = auth.session_auth();
        assert_eq!(
            build(AuthRole::Dial)
                .expect("a dialled session presents the key")
                .method_count(),
            1
        );
        assert_eq!(
            build(AuthRole::Accept)
                .expect("an accepted session asks for a key")
                .method_count(),
            1
        );
    }

    /// Upstream builds its from-config set empty, and the node keeps it so: on the accepting
    /// side that admits nobody, on the dialling side anybody.
    #[test]
    fn the_admitted_set_is_upstreams_empty_one() {
        let (public, private) = pem_pair();
        let auth = NodeAuth::with_pubkey_config(None, inline(Some(&public), Some(&private)))
            .unwrap()
            .expect("an identity");
        let identity = auth.pubkey.as_ref().expect("the identity is held");
        assert!(!identity.lookup.is_disabled());
        assert_eq!(identity.lookup.len(), Some(0));
    }

    #[test]
    fn half_a_pair_is_an_error_and_not_a_node_without_the_identity() {
        let (public, private) = pem_pair();
        assert!(matches!(
            NodeAuth::with_pubkey_config(None, inline(Some(&public), None)),
            Err(NodeAuthError::PubKey(_))
        ));
        assert!(matches!(
            NodeAuth::with_pubkey_config(None, inline(None, Some(&private))),
            Err(NodeAuthError::PubKey(_))
        ));
    }

    #[test]
    fn a_key_file_that_cannot_be_read_is_an_error() {
        let built = NodeAuth::with_pubkey_config(
            None,
            PubKeyPemConfig {
                public_key_file: Some("/nonexistent/wz-pub.pem"),
                private_key_file: Some("/nonexistent/wz-priv.pem"),
                ..PubKeyPemConfig::default()
            },
        );
        assert!(matches!(built, Err(NodeAuthError::PubKey(_))));
    }

    #[cfg(feature = "access-extauth-usrpwd")]
    #[test]
    fn an_identity_joins_the_usrpwd_credentials_the_node_already_states() {
        let (public, private) = pem_pair();
        let usrpwd =
            NodeAuth::from_usrpwd_config(None, Some("alice"), Some(&SecretText::new("s3cret")))
                .unwrap();
        let auth = NodeAuth::with_pubkey_config(usrpwd, inline(Some(&public), Some(&private)))
            .unwrap()
            .expect("both credentials");
        assert_eq!(
            auth.dial_dispatch().expect("presents both").method_count(),
            2
        );
        assert_eq!(
            auth.accept_dispatch().expect("asks the key").method_count(),
            1,
            "the node states no dictionary, so it asks the key alone"
        );
    }
}
