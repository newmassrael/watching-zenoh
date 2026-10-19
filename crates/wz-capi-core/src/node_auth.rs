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
//! # What a bad config does
//!
//! It fails the open. A node told to demand credentials from a file it cannot read, or from a
//! file that holds nobody, is not one that should start and hope: the alternative to refusing is
//! a node that believes it is protected and admits every peer. (Upstream folds an empty
//! dictionary to "no authentication" and opens; that is the same hole reached by a quieter road,
//! and this surface reports it as the configuration error it is.) A user without a password, or
//! a password without a user, is half a credential and is refused for the same reason: it cannot
//! authenticate to anything, and the node would only discover that when a peer refuses it.
//!
//! # Why the type exists in every build
//!
//! [`NodeAuth`] is a field of the node's open parameters, which the zenoh-pico ABI fills in too
//! (with `None`). Cargo unifies features across a workspace, so a field that existed only under
//! the credential feature would break that ABI's literal in any build that also built zenoh-c's.
//! The type is therefore always there and carries nothing without the feature; only what builds
//! one and what it does with the credentials is gated.

#[cfg(feature = "access-extauth-usrpwd")]
use std::sync::Arc;

#[cfg(feature = "access-extauth-usrpwd")]
use wz_runtime_tokio::accept_loop::{AuthRole, SessionAuth};
#[cfg(feature = "access-extauth-usrpwd")]
use wz_runtime_tokio::extauth_usrpwd_store::{LoadError, UsrPwdStore};
#[cfg(feature = "access-extauth-usrpwd")]
use wz_runtime_tokio::zenoh_config::SecretText;
#[cfg(feature = "access-extauth-usrpwd")]
use wz_session_core::auth_dispatch::AuthDispatch;
#[cfg(feature = "access-extauth-usrpwd")]
use wz_session_core::extauth_usrpwd::UsrPwdMethod;

/// Why a node's authentication could not be built from its config.
#[cfg(feature = "access-extauth-usrpwd")]
#[derive(Debug)]
pub enum NodeAuthError {
    /// The dictionary file could not be read or parsed.
    Dictionary(LoadError),
    /// The dictionary parsed and holds no user, so it would admit nobody and its node would be a
    /// listener no peer can reach.
    EmptyDictionary,
    /// One of `user` and `password` is stated without the other.
    IncompleteCredential,
}

#[cfg(feature = "access-extauth-usrpwd")]
impl core::fmt::Display for NodeAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dictionary(e) => write!(f, "the usrpwd dictionary cannot be loaded: {e}"),
            Self::EmptyDictionary => f.write_str("the usrpwd dictionary holds no user"),
            Self::IncompleteCredential => {
                f.write_str("the usrpwd user and password must be stated together")
            }
        }
    }
}

#[cfg(feature = "access-extauth-usrpwd")]
impl std::error::Error for NodeAuthError {}

/// The authentication one node holds: what it verifies of the peers it accepts and what it
/// presents to the peers it dials. Never printed: it holds a password.
#[derive(Clone)]
pub struct NodeAuth {
    /// The credentials a peer must hold a user of to be accepted. Shared by every session's
    /// method, so a user added to it is admitted by the next handshake.
    #[cfg(feature = "access-extauth-usrpwd")]
    responder: Option<UsrPwdStore>,
    /// The user and password this node presents when it dials.
    #[cfg(feature = "access-extauth-usrpwd")]
    initiator: Option<(String, SecretText)>,
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
        }))
    }

    /// What this node presents to a peer it dials: the usrpwd initiator method, or `None` for a
    /// node with no credential. A fresh value for each session, so no handshake shares state.
    pub fn dial_dispatch(&self) -> Option<AuthDispatch> {
        let (user, password) = self.initiator.as_ref()?;
        Some(AuthDispatch::new(vec![Box::new(UsrPwdMethod::initiator(
            user.as_bytes().to_vec(),
            password.expose().as_bytes().to_vec(),
        )) as _]))
    }

    /// What this node verifies of a peer it accepts: the usrpwd responder method over the
    /// node's dictionary, or `None` for a node with none.
    pub fn accept_dispatch(&self) -> Option<AuthDispatch> {
        let store = self.responder.as_ref()?;
        // The challenge nonce is drawn by the session itself at each InitAck, from OS
        // entropy; the `0` is the sentinel the method is built with.
        Some(AuthDispatch::new(vec![
            Box::new(UsrPwdMethod::responder_with_source(
                Box::new(store.clone()),
                0,
            )) as _,
        ]))
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
