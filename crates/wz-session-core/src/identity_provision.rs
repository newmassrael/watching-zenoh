// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rule an identity is provisioned by on the machine that will be it: a certificate file and
//! a private key file, made once and never replaced (decision D9 of
//! `docs/session-lifecycle-intent.md`).
//!
//! The key is made where it will be used and never leaves that machine; whoever registers the
//! machine receives the certificate alone and computes from it the zid the key names
//! ([`crate::credential_identity`]). Two makers hold to this rule: a declared node's
//! `--make-identity`, on a device, and the C library's identity door, on the computer a client
//! runs on. Both read the two files' presence through
//! [`Provision::of`](crate::identity_provision::Provision::of) and say the same words when they
//! refuse, so a lab that provisions both kinds of machine reads one contract:
//!
//! - neither file is there: make a key and a certificate over it, the key first, each created
//!   exclusively so that nothing is replaced, and of two makers racing only one wins;
//! - both are there: make nothing, so that provisioning a machine again does not change its zid;
//! - only one is there: refuse, and write nothing. Half an identity is a fault to look at, and
//!   making the other half would pair a key with a certificate that is not its own.
//!
//! In every case that does not refuse, the maker then reads the two files back as a session
//! reads them, and the key must be the certificate's own
//! ([`NOT_ITS_KEY`](crate::identity_provision::NOT_ITS_KEY)).
//!
//! No allocation and no feature gate: the fixed-memory node and the heap library share it.

/// One of the two files of an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityFile {
    /// The certificate, whose public key names the zid.
    Certificate,
    /// The certificate's private key, its owner's alone.
    PrivateKey,
}

impl IdentityFile {
    /// The file as a refusal names it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Certificate => "the certificate",
            Self::PrivateKey => "the private key",
        }
    }
}

/// What a maker does with the two files it was given, by which of them are there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provision {
    /// Neither is there: make both.
    Make,
    /// Both are there: make nothing, and read them back.
    Keep,
    /// Only one is there: refuse, naming the one that is `missing` ([`HALF_AN_IDENTITY`]).
    Half {
        /// The file that is not there.
        missing: IdentityFile,
    },
}

impl Provision {
    /// The provision for a certificate and a key that are, or are not, there.
    pub const fn of(certificate_there: bool, key_there: bool) -> Self {
        match (certificate_there, key_there) {
            (false, false) => Self::Make,
            (true, true) => Self::Keep,
            (true, false) => Self::Half {
                missing: IdentityFile::PrivateKey,
            },
            (false, true) => Self::Half {
                missing: IdentityFile::Certificate,
            },
        }
    }
}

/// Why nothing is made when one file of the identity is there and the other is not: said of the
/// file that is missing.
pub const HALF_AN_IDENTITY: &str = "it is not there while the other file of the identity is: \
                                    nothing is made, so that a key is never paired with a \
                                    certificate that is not its own";

/// What a maker names when the fault is the identity's and not one file's.
pub const THE_IDENTITY: &str = "the identity";

/// Why nothing was made when the key could not be: said of [`THE_IDENTITY`].
pub const KEY_NOT_MADE: &str = "the secure channel could not make a key";

/// Why two files read back are no identity: said of the private key.
pub const NOT_ITS_KEY: &str =
    "it is not the private key of the certificate, or either does not parse";

/// The words a maker or a reader of an identity says of one file it could not make or read.
///
/// One copy for both makers and for the node that reads its identity at start
/// (`wz_runtime_posix::file`'s refusals answer with these), so a lab reads one sentence for one
/// fault on every kind of machine.
pub mod file_words {
    /// A file (or anything else) is at the path already, and is left as it is.
    pub const EXISTS: &str = "a file is there already, and is not overwritten";
    /// The file could not be made.
    pub const NOT_MADE: &str = "it could not be made";
    /// A write failed; what was made is removed.
    pub const NOT_WRITTEN: &str = "it could not be written";
    /// What was written could not be made durable; what was made is removed.
    pub const NOT_DURABLE: &str = "what was written could not be made durable";
    /// The file could not be opened.
    pub const NOT_OPENED: &str = "it could not be opened";
    /// Its status could not be read.
    pub const NO_STATUS: &str = "its status could not be read";
    /// A read failed.
    pub const NOT_READ: &str = "it could not be read";
    /// It is longer than what reads it takes.
    pub const TOO_LONG: &str = "it is longer than the buffer it is read into";
    /// A secret the group or others may read.
    pub const EXPOSED: &str = "it is a secret the group or others may read (chmod 600 it)";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_presence_of_the_two_files_has_one_provision() {
        assert_eq!(Provision::of(false, false), Provision::Make);
        assert_eq!(Provision::of(true, true), Provision::Keep);
        assert_eq!(
            Provision::of(true, false),
            Provision::Half {
                missing: IdentityFile::PrivateKey
            }
        );
        assert_eq!(
            Provision::of(false, true),
            Provision::Half {
                missing: IdentityFile::Certificate
            }
        );
    }

    #[test]
    fn the_refusal_sentences_are_the_ones_the_node_has_always_said() {
        // A lab's tools match these words; the node said them before the rule moved here.
        assert_eq!(
            HALF_AN_IDENTITY,
            "it is not there while the other file of the identity is: nothing is made, so that a \
             key is never paired with a certificate that is not its own"
        );
        assert_eq!(IdentityFile::Certificate.name(), "the certificate");
        assert_eq!(IdentityFile::PrivateKey.name(), "the private key");
    }
}
