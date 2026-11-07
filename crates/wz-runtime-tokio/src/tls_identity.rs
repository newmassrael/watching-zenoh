// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The identity a client presents over the TLS link, made on the computer it runs on (decision D9
//! of `docs/session-lifecycle-intent.md`): a P-256 key and a certificate self-signed over it,
//! written once and never replaced.
//!
//! A declared node makes its identity on its device with `--make-identity`; this is the same
//! contract for a program that links the C library and has no node executable. Both follow
//! [`wz_session_core::identity_provision`]: neither file there, both are made (the key first, each
//! created exclusively); both there, nothing is made; one there, nothing is made and the missing
//! one is named. The words of every refusal are that module's.
//!
//! In every case that does not refuse, the two files are read back as the TLS link reads them
//! ([`crate::tls_config::certs_from_pem`], [`crate::tls_config::private_key_from_pem`]), the key
//! must be the certificate's own, and the zid answered is the one a peer computes from the
//! certificate the link presents ([`crate::stream_link::peer_chain_credential_zid`]). A session
//! configured with these files and that zid as its `id` is a peer whose zid is bound to its key.
//!
//! The key is the computer's alone from the moment it exists (mode 0600), and a key read back
//! that the group or others may read is refused, as a node refuses it at start. The key's text is
//! overwritten in this process's memory once it is written or read.
//!
//! Unix only: a file's mode is what makes a key its owner's alone, and a platform without one has
//! no file this contract can call a secret.
#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use tokio_rustls::rustls::crypto::ring::sign::any_supported_type;
use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::identity_provision::{
    file_words, IdentityFile, Provision, HALF_AN_IDENTITY, KEY_NOT_MADE, NOT_ITS_KEY, THE_IDENTITY,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::stream_link::peer_chain_credential_zid;
use crate::tls_config::{certs_from_pem, private_key_from_pem};

/// The most bytes either file is read back to: a certificate chain or a key is a few KiB.
pub const IDENTITY_FILE_BYTES_MAX: u64 = 64 * 1024;

/// An identity that is there: the zid its key names, and whether this call made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provisioned {
    /// The zid the key names, sixteen bytes as a derived zid is
    /// ([`wz_session_core::credential_identity::zid_from_spki_der`]).
    pub zid: [u8; CREDENTIAL_ZID_BYTES],
    /// The call made both files; false when both were there already.
    pub made: bool,
}

impl Provisioned {
    /// The zid as zenoh spells it (`z_id_to_string`, a configuration's `id`): lower-case hex of
    /// the `u128`, no leading zero.
    pub fn zid_text(&self) -> String {
        wz_session_core::zid_hex::zid_to_zenoh_hex(&self.zid)
    }
}

/// Why no identity is there: the file the fault is in (or the identity as a whole) and the
/// sentence of [`wz_session_core::identity_provision`] that says why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityRefused {
    /// The file, or `None` for the identity as a whole.
    pub file: Option<IdentityFile>,
    /// Why, in the contract's words.
    pub reason: &'static str,
}

impl IdentityRefused {
    /// What the refusal is said of: `the certificate`, `the private key` or `the identity`.
    pub const fn subject(&self) -> &'static str {
        match self.file {
            Some(file) => file.name(),
            None => THE_IDENTITY,
        }
    }
}

const fn refused(file: Option<IdentityFile>, reason: &'static str) -> IdentityRefused {
    IdentityRefused { file, reason }
}

/// Make the identity whose certificate is at `certificate` and whose private key is at
/// `private_key`, both PEM, unless both are there already, and answer the zid its key names. The
/// certificate's subject is `CN=<common_name>`; no peer reads the name (the zid is the key's).
pub fn make_identity_files(
    certificate: &Path,
    private_key: &Path,
    common_name: &str,
) -> Result<Provisioned, IdentityRefused> {
    let made = match Provision::of(is_there(certificate), is_there(private_key)) {
        Provision::Keep => false,
        Provision::Make => {
            write_made_identity(certificate, private_key, common_name)?;
            true
        }
        Provision::Half { missing } => return Err(refused(Some(missing), HALF_AN_IDENTITY)),
    };
    let zid = read_identity(certificate, private_key)?;
    Ok(Provisioned { zid, made })
}

/// Whether anything is at `path`. A link counts and is not followed, as the node's maker reads it:
/// a dangling link is a file that is there, and is not replaced.
fn is_there(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Make an identity and write it: the key first, so that of two makers racing on one computer
/// only the one that made the key writes a certificate, and a key whose certificate could not be
/// written is removed again.
fn write_made_identity(
    certificate: &Path,
    private_key: &Path,
    common_name: &str,
) -> Result<(), IdentityRefused> {
    let not_made = |_| refused(None, KEY_NOT_MADE);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(not_made)?;
    let mut params = rcgen::CertificateParams::default();
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, common_name);
    params.distinguished_name = name;
    // The validity a node's own maker writes: no clock is assumed, and the validity is not the
    // verdict (the zid and the pin are).
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 12, 31);
    let cert = params.self_signed(&key).map_err(not_made)?;
    let mut key_text = key.serialize_pem().into_bytes();
    drop(key);

    let written = create_new(private_key, &key_text, true)
        .map_err(|why| refused(Some(IdentityFile::PrivateKey), why));
    wipe(&mut key_text);
    written?;
    if let Err(why) = create_new(certificate, cert.pem().as_bytes(), false) {
        // The key this call made just above, which no certificate holds.
        let _ = fs::remove_file(private_key);
        return Err(refused(Some(IdentityFile::Certificate), why));
    }
    Ok(())
}

/// Create `path` with `bytes`, exclusively and without following a link, readable by its owner
/// alone when it is a `secret`, and durable before this returns. What could not be written whole
/// is removed.
fn create_new(path: &Path, bytes: &[u8], secret: bool) -> Result<(), &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if secret { 0o600 } else { 0o644 })
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|why| match why.kind() {
            io::ErrorKind::AlreadyExists => file_words::EXISTS,
            _ => file_words::NOT_MADE,
        })?;
    let written = file
        .write_all(bytes)
        .map_err(|_| file_words::NOT_WRITTEN)
        .and_then(|()| file.sync_all().map_err(|_| file_words::NOT_DURABLE));
    if written.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    written
}

/// Read the two files back as the TLS link reads them, and answer the zid a peer computes from the
/// certificate, when the key is its own.
fn read_identity(
    certificate: &Path,
    private_key: &Path,
) -> Result<[u8; CREDENTIAL_ZID_BYTES], IdentityRefused> {
    let chain_text = read_whole(certificate, false)
        .map_err(|why| refused(Some(IdentityFile::Certificate), why))?;
    let mut key_text = read_whole(private_key, true)
        .map_err(|why| refused(Some(IdentityFile::PrivateKey), why))?;
    let zid = paired_zid(&chain_text, &key_text);
    wipe(&mut key_text);
    zid.ok_or(refused(Some(IdentityFile::PrivateKey), NOT_ITS_KEY))
}

/// The zid of the chain in `chain_text`, when the key in `key_text` is its leaf's own.
fn paired_zid(chain_text: &[u8], key_text: &[u8]) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
    let chain = certs_from_pem(chain_text).ok()?;
    let leaf = chain.first()?;
    let key = private_key_from_pem(key_text).ok()?;
    let signing = any_supported_type(&key).ok()?;
    let public = signing.public_key()?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    if parsed.tbs_certificate.subject_pki.raw != public.as_ref() {
        return None;
    }
    peer_chain_credential_zid(Some(&chain))
}

/// The whole of the file at `path`, at most [`IDENTITY_FILE_BYTES_MAX`] bytes; a `secret` only
/// when no one but its owner may read it.
fn read_whole(path: &Path, secret: bool) -> Result<Vec<u8>, &'static str> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| file_words::NOT_OPENED)?;
    let status = file.metadata().map_err(|_| file_words::NO_STATUS)?;
    if secret && status.mode() & 0o077 != 0 {
        return Err(file_words::EXPOSED);
    }
    if status.len() > IDENTITY_FILE_BYTES_MAX {
        return Err(file_words::TOO_LONG);
    }
    let mut text = Vec::new();
    let read = file
        .take(IDENTITY_FILE_BYTES_MAX + 1)
        .read_to_end(&mut text);
    let refusal = match read {
        Err(_) => Some(file_words::NOT_READ),
        Ok(_) if text.len() as u64 > IDENTITY_FILE_BYTES_MAX => Some(file_words::TOO_LONG),
        Ok(_) => None,
    };
    match refusal {
        Some(why) => {
            wipe(&mut text);
            Err(why)
        }
        None => Ok(text),
    }
}

/// Overwrite `bytes` with zeros, in a way the compiler does not elide.
fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: a live, writable byte; volatile so the wipe is not elided.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wz_session_core::credential_identity::zid_from_spki_der;

    struct Dir(std::path::PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "wz-tls-identity-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn files(&self) -> (std::path::PathBuf, std::path::PathBuf) {
            (self.0.join("cert.pem"), self.0.join("key.pem"))
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn neither_file_there_makes_both_and_the_zid_is_the_one_the_certificate_names() {
        let dir = Dir::new("make");
        let (cert, key) = dir.files();
        let made = make_identity_files(&cert, &key, "wz-test").unwrap();
        assert!(made.made);
        assert_eq!(mode(&key), 0o600, "the key is its owner's alone");

        // The zid is the hash of the certificate's key, computed here apart from the maker.
        let der = certs_from_pem(&fs::read(&cert).unwrap()).unwrap();
        let (_, parsed) = X509Certificate::from_der(der[0].as_ref()).unwrap();
        assert_eq!(
            made.zid,
            zid_from_spki_der(parsed.tbs_certificate.subject_pki.raw)
        );
        assert_eq!(
            parsed.subject().iter_common_name().next().unwrap().as_str(),
            Ok("wz-test")
        );
    }

    #[test]
    fn both_files_there_make_nothing_and_answer_the_same_zid() {
        let dir = Dir::new("keep");
        let (cert, key) = dir.files();
        let first = make_identity_files(&cert, &key, "wz-test").unwrap();
        let (cert_text, key_text) = (fs::read(&cert).unwrap(), fs::read(&key).unwrap());
        let again = make_identity_files(&cert, &key, "wz-test").unwrap();
        assert_eq!(
            again,
            Provisioned {
                zid: first.zid,
                made: false
            }
        );
        assert_eq!(fs::read(&cert).unwrap(), cert_text, "nothing is replaced");
        assert_eq!(fs::read(&key).unwrap(), key_text, "nothing is replaced");
    }

    #[test]
    fn one_file_there_makes_nothing_and_names_the_missing_one() {
        let dir = Dir::new("half");
        let (cert, key) = dir.files();
        make_identity_files(&cert, &key, "wz-test").unwrap();
        fs::remove_file(&cert).unwrap();
        let why = make_identity_files(&cert, &key, "wz-test").unwrap_err();
        assert_eq!(
            why,
            refused(Some(IdentityFile::Certificate), HALF_AN_IDENTITY)
        );
        assert_eq!(why.subject(), "the certificate");
        assert!(!is_there(&cert), "nothing is made");

        let other = Dir::new("half-key");
        let (cert, key) = other.files();
        make_identity_files(&cert, &key, "wz-test").unwrap();
        fs::remove_file(&key).unwrap();
        let why = make_identity_files(&cert, &key, "wz-test").unwrap_err();
        assert_eq!(
            why,
            refused(Some(IdentityFile::PrivateKey), HALF_AN_IDENTITY)
        );
        assert!(!is_there(&key), "nothing is made");
    }

    #[test]
    fn a_key_others_may_read_or_a_key_that_is_not_the_certificates_is_refused() {
        let dir = Dir::new("exposed");
        let (cert, key) = dir.files();
        make_identity_files(&cert, &key, "wz-test").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            make_identity_files(&cert, &key, "wz-test").unwrap_err(),
            refused(Some(IdentityFile::PrivateKey), file_words::EXPOSED)
        );

        // Two identities, each file of one paired with the other's.
        let a = Dir::new("pair-a");
        let b = Dir::new("pair-b");
        let (cert_a, key_a) = a.files();
        let (_, key_b) = b.files();
        make_identity_files(&cert_a, &key_a, "wz-test").unwrap();
        make_identity_files(&b.files().0, &key_b, "wz-test").unwrap();
        fs::remove_file(&key_a).unwrap();
        fs::rename(&key_b, &key_a).unwrap();
        assert_eq!(
            make_identity_files(&cert_a, &key_a, "wz-test").unwrap_err(),
            refused(Some(IdentityFile::PrivateKey), NOT_ITS_KEY)
        );
    }

    /// What the identity is for: a TLS link presents it, a peer that pins its certificate accepts
    /// it, and the peer computes from it the zid the maker answered.
    #[test]
    fn a_made_identity_is_accepted_by_a_peer_that_pins_it_and_names_the_same_zid() {
        use crate::tls_config::{
            client_config_from_pem, server_config_from_pem, ClientAuthPem, ServerNameVerification,
        };
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::rustls::{ClientConnection, ServerConnection};

        let (client_dir, server_dir) = (Dir::new("client"), Dir::new("server"));
        let (client_cert, client_key) = client_dir.files();
        let (server_cert, server_key) = server_dir.files();
        let client = make_identity_files(&client_cert, &client_key, "wz-client").unwrap();
        make_identity_files(&server_cert, &server_key, "wz-server").unwrap();
        let read = |path: &Path| fs::read(path).unwrap();

        let client_config = client_config_from_pem(
            Some(&read(&server_cert)),
            Some(ClientAuthPem {
                cert_chain_pem: &read(&client_cert),
                private_key_pem: &read(&client_key),
            }),
            ServerNameVerification::AnyName,
        )
        .unwrap();
        let server_config = server_config_from_pem(
            &read(&server_cert),
            &read(&server_key),
            Some(&read(&client_cert)),
        )
        .unwrap();
        let mut c =
            ClientConnection::new(client_config, ServerName::try_from("wz").unwrap()).unwrap();
        let mut s = ServerConnection::new(server_config).unwrap();
        for _ in 0..16 {
            if !c.is_handshaking() && !s.is_handshaking() {
                break;
            }
            let mut wire = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut wire).unwrap();
            }
            s.read_tls(&mut wire.as_slice()).unwrap();
            s.process_new_packets()
                .expect("the server accepts the client");
            let mut wire = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut wire).unwrap();
            }
            c.read_tls(&mut wire.as_slice()).unwrap();
            c.process_new_packets()
                .expect("the client accepts the server");
        }
        assert!(
            !c.is_handshaking() && !s.is_handshaking(),
            "the handshake ends"
        );
        assert_eq!(
            peer_chain_credential_zid(s.peer_certificates()),
            Some(client.zid),
            "the server names the client by the zid the maker answered"
        );
    }

    #[test]
    fn a_dangling_link_is_a_file_that_is_there_and_is_not_followed() {
        let dir = Dir::new("link");
        let (cert, key) = dir.files();
        let target = dir.0.join("elsewhere.pem");
        std::os::unix::fs::symlink(&target, &key).unwrap();
        // The key's place is taken and the certificate's is not: half an identity.
        assert_eq!(
            make_identity_files(&cert, &key, "wz-test").unwrap_err(),
            refused(Some(IdentityFile::Certificate), HALF_AN_IDENTITY)
        );
        assert!(!is_there(&target), "the link is not followed");
    }
}
