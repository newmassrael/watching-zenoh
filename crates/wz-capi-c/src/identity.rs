// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE IDENTITY A CLIENT PRESENTS, MADE ON THE COMPUTER IT RUNS ON: the door a program that links
//! this library calls once, before it opens a session over TLS with its own key.
//!
//! # Why this is a door
//!
//! A declared node makes its identity on its device with `--make-identity <certificate>
//! <private_key>`, and a peer whose zid is bound to its key is what a node's commander list names
//! (decision D1 and D9 of `docs/session-lifecycle-intent.md`). A client has no node executable,
//! so until now it could make the same identity only with a node's binary. This is the same
//! contract (`wz_session_core::identity_provision`): a P-256 key and a certificate self-signed over
//! it, the key first and its owner's alone, each file created exclusively; both files there, nothing
//! is made; one there, nothing is made and the missing one is named. Either way the two files are
//! read back as the TLS link reads them, and the zid answered is the one a peer computes from the
//! certificate (`wz_runtime_tokio::tls_identity`).
//!
//! The files are what a configuration names (`transport/link/tls/connect_certificate`,
//! `connect_private_key`, with `enable_mtls`), and the zid is the spelling its `id` takes, so a
//! session opened with them proves the zid a node's list names.
//!
//! # No session, no allocation the caller sees
//!
//! A pure call over two paths and the caller's struct: no session is opened, no runtime started,
//! and every string handed back is in the struct or a static string this library owns.
//!
//! Unix only, as the maker it calls is: a file's mode is what makes the key its owner's alone.
#![cfg(unix)]

use core::ffi::{c_char, CStr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use wz_runtime_tokio::tls_identity::make_identity_files;

use crate::result::{ZResult, Z_EIO, Z_ENULL, Z_OK};

/// The bytes the zid's text takes: at most 32 hex digits and its NUL.
pub const WZ_CAPI_C_IDENTITY_ZID_MAX: usize = 33;

/// The common name of the certificate this door makes. No peer reads it (the zid is the key's);
/// it says which maker made the file to whoever opens it.
const COMMON_NAME: &str = "wz-capi-c";

/// An identity made or found, or why there is none.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_capi_c_identity_t {
    /// This call made both files; false when both were there already, or on a refusal.
    pub made: bool,
    /// The zid the key names, lower-case hex as `z_id_to_string` prints it and a configuration's
    /// `id` takes it, NUL-terminated; empty on a refusal.
    pub zid: [c_char; WZ_CAPI_C_IDENTITY_ZID_MAX],
    /// On a refusal, what it is said of: `the certificate`, `the private key` or `the identity`;
    /// NULL otherwise.
    pub file: *const c_char,
    /// On a refusal, why, in the contract's words; NULL otherwise.
    pub reason: *const c_char,
}

/// Make the identity whose certificate is the file `certificate` and whose private key is the file
/// `private_key`, both PEM, unless both are there already, and write the zid its key names into
/// `out`.
///
/// Returns `Z_OK` when the identity is there (`out.made` says whether this call made it), `Z_EIO`
/// when it is not, with `out.file` and `out.reason` saying which file and why (nothing is made
/// then, and nothing that was there is changed), and `Z_ENULL` for a NULL argument. `out` is
/// filled from scratch.
///
/// # Safety
/// `certificate` and `private_key` are NUL-terminated paths, `out` writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_identity_make(
    certificate: *const c_char,
    private_key: *const c_char,
    out: *mut wz_capi_c_identity_t,
) -> ZResult {
    if out.is_null() {
        return Z_ENULL;
    }
    let mut made = wz_capi_c_identity_t {
        made: false,
        zid: [0; WZ_CAPI_C_IDENTITY_ZID_MAX],
        file: core::ptr::null(),
        reason: core::ptr::null(),
    };
    let rc = if certificate.is_null() || private_key.is_null() {
        Z_ENULL
    } else {
        // SAFETY: both are non-NULL, NUL-terminated by the caller's contract.
        let (certificate, private_key) =
            unsafe { (CStr::from_ptr(certificate), CStr::from_ptr(private_key)) };
        match make_identity_files(path(certificate), path(private_key), COMMON_NAME) {
            Ok(provisioned) => {
                made.made = provisioned.made;
                let text = provisioned.zid_text();
                for (cell, byte) in made.zid.iter_mut().zip(text.bytes()) {
                    *cell = byte as c_char;
                }
                Z_OK
            }
            Err(why) => {
                made.file = static_c_str(why.subject());
                made.reason = static_c_str(why.reason);
                Z_EIO
            }
        }
    };
    // SAFETY: `out` is non-NULL and writable by the caller's contract.
    unsafe { out.write(made) };
    rc
}

/// A C path as the path it names: on unix a path is bytes, whatever their encoding.
fn path(text: &CStr) -> &Path {
    Path::new(std::ffi::OsStr::from_bytes(text.to_bytes()))
}

/// The NUL-terminated copy of a static sentence, made once per sentence and kept for the life of
/// the library: the refusal's words are the contract's, and a C caller holds them past this call.
fn static_c_str(text: &'static str) -> *const c_char {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::sync::{Mutex, OnceLock};

    static TEXTS: OnceLock<Mutex<BTreeMap<&'static str, &'static CStr>>> = OnceLock::new();
    let mut texts = TEXTS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    texts
        .entry(text)
        .or_insert_with(|| {
            let owned = CString::new(text).expect("a sentence of the contract holds no NUL");
            Box::leak(owned.into_boxed_c_str())
        })
        .as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::process::Command;

    struct Dir(std::path::PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("wz-capi-c-identity-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn c_path(&self, file: &str) -> CString {
            CString::new(self.0.join(file).as_os_str().as_bytes()).unwrap()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make(cert: &CString, key: &CString) -> (ZResult, wz_capi_c_identity_t) {
        let mut out = core::mem::MaybeUninit::<wz_capi_c_identity_t>::uninit();
        // SAFETY: two live C strings and a writable struct.
        let rc = unsafe { wz_capi_c_identity_make(cert.as_ptr(), key.as_ptr(), out.as_mut_ptr()) };
        // SAFETY: the door fills `out` on every path that has an `out`.
        (rc, unsafe { out.assume_init() })
    }

    fn text(ptr: *const c_char) -> &'static str {
        assert!(!ptr.is_null());
        // SAFETY: a static string this library owns.
        unsafe { CStr::from_ptr(ptr) }.to_str().unwrap()
    }

    fn zid(out: &wz_capi_c_identity_t) -> String {
        // SAFETY: the array is NUL-terminated.
        unsafe { CStr::from_ptr(out.zid.as_ptr()) }
            .to_str()
            .unwrap()
            .to_string()
    }

    /// The zid this door answers is the zid the declaration tools compute from the certificate
    /// (`wz_node.py --zid-of`, a reader of the DER written apart from the Rust one), so the text a
    /// lab writes into a node's commander list is the text this door gave.
    #[test]
    fn the_door_makes_once_and_its_zid_is_the_one_wz_node_computes() {
        let dir = Dir::new("make");
        let (cert, key) = (dir.c_path("cert.pem"), dir.c_path("key.pem"));
        let (rc, first) = make(&cert, &key);
        assert_eq!(rc, Z_OK);
        assert!(first.made);
        assert!(first.file.is_null() && first.reason.is_null());
        let first_zid = zid(&first);
        assert!(
            !first_zid.is_empty()
                && first_zid.len() <= 32
                && !first_zid.starts_with('0')
                && first_zid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{first_zid}"
        );

        let (rc, again) = make(&cert, &key);
        assert_eq!(rc, Z_OK);
        assert!(!again.made, "both files there: nothing is made");
        assert_eq!(zid(&again), first_zid);

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let printed = Command::new("python3")
            .arg(root.join("scripts/lib/wz_node.py"))
            .arg("--zid-of")
            .arg(dir.0.join("cert.pem"))
            .output()
            .expect("python3 runs");
        assert!(printed.status.success(), "{printed:?}");
        assert_eq!(String::from_utf8(printed.stdout).unwrap().trim(), first_zid);
    }

    #[test]
    fn half_an_identity_is_refused_in_the_contracts_words_and_nothing_is_made() {
        let dir = Dir::new("half");
        let (cert, key) = (dir.c_path("cert.pem"), dir.c_path("key.pem"));
        assert_eq!(make(&cert, &key).0, Z_OK);
        std::fs::remove_file(dir.0.join("key.pem")).unwrap();
        let (rc, out) = make(&cert, &key);
        assert_eq!(rc, Z_EIO);
        assert!(!out.made);
        assert_eq!(zid(&out), "");
        assert_eq!(text(out.file), "the private key");
        assert_eq!(
            text(out.reason),
            wz_session_core::identity_provision::HALF_AN_IDENTITY
        );
        assert!(!dir.0.join("key.pem").exists(), "nothing is made");
    }

    #[test]
    fn a_place_no_file_can_be_made_is_z_eio_and_a_null_argument_is_z_enull() {
        let path = CString::new("/nonexistent/wz/me.crt").unwrap();
        let (rc, out) = make(&path, &CString::new("/nonexistent/wz/me.key").unwrap());
        assert_eq!(
            rc, Z_EIO,
            "a directory that is not there: the key cannot be made"
        );
        assert_eq!(text(out.file), "the private key");
        let mut out = core::mem::MaybeUninit::<wz_capi_c_identity_t>::uninit();
        // SAFETY: NULL paths are what is tested; `out` is writable.
        let rc =
            unsafe { wz_capi_c_identity_make(core::ptr::null(), path.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, Z_ENULL);
        // SAFETY: as above, with a NULL `out`, which is not written.
        let rc =
            unsafe { wz_capi_c_identity_make(path.as_ptr(), path.as_ptr(), core::ptr::null_mut()) };
        assert_eq!(rc, Z_ENULL);
    }
}
