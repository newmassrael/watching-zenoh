// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An RSA private key opens an identity in either PEM form it is written in. OpenSSL 3 writes
//! `BEGIN PRIVATE KEY` (PKCS#8) by default and the stock zenoh-pico examples carry
//! `BEGIN RSA PRIVATE KEY` (PKCS#1); the pinned Mbed TLS leaves the public half of a PKCS#8 RSA
//! key unset, so without the channel's completion the zid could not be derived and the open
//! failed with PSA's invalid-argument code (-135). The key is made here by the `openssl` tool, as
//! the host that runs the test has it, so no private key is kept in the repository.
#![cfg(all(feature = "rsa", unix))]

use std::ffi::CString;
use std::path::Path;
use std::process::Command;

use wz_session_core::credential_identity::zid_from_spki_der;
use wz_tls_mbedtls::channel::{start, Identity};

fn openssl(dir: &Path, script: &str) {
    let status = Command::new("sh")
        .arg("-c")
        .arg(script)
        .current_dir(dir)
        .status()
        .expect("the openssl tool runs (this test needs it on PATH)");
    assert!(status.success(), "openssl step failed: {script}");
}

fn pem(dir: &Path, name: &str) -> CString {
    CString::new(std::fs::read(dir.join(name)).expect("the file openssl wrote"))
        .expect("PEM has no NUL")
}

#[test]
fn an_rsa_key_opens_an_identity_as_pkcs1_and_as_pkcs8_and_names_the_same_zid() {
    let dir = std::env::temp_dir().join(format!("wz-rsa-key-forms-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    openssl(
        &dir,
        "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out pkcs8.pem \
         && openssl rsa -in pkcs8.pem -traditional -out pkcs1.pem \
         && openssl req -new -x509 -key pkcs8.pem -subj /CN=localhost -days 30 -out cert.pem \
         && openssl pkey -in pkcs8.pem -pubout -outform DER -out spki.der",
    );

    let arena: &'static mut [u8] = vec![0u8; 1 << 20].leak();
    start(arena).expect("the library starts");

    let cert = pem(&dir, "cert.pem");
    assert!(
        std::str::from_utf8(pem(&dir, "pkcs8.pem").to_bytes())
            .expect("PEM is text")
            .starts_with("-----BEGIN PRIVATE KEY-----"),
        "the PKCS#8 form is the one under test"
    );
    assert!(
        std::str::from_utf8(pem(&dir, "pkcs1.pem").to_bytes())
            .expect("PEM is text")
            .starts_with("-----BEGIN RSA PRIVATE KEY-----"),
        "the PKCS#1 form is the control"
    );

    let pkcs1 = Identity::from_pem(&cert, &pem(&dir, "pkcs1.pem")).expect("the PKCS#1 key opens");
    let pkcs8 = Identity::from_pem(&cert, &pem(&dir, "pkcs8.pem")).expect("the PKCS#8 key opens");
    let spki = std::fs::read(dir.join("spki.der")).expect("the public key openssl wrote");
    let named = zid_from_spki_der(&spki);

    assert_eq!(pkcs1.zid(), named, "the PKCS#1 key names the SPKI's zid");
    assert_eq!(pkcs8.zid(), named, "the PKCS#8 key names the SPKI's zid");
    std::fs::remove_dir_all(&dir).ok();
}
