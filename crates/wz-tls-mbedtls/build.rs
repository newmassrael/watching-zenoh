// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-tls-mbedtls build.rs -- with `vendored`, builds the pinned Mbed TLS (vendor/mbedtls, with
// vendor/tf-psa-crypto as its crypto library) through its own CMake under this crate's
// configuration, then compiles the channel's C side (csrc/wz_tls.c) against it. The two must
// share one configuration: the C side reads Mbed TLS structures, whose layout the configuration
// decides, so both see the same MBEDTLS_CONFIG_FILE and TF_PSA_CRYPTO_CONFIG_FILE.
//
// Without `vendored` nothing is built here: the image compiles csrc/wz_tls.c in its own build,
// against the Mbed TLS its platform carries, and links both.

use std::env;
use std::path::PathBuf;

/// The libraries Mbed TLS's CMake installs, in link order: TLS, then X.509, then the crypto
/// library both use.
const LIBRARIES: [&str; 3] = ["mbedtls", "mbedx509", "tfpsacrypto"];

const TLS_CONFIG: &str = "wz_tls_mbedtls_config.h";
const CRYPTO_CONFIG: &str = "wz_tls_crypto_config.h";

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    for watched in ["csrc", "config"] {
        println!(
            "cargo:rerun-if-changed={}",
            manifest_dir.join(watched).display()
        );
    }
    if env::var_os("CARGO_FEATURE_VENDORED").is_none() {
        return;
    }

    let source = |path: &str| {
        dunce::canonicalize(manifest_dir.join(path))
            .unwrap_or_else(|e| panic!("{path}: {e} (is the submodule checked out?)"))
    };
    let mbedtls = source("../../vendor/mbedtls");
    let crypto = source("../../vendor/tf-psa-crypto");
    let config = source("config");
    let csrc = source("csrc");
    // A submodule that was never initialised is an empty directory, which CMake reads as a
    // project with no CMakeLists.txt; say what is missing instead.
    for tree in [&mbedtls, &crypto] {
        assert!(
            tree.join("CMakeLists.txt").is_file(),
            "{} is empty: run `git submodule update --init vendor/mbedtls vendor/tf-psa-crypto`",
            tree.display()
        );
    }
    println!(
        "cargo:rerun-if-changed={}",
        mbedtls.join("library").display()
    );
    println!("cargo:rerun-if-changed={}", crypto.join("core").display());

    let dst = cmake::Config::new(&mbedtls)
        .define("TF_PSA_CRYPTO_DIR", &crypto)
        .define("MBEDTLS_CONFIG_FILE", config.join(TLS_CONFIG))
        .define("TF_PSA_CRYPTO_CONFIG_FILE", config.join(CRYPTO_CONFIG))
        .define("ENABLE_PROGRAMS", "OFF")
        .define("ENABLE_TESTING", "OFF")
        // The generated sources are committed at the pinned revision; regenerating them would
        // need Python packages a build host does not have.
        .define("GEN_FILES", "OFF")
        // Upstream's warnings are upstream's; a newer compiler must not stop this build on them.
        .define("MBEDTLS_FATAL_WARNINGS", "OFF")
        .define("TF_PSA_CRYPTO_FATAL_WARNINGS", "OFF")
        .define("USE_SHARED_MBEDTLS_LIBRARY", "OFF")
        .define("USE_STATIC_MBEDTLS_LIBRARY", "ON")
        // The handshake's arithmetic is what the channel costs; build it optimised in every
        // cargo profile, as the image's build does.
        .profile("Release")
        .build();

    let include = dst.join("include");
    cc::Build::new()
        .file(csrc.join("wz_tls.c"))
        .include(&csrc)
        .include(&config)
        .include(&include)
        .define("MBEDTLS_CONFIG_FILE", Some(quoted(TLS_CONFIG).as_str()))
        .define(
            "TF_PSA_CRYPTO_CONFIG_FILE",
            Some(quoted(CRYPTO_CONFIG).as_str()),
        )
        .compile("wz_tls");

    for lib_dir in ["lib", "lib64"] {
        let dir = dst.join(lib_dir);
        if dir.is_dir() {
            println!("cargo:rustc-link-search=native={}", dir.display());
        }
    }
    for library in LIBRARIES {
        println!("cargo:rustc-link-lib=static={library}");
    }
    // The headers and configuration an image compiling against this build would need.
    println!("cargo:include={}", include.display());
    println!("cargo:config={}", config.display());
}

/// `name` as a C string literal, the form `#include MBEDTLS_CONFIG_FILE` takes.
fn quoted(name: &str) -> String {
    format!("\"{name}\"")
}
