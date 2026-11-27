// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host's ES256, over `ring`: the verifier a host node opens sealed commands with, and the
//! signer a commander, a tool or a test seals them with.

use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING,
};

use crate::{Es256, Es256Signer, SealError, POINT_LEN, SIGNATURE_LEN};

/// ES256 verified by `ring`, which refuses a point that is not on P-256.
#[derive(Debug, Clone, Copy, Default)]
pub struct RingEs256;

impl Es256 for RingEs256 {
    fn verify(
        &self,
        point: &[u8; POINT_LEN],
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point.as_slice())
            .verify(message, signature.as_slice())
            .is_ok()
    }
}

/// A P-256 key that signs ES256 with `ring`.
pub struct RingSigner {
    key: EcdsaKeyPair,
    point: [u8; POINT_LEN],
    rng: SystemRandom,
}

impl RingSigner {
    /// The key a PKCS#8 document holds (the DER of a `BEGIN PRIVATE KEY` PEM, which
    /// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` writes). Refused as
    /// [`SealError::Key`] unless it is a P-256 key whose document carries its public half.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, SealError> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
            .map_err(|_| SealError::Key)?;
        let point =
            <[u8; POINT_LEN]>::try_from(key.public_key().as_ref()).map_err(|_| SealError::Key)?;
        Ok(Self { key, point, rng })
    }

    /// A new key, made from the system's randomness: a commander for a test.
    pub fn generate() -> Result<Self, SealError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| SealError::Signer)?;
        Self::from_pkcs8(pkcs8.as_ref())
    }
}

impl Es256Signer for RingSigner {
    fn point(&self) -> [u8; POINT_LEN] {
        self.point
    }

    fn sign(&self, message: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
        let signature = self.key.sign(&self.rng, message).ok()?;
        <[u8; SIGNATURE_LEN]>::try_from(signature.as_ref()).ok()
    }
}
