/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * TF-PSA-Crypto's configuration for the secure channel of decision D9
 * (docs/session-lifecycle-intent.md), as the pinned source is built on the profiles that are not
 * Zephyr. It states the same choices the kit image states in Kconfig
 * (`deploy/zephyr-tls-fit/prj.conf`): P-256 keys in the PSA key store, ECDSA and ECDH over them,
 * the TLS 1.3 key schedule (HKDF over HMAC-SHA-256) and AES-128-GCM records, a DRBG over the
 * platform's entropy, and every allocation from one static arena. Nothing else is built.
 */

#ifndef WZ_TLS_CRYPTO_CONFIG_H
#define WZ_TLS_CRYPTO_CONFIG_H

/* The algorithms and key types the channel uses. */
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_ECDSA                      1
#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_HMAC                       1
#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ECC_SECP_R1_256                1
#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_KEY_TYPE_DERIVE                1
#define PSA_WANT_KEY_TYPE_HMAC                  1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1

/* PSA Crypto itself, with its random generator: a CTR_DRBG seeded from the platform's entropy
 * (the operating system's on a host, as the kit's is its TRNG). */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_CTR_DRBG_C

/* The key and certificate encodings the channel reads and writes. */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
/* A certificate authority's certificates and keys arrive as PEM (the form a peer's files and
 * the pico configuration hold them in); the generated identity never needs it. */
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C

/* Every allocation comes from the arena the program hands `wz_tls_start`; its peak is measured.
 * Before that, Mbed TLS's allocator is not the C library's but one that refuses (`wz_tls.c`), so
 * no allocation can reach a heap: the arena is the only memory the channel can be given. */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_MEMORY_DEBUG
#include <stddef.h>
void *wz_tls_no_calloc(size_t count, size_t size);
void wz_tls_no_free(void *ptr);
#define MBEDTLS_PLATFORM_STD_CALLOC wz_tls_no_calloc
#define MBEDTLS_PLATFORM_STD_FREE wz_tls_no_free

/* The NIST curve reduction, as the kit's build has it. */
#define MBEDTLS_ECP_NIST_OPTIM

#endif /* WZ_TLS_CRYPTO_CONFIG_H */
