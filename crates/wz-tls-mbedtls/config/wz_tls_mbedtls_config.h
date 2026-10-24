/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Mbed TLS's configuration for the secure channel of decision D9
 * (docs/session-lifecycle-intent.md), as the pinned source is built on the profiles that are not
 * Zephyr, stating what the kit image states in Kconfig (`deploy/zephyr-tls-fit/prj.conf`): TLS
 * 1.3 only, both roles, the ephemeral key exchange only, no session tickets, one cipher suite,
 * the certificate a device writes over its own key and the peer's it reads.
 */

#ifndef WZ_TLS_MBEDTLS_CONFIG_H
#define WZ_TLS_MBEDTLS_CONFIG_H

#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
/* TLS 1.3 requires it; the pin reads the peer's certificate after the handshake. */
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

/* The one suite the channel offers and takes. */
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS1_3_AES_128_GCM_SHA256

#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CRT_WRITE_C

/* The record buffers, decided in Round 3495. RECEIVE is the protocol's maximum, 2^14: a peer
 * that did not negotiate the record size limit (RFC 8449; rustls 0.23, which zenohd 1.10.1
 * links, does not implement it) may send a record that large. SEND is ours to bound: a
 * negotiated batch (1,024 on the fixed-memory profile) with its 2-byte length, or this end's own
 * handshake flight, whichever is larger. */
#define MBEDTLS_SSL_IN_CONTENT_LEN  16384
#define MBEDTLS_SSL_OUT_CONTENT_LEN 1500

#endif /* WZ_TLS_MBEDTLS_CONFIG_H */
