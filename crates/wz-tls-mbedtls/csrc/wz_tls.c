/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The secure channel of decision D9 over Mbed TLS: an identity (a P-256 key in the PSA key
 * store and a certificate self-signed over it) and a TLS 1.3 session with mutual
 * authentication, pinned by the zid of the peer's key rather than by a chain. The interface is
 * `wz_tls.h`; this file is compiled with the configuration of the Mbed TLS it links, so it is
 * built beside that library: by `build.rs` from the pinned source, or by an image's own build
 * where the platform carries Mbed TLS (Zephyr).
 */

#include "wz_tls.h"

#include <string.h>

#include <psa/crypto.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include <mbedtls/memory_buffer_alloc.h>
#endif

/* The largest DER SubjectPublicKeyInfo of a key this channel takes: P-256 is 91 bytes. */
#define SPKI_MAX 160
/* The largest certificate this file writes: a self-signed P-256 one is under 400 bytes. */
#define CERT_MAX 1024

static int started;

/* Mbed TLS's allocator before `wz_tls_start` hands it the arena, where the configuration names
 * them (`wz_tls_crypto_config.h`): a refusal, so nothing allocates from a heap. An image built
 * against another configuration (Zephyr's) does not reference them. */
void *wz_tls_no_calloc(size_t count, size_t size)
{
	(void)count;
	(void)size;
	return NULL;
}

void wz_tls_no_free(void *ptr)
{
	(void)ptr;
}

int wz_tls_start(unsigned char *arena, size_t len)
{
	if (started) {
		return WZ_TLS_E_STATE;
	}
	if (arena != NULL) {
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
		mbedtls_memory_buffer_alloc_init(arena, len);
#else
		(void)len;
		return WZ_TLS_E_STATE;
#endif
	}
	/* NULL: the platform already serves Mbed TLS's allocations (Zephyr starts its own arena). */
	psa_status_t st = psa_crypto_init();
	if (st != PSA_SUCCESS) {
		return (int)st;
	}
	started = 1;
	return 0;
}

int wz_tls_arena_peak(size_t *bytes, size_t *blocks)
{
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(MBEDTLS_MEMORY_DEBUG)
	mbedtls_memory_buffer_alloc_max_get(bytes, blocks);
	return 0;
#else
	*bytes = 0;
	*blocks = 0;
	return -1;
#endif
}

void wz_tls_arena_peak_reset(void)
{
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(MBEDTLS_MEMORY_DEBUG)
	mbedtls_memory_buffer_alloc_max_reset();
#endif
}

/* ── The zid of a key: the first 16 bytes of SHA-256 over its DER SubjectPublicKeyInfo (D1). ── */

static int zid_of(const mbedtls_pk_context *pk, uint8_t zid[WZ_TLS_ZID_BYTES])
{
	unsigned char der[SPKI_MAX];
	uint8_t digest[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
	size_t digest_len = 0;
	/* Mbed TLS writes DER backwards, from the end of the buffer. */
	int n = mbedtls_pk_write_pubkey_der(pk, der, sizeof(der));

	if (n <= 0) {
		return n == 0 ? PSA_ERROR_INVALID_ARGUMENT : n;
	}
	psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, der + sizeof(der) - n, (size_t)n,
					   digest, sizeof(digest), &digest_len);
	if (st != PSA_SUCCESS) {
		return (int)st;
	}
	memcpy(zid, digest, WZ_TLS_ZID_BYTES);
	return 0;
}

/* ── An identity. ── */

struct wz_tls_identity {
	mbedtls_svc_key_id_t key;
	mbedtls_pk_context pk;
	mbedtls_x509_crt crt;
	uint8_t zid[WZ_TLS_ZID_BYTES];
};

static int write_self_signed(struct wz_tls_identity *id, const char *subject)
{
	/* Serial 1: a certificate is only the container of the key (D9), and one key has one. */
	static const unsigned char serial[] = { 1 };
	mbedtls_x509write_cert w;
	unsigned char *der = mbedtls_calloc(1, CERT_MAX);
	int rc;

	if (der == NULL) {
		return MBEDTLS_ERR_X509_ALLOC_FAILED;
	}
	mbedtls_x509write_crt_init(&w);
	mbedtls_x509write_crt_set_version(&w, MBEDTLS_X509_CRT_VERSION_3);
	rc = mbedtls_x509write_crt_set_serial_raw(&w, (unsigned char *)serial, sizeof(serial));
	if (rc == 0) {
		/* No clock is assumed: the validity is not a verdict here (the pin is). */
		rc = mbedtls_x509write_crt_set_validity(&w, "20260101000000", "20991231235959");
	}
	if (rc == 0) {
		rc = mbedtls_x509write_crt_set_subject_name(&w, subject);
	}
	if (rc == 0) {
		rc = mbedtls_x509write_crt_set_issuer_name(&w, subject);
	}
	mbedtls_x509write_crt_set_subject_key(&w, &id->pk);
	mbedtls_x509write_crt_set_issuer_key(&w, &id->pk);
	mbedtls_x509write_crt_set_md_alg(&w, MBEDTLS_MD_SHA256);
	int n = rc == 0 ? mbedtls_x509write_crt_der(&w, der, CERT_MAX) : rc;
	mbedtls_x509write_crt_free(&w);
	if (n > 0) {
		rc = mbedtls_x509_crt_parse_der(&id->crt, der + CERT_MAX - n, (size_t)n);
	} else {
		rc = n == 0 ? MBEDTLS_ERR_X509_BAD_INPUT_DATA : n;
	}
	mbedtls_free(der);
	return rc;
}

int wz_tls_identity_generate(struct wz_tls_identity **out, const char *subject)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	struct wz_tls_identity *id;
	int rc;

	if (!started) {
		return WZ_TLS_E_STATE;
	}
	id = mbedtls_calloc(1, sizeof(*id));
	if (id == NULL) {
		return MBEDTLS_ERR_SSL_ALLOC_FAILED;
	}
	mbedtls_pk_init(&id->pk);
	mbedtls_x509_crt_init(&id->crt);
	id->key = MBEDTLS_SVC_KEY_ID_INIT;

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
	psa_status_t st = psa_generate_key(&attr, &id->key);
	if (st != PSA_SUCCESS) {
		mbedtls_free(id);
		return (int)st;
	}
	rc = mbedtls_pk_wrap_psa(&id->pk, id->key);
	if (rc == 0) {
		rc = write_self_signed(id, subject);
	}
	if (rc == 0) {
		rc = zid_of(&id->pk, id->zid);
	}
	if (rc != 0) {
		wz_tls_identity_free(id);
		return rc;
	}
	*out = id;
	return 0;
}

void wz_tls_identity_zid(const struct wz_tls_identity *id, uint8_t zid[WZ_TLS_ZID_BYTES])
{
	memcpy(zid, id->zid, WZ_TLS_ZID_BYTES);
}

void wz_tls_identity_cert(const struct wz_tls_identity *id, const uint8_t **der, size_t *len)
{
	*der = id->crt.raw.p;
	*len = id->crt.raw.len;
}

void wz_tls_identity_free(struct wz_tls_identity *id)
{
	if (id == NULL) {
		return;
	}
	mbedtls_x509_crt_free(&id->crt);
	mbedtls_pk_free(&id->pk);
	psa_destroy_key(id->key);
	mbedtls_free(id);
}

/* ── A session. ── */

struct wz_tls_session {
	mbedtls_ssl_config conf;
	mbedtls_ssl_context ssl;
	struct wz_tls_io io;
	/* The transport reported a failure; the call that saw it returns WZ_TLS_E_TRANSPORT. */
	int io_failed;
};

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct wz_tls_session *s = ctx;
	int n = s->io.send(s->io.ctx, buf, len);

	if (n >= 0) {
		return n;
	}
	if (n == WZ_TLS_IO_WOULD_BLOCK) {
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	s->io_failed = 1;
	return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct wz_tls_session *s = ctx;
	int n = s->io.recv(s->io.ctx, buf, len);

	if (n >= 0) {
		/* 0 is the end of the stream, which Mbed TLS reads as such. */
		return n;
	}
	if (n == WZ_TLS_IO_WOULD_BLOCK) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	s->io_failed = 1;
	return MBEDTLS_ERR_NET_RECV_FAILED;
}

/* An Mbed TLS result as this interface states it. */
static int result(struct wz_tls_session *s, int rc)
{
	if (rc >= 0) {
		return rc;
	}
	if (s->io_failed) {
		return WZ_TLS_E_TRANSPORT;
	}
	switch (rc) {
	case MBEDTLS_ERR_SSL_WANT_READ:
		return WZ_TLS_WANT_READ;
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return WZ_TLS_WANT_WRITE;
	default:
		return rc;
	}
}

int wz_tls_session_open(struct wz_tls_session **out, int role, const struct wz_tls_identity *own,
			const struct wz_tls_io *io)
{
	int endpoint = role == WZ_TLS_SERVER ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;
	struct wz_tls_session *s;
	int rc;

	if (!started) {
		return WZ_TLS_E_STATE;
	}
	s = mbedtls_calloc(1, sizeof(*s));
	if (s == NULL) {
		return MBEDTLS_ERR_SSL_ALLOC_FAILED;
	}
	mbedtls_ssl_config_init(&s->conf);
	mbedtls_ssl_init(&s->ssl);
	s->io = *io;

	rc = mbedtls_ssl_config_defaults(&s->conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT);
	if (rc == 0) {
		mbedtls_ssl_conf_min_tls_version(&s->conf, MBEDTLS_SSL_VERSION_TLS1_3);
		mbedtls_ssl_conf_max_tls_version(&s->conf, MBEDTLS_SSL_VERSION_TLS1_3);
		/* The peer must present a certificate and prove its key in CertificateVerify, which
		 * Mbed TLS checks in every mode; OPTIONAL keeps an untrusted chain from ending the
		 * handshake, because no chain is the verdict here: the zid of the key is, and the
		 * caller reads it before any data (`wz_tls_session_peer_zid`).
		 */
		mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
		rc = mbedtls_ssl_conf_own_cert(&s->conf, (mbedtls_x509_crt *)&own->crt,
					       (mbedtls_pk_context *)&own->pk);
	}
	if (rc == 0) {
		rc = mbedtls_ssl_setup(&s->ssl, &s->conf);
	}
	if (rc == 0 && endpoint == MBEDTLS_SSL_IS_CLIENT) {
		/* The identity is the zid, never a name: no server name is sent or checked. */
		rc = mbedtls_ssl_set_hostname(&s->ssl, NULL);
	}
	if (rc != 0) {
		wz_tls_session_free(s);
		return rc;
	}
	mbedtls_ssl_set_bio(&s->ssl, s, bio_send, bio_recv, NULL);
	*out = s;
	return 0;
}

void wz_tls_session_set_io_ctx(struct wz_tls_session *s, void *ctx)
{
	s->io.ctx = ctx;
}

int wz_tls_session_handshake(struct wz_tls_session *s)
{
	int rc = result(s, mbedtls_ssl_handshake(&s->ssl));

	if (rc == 0 && mbedtls_ssl_get_peer_cert(&s->ssl) == NULL) {
		/* OPTIONAL lets a client finish without one; a channel without a key proves nobody. */
		return WZ_TLS_E_NO_PEER_CERT;
	}
	return rc;
}

int wz_tls_session_peer_zid(const struct wz_tls_session *s, uint8_t zid[WZ_TLS_ZID_BYTES])
{
	const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&s->ssl);

	if (peer == NULL) {
		return WZ_TLS_E_NO_PEER_CERT;
	}
	return zid_of(&peer->pk, zid);
}

const char *wz_tls_session_suite(const struct wz_tls_session *s)
{
	if (!mbedtls_ssl_is_handshake_over((mbedtls_ssl_context *)&s->ssl)) {
		return NULL;
	}
	return mbedtls_ssl_get_ciphersuite(&s->ssl);
}

int wz_tls_session_write(struct wz_tls_session *s, const unsigned char *buf, size_t len)
{
	return result(s, mbedtls_ssl_write(&s->ssl, buf, len));
}

int wz_tls_session_read(struct wz_tls_session *s, unsigned char *buf, size_t len)
{
	int rc = mbedtls_ssl_read(&s->ssl, buf, len);

	if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || rc == MBEDTLS_ERR_SSL_CONN_EOF) {
		return 0;
	}
	return result(s, rc);
}

int wz_tls_session_pending(const struct wz_tls_session *s)
{
	return mbedtls_ssl_get_bytes_avail(&s->ssl) > 0 || mbedtls_ssl_check_pending(&s->ssl);
}

void wz_tls_session_close_notify(struct wz_tls_session *s)
{
	(void)mbedtls_ssl_close_notify(&s->ssl);
}

void wz_tls_session_free(struct wz_tls_session *s)
{
	if (s == NULL) {
		return;
	}
	mbedtls_ssl_free(&s->ssl);
	mbedtls_ssl_config_free(&s->conf);
	mbedtls_free(s);
}
