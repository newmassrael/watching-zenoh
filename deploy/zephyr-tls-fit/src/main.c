/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The fit of the fixed-memory profile's secure channel (decision D9 of
 * docs/session-lifecycle-intent.md), measured on the device it is for.
 *
 * Two peers in one image, a client and a server, each with an identity of its own: a P-256 key
 * generated in the PSA key store and a certificate self-signed over it here. They run a TLS 1.3
 * handshake with mutual authentication over an in-memory pipe, and each accepts the other only
 * when the zid derived from the key in the other's certificate (decision D1: the first 16 bytes
 * of SHA-256 over the DER SubjectPublicKeyInfo) is the zid it expected. There is no certificate
 * authority: the chain is not the verdict, the key is (the client configures OPTIONAL so that an
 * untrusted chain does not end the handshake, and the possession of the key is still proven by
 * CertificateVerify, which Mbed TLS checks whatever the mode).
 *
 * What the console says, one line per round and one at the end, is what the channel costs: the
 * time of each role's handshake (only the time spent inside that role's calls), the peak of the
 * static arena every Mbed TLS allocation comes from, and the main thread's stack. A last round
 * expects a zid the server does not have, and must refuse it.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <psa/crypto.h>

#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#define ZID_BYTES 16

/* ── The pipe: one ring per direction, enough for the largest TLS record and its header. ── */

#define RING_BYTES (16384 + 2048)

struct ring {
	uint8_t buf[RING_BYTES];
	size_t head;
	size_t len;
};

static struct ring to_server;
static struct ring to_client;

struct end {
	struct ring *out;
	struct ring *in;
};

static int pipe_send(void *ctx, const unsigned char *data, size_t len)
{
	struct ring *r = ((struct end *)ctx)->out;
	size_t room = RING_BYTES - r->len;

	if (room == 0) {
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	if (len > room) {
		len = room;
	}
	for (size_t i = 0; i < len; i++) {
		r->buf[(r->head + r->len + i) % RING_BYTES] = data[i];
	}
	r->len += len;
	return (int)len;
}

static int pipe_recv(void *ctx, unsigned char *data, size_t len)
{
	struct ring *r = ((struct end *)ctx)->in;

	if (r->len == 0) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	if (len > r->len) {
		len = r->len;
	}
	for (size_t i = 0; i < len; i++) {
		data[i] = r->buf[(r->head + i) % RING_BYTES];
	}
	r->head = (r->head + len) % RING_BYTES;
	r->len -= len;
	return (int)len;
}

/* ── An identity: the key in the PSA store, the certificate over it, the zid it names. ── */

struct identity {
	mbedtls_svc_key_id_t key;
	mbedtls_pk_context pk;
	mbedtls_x509_crt crt;
	uint8_t zid[ZID_BYTES];
};

static int zid_of(mbedtls_pk_context *pk, uint8_t zid[ZID_BYTES])
{
	static unsigned char der[160];
	uint8_t digest[32];
	size_t digest_len = 0;
	int n = mbedtls_pk_write_pubkey_der(pk, der, sizeof(der));

	if (n <= 0) {
		return n == 0 ? -1 : n;
	}
	psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, der + sizeof(der) - n, (size_t)n,
					   digest, sizeof(digest), &digest_len);
	if (st != PSA_SUCCESS) {
		return (int)st;
	}
	memcpy(zid, digest, ZID_BYTES);
	return 0;
}

static int identity_make(struct identity *id, const char *name, uint8_t serial)
{
	static unsigned char der[1024];
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_x509write_cert w;
	int rc;

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE |
					       PSA_KEY_USAGE_VERIFY_HASH |
					       PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
	psa_status_t st = psa_generate_key(&attr, &id->key);
	if (st != PSA_SUCCESS) {
		printk("TLS-FIT error: psa_generate_key %d\n", (int)st);
		return -1;
	}

	mbedtls_pk_init(&id->pk);
	rc = mbedtls_pk_wrap_psa(&id->pk, id->key);
	if (rc != 0) {
		printk("TLS-FIT error: mbedtls_pk_wrap_psa %d\n", rc);
		return -1;
	}

	mbedtls_x509write_crt_init(&w);
	mbedtls_x509write_crt_set_version(&w, MBEDTLS_X509_CRT_VERSION_3);
	rc = mbedtls_x509write_crt_set_serial_raw(&w, &serial, 1);
	if (rc == 0) {
		rc = mbedtls_x509write_crt_set_validity(&w, "20260101000000", "20991231235959");
	}
	if (rc == 0) {
		rc = mbedtls_x509write_crt_set_subject_name(&w, name);
	}
	if (rc == 0) {
		rc = mbedtls_x509write_crt_set_issuer_name(&w, name);
	}
	mbedtls_x509write_crt_set_subject_key(&w, &id->pk);
	mbedtls_x509write_crt_set_issuer_key(&w, &id->pk);
	mbedtls_x509write_crt_set_md_alg(&w, MBEDTLS_MD_SHA256);
	int n = rc == 0 ? mbedtls_x509write_crt_der(&w, der, sizeof(der)) : rc;
	mbedtls_x509write_crt_free(&w);
	if (n <= 0) {
		printk("TLS-FIT error: certificate write %d\n", n);
		return -1;
	}

	mbedtls_x509_crt_init(&id->crt);
	rc = mbedtls_x509_crt_parse_der(&id->crt, der + sizeof(der) - n, (size_t)n);
	if (rc != 0) {
		printk("TLS-FIT error: certificate parse %d\n", rc);
		return -1;
	}
	rc = zid_of(&id->pk, id->zid);
	if (rc != 0) {
		printk("TLS-FIT error: zid of own key %d\n", rc);
		return -1;
	}
	return 0;
}

/* ── One handshake between the two, each role's time counted inside its own calls. ── */

struct peer {
	mbedtls_ssl_config conf;
	mbedtls_ssl_context ssl;
	struct end end;
	uint64_t cycles;
	bool done;
};

static int peer_setup(struct peer *p, int endpoint, struct identity *own, struct ring *out,
		      struct ring *in)
{
	int rc;

	memset(p, 0, sizeof(*p));
	mbedtls_ssl_config_init(&p->conf);
	mbedtls_ssl_init(&p->ssl);
	rc = mbedtls_ssl_config_defaults(&p->conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT);
	if (rc != 0) {
		return rc;
	}
	mbedtls_ssl_conf_min_tls_version(&p->conf, MBEDTLS_SSL_VERSION_TLS1_3);
	mbedtls_ssl_conf_max_tls_version(&p->conf, MBEDTLS_SSL_VERSION_TLS1_3);
	/* The peer must present a certificate and prove its key (CertificateVerify); the chain it
	 * reaches is not the verdict, the zid of the key is (checked after the handshake, before
	 * any application data, by `pinned`).
	 */
	mbedtls_ssl_conf_authmode(&p->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	rc = mbedtls_ssl_conf_own_cert(&p->conf, &own->crt, &own->pk);
	if (rc != 0) {
		return rc;
	}
	rc = mbedtls_ssl_setup(&p->ssl, &p->conf);
	if (rc != 0) {
		return rc;
	}
	if (endpoint == MBEDTLS_SSL_IS_CLIENT) {
		/* The identity is the zid, never a name. */
		rc = mbedtls_ssl_set_hostname(&p->ssl, NULL);
		if (rc != 0) {
			return rc;
		}
	}
	p->end.out = out;
	p->end.in = in;
	mbedtls_ssl_set_bio(&p->ssl, &p->end, pipe_send, pipe_recv, NULL);
	return 0;
}

static void peer_free(struct peer *p)
{
	mbedtls_ssl_free(&p->ssl);
	mbedtls_ssl_config_free(&p->conf);
}

static int step(struct peer *p)
{
	if (p->done) {
		return 0;
	}
	uint32_t t0 = k_cycle_get_32();
	int rc = mbedtls_ssl_handshake(&p->ssl);

	p->cycles += (uint32_t)(k_cycle_get_32() - t0);
	if (rc == 0) {
		p->done = true;
		return 0;
	}
	if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
		return 0;
	}
	return rc;
}

/* The peer certificate's key names the zid the caller expected: the D1 binding. */
static bool pinned(const mbedtls_ssl_context *ssl, const uint8_t expected[ZID_BYTES])
{
	const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(ssl);
	uint8_t zid[ZID_BYTES];

	if (peer == NULL) {
		return false;
	}
	if (zid_of((mbedtls_pk_context *)&peer->pk, zid) != 0) {
		return false;
	}
	return memcmp(zid, expected, ZID_BYTES) == 0;
}

static uint32_t us(uint64_t cycles)
{
	return (uint32_t)(cycles * 1000000ULL / sys_clock_hw_cycles_per_sec());
}

static struct identity id_client;
static struct identity id_server;
static struct peer client;
static struct peer server;

static size_t stack_used(void)
{
	size_t unused = 0;

	if (k_thread_stack_space_get(k_current_get(), &unused) != 0) {
		return 0;
	}
	return k_current_get()->stack_info.size - unused;
}

/* One round. `expect_client` is the zid the server pins; a wrong one must be refused. */
static int round_run(int n, const uint8_t expect_client[ZID_BYTES], bool must_refuse)
{
	int rc;

	memset(&to_server, 0, sizeof(to_server));
	memset(&to_client, 0, sizeof(to_client));
	mbedtls_memory_buffer_alloc_max_reset();

	rc = peer_setup(&client, MBEDTLS_SSL_IS_CLIENT, &id_client, &to_server, &to_client);
	if (rc == 0) {
		rc = peer_setup(&server, MBEDTLS_SSL_IS_SERVER, &id_server, &to_client, &to_server);
	}
	if (rc != 0) {
		printk("TLS-FIT error: setup %d\n", rc);
		return -1;
	}

	for (int turns = 0; turns < 200 && !(client.done && server.done); turns++) {
		rc = step(&client);
		if (rc == 0) {
			rc = step(&server);
		}
		if (rc != 0) {
			printk("TLS-FIT error: handshake round=%d rc=-0x%04x\n", n, (unsigned int)-rc);
			peer_free(&client);
			peer_free(&server);
			return -1;
		}
	}
	bool ok = client.done && server.done;
	bool client_pins = ok && pinned(&client.ssl, id_server.zid);
	bool server_pins = ok && pinned(&server.ssl, expect_client);

	/* Application data both ways, only once both ends accepted the other. */
	bool data_ok = false;
	if (client_pins && server_pins) {
		static const unsigned char hello[64] = "wz secure channel fit";
		unsigned char got[64];

		data_ok = mbedtls_ssl_write(&client.ssl, hello, sizeof(hello)) == sizeof(hello) &&
			  mbedtls_ssl_read(&server.ssl, got, sizeof(got)) == sizeof(got) &&
			  memcmp(got, hello, sizeof(hello)) == 0 &&
			  mbedtls_ssl_write(&server.ssl, got, sizeof(got)) == sizeof(got) &&
			  mbedtls_ssl_read(&client.ssl, got, sizeof(got)) == sizeof(got) &&
			  memcmp(got, hello, sizeof(hello)) == 0;
	}

	size_t peak = 0;
	size_t blocks = 0;
	mbedtls_memory_buffer_alloc_max_get(&peak, &blocks);

	if (must_refuse) {
		bool refused = ok && client_pins && !server_pins;
		printk("TLS-FIT pin-refusal ok=%d handshake=%d client_pins=%d server_pins=%d\n",
		       refused, ok, client_pins, server_pins);
		peer_free(&client);
		peer_free(&server);
		return refused ? 0 : -1;
	}

	printk("TLS-FIT round=%d ok=%d suite=%s hs_client_us=%u hs_server_us=%u "
	       "arena_peak=%u arena_blocks_peak=%u stack_used=%u\n",
	       n, ok && client_pins && server_pins && data_ok,
	       ok ? mbedtls_ssl_get_ciphersuite(&client.ssl) : "none", us(client.cycles),
	       us(server.cycles), (unsigned int)peak, (unsigned int)blocks,
	       (unsigned int)stack_used());
	peer_free(&client);
	peer_free(&server);
	return ok && client_pins && server_pins && data_ok ? 0 : -1;
}

int main(void)
{
	printk("TLS-FIT start: Mbed TLS PSA line, TLS 1.3 mutual, P-256, clock %u Hz\n",
	       (unsigned int)sys_clock_hw_cycles_per_sec());

	psa_status_t st = psa_crypto_init();
	if (st != PSA_SUCCESS) {
		printk("TLS-FIT error: psa_crypto_init %d\n", (int)st);
		printk("TLS-FIT done ok=0\n");
		return 0;
	}

	uint32_t t0 = k_cycle_get_32();
	if (identity_make(&id_client, "CN=wz-fit-client", 1) != 0 ||
	    identity_make(&id_server, "CN=wz-fit-server", 2) != 0) {
		printk("TLS-FIT done ok=0\n");
		return 0;
	}
	uint32_t identity_us = us((uint32_t)(k_cycle_get_32() - t0));
	size_t peak = 0;
	size_t blocks = 0;
	mbedtls_memory_buffer_alloc_max_get(&peak, &blocks);
	printk("TLS-FIT identities: two keys and self-signed certificates in %u us together, "
	       "arena_peak=%u\n",
	       identity_us, (unsigned int)peak);

	int failed = 0;
	for (int n = 1; n <= CONFIG_TLS_FIT_ROUNDS; n++) {
		failed |= round_run(n, id_client.zid, false) != 0;
	}

	uint8_t wrong[ZID_BYTES];
	memcpy(wrong, id_client.zid, ZID_BYTES);
	wrong[0] ^= 0x01;
	failed |= round_run(0, wrong, true) != 0;

	printk("TLS-FIT done ok=%d rounds=%d mbedtls_heap=%u main_stack=%u\n", !failed,
	       CONFIG_TLS_FIT_ROUNDS, (unsigned int)CONFIG_MBEDTLS_HEAP_SIZE,
	       (unsigned int)CONFIG_MAIN_STACK_SIZE);
	return 0;
}
