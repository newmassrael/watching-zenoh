/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The secure channel of decision D9 (docs/session-lifecycle-intent.md) over Mbed TLS, as the
 * few calls the Rust side of `wz-tls-mbedtls` makes. Every Mbed TLS structure stays on this side:
 * the Rust side holds pointers to objects this file allocates from the one static arena Mbed TLS
 * serves, so no structure's layout crosses the boundary and an object never moves once made.
 *
 * Errors are negative and are Mbed TLS's or PSA's own codes, passed through, or WZ_TLS_E_*.
 * Single-threaded by contract: the profile this serves runs one thread.
 */

#ifndef WZ_TLS_H
#define WZ_TLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The length of a zid derived from a key (decision D1). */
#define WZ_TLS_ZID_BYTES 16

/** A call that wants more bytes from the transport before it can go on. Negative, so a byte
 * count is never read as it, and outside every Mbed TLS and PSA code. */
#define WZ_TLS_WANT_READ (-0x10010)
/** A call that wants the transport to take bytes before it can go on. */
#define WZ_TLS_WANT_WRITE (-0x10011)

/** The transport failed; the Rust side holds its reason. */
#define WZ_TLS_E_TRANSPORT (-0x10001)
/** The peer completed the handshake without presenting a certificate. */
#define WZ_TLS_E_NO_PEER_CERT (-0x10002)
/** The library was already started, or not yet. */
#define WZ_TLS_E_STATE (-0x10003)

/** What the transport callbacks return besides a byte count. */
#define WZ_TLS_IO_WOULD_BLOCK (-1)
#define WZ_TLS_IO_FAILED (-2)

/**
 * The byte stream a session runs over. `send` takes up to `len` bytes and returns how many it
 * took, `recv` returns how many it read (0: the peer ended the stream); either returns
 * WZ_TLS_IO_WOULD_BLOCK or WZ_TLS_IO_FAILED instead.
 */
struct wz_tls_io {
	void *ctx;
	int (*send)(void *ctx, const unsigned char *buf, size_t len);
	int (*recv)(void *ctx, unsigned char *buf, size_t len);
};

/** Serve every Mbed TLS allocation from `arena`, then start PSA Crypto. Once per program. */
int wz_tls_start(unsigned char *arena, size_t len);

/** The arena's peak use since the last reset, in bytes and blocks; -1 when not measured. */
int wz_tls_arena_peak(size_t *bytes, size_t *blocks);

/** Reset the arena's peak to its current use. */
void wz_tls_arena_peak_reset(void);

struct wz_tls_identity;

/**
 * A new identity: a P-256 key generated in the PSA key store, a certificate self-signed over it
 * whose subject and issuer are `subject` (an X.509 name, "CN=..."), and the zid the key names.
 */
int wz_tls_identity_generate(struct wz_tls_identity **out, const char *subject);

/** The identity's zid. */
void wz_tls_identity_zid(const struct wz_tls_identity *id, uint8_t zid[WZ_TLS_ZID_BYTES]);

/** The identity's certificate, DER, valid for as long as the identity. */
void wz_tls_identity_cert(const struct wz_tls_identity *id, const uint8_t **der, size_t *len);

/** Destroy the key and free the identity. No session may still use it. */
void wz_tls_identity_free(struct wz_tls_identity *id);

/** The two ends of a handshake. */
#define WZ_TLS_CLIENT 0
#define WZ_TLS_SERVER 1

struct wz_tls_session;

/**
 * A session of `role` presenting `own`, over `io` (copied: the session keeps its own). Mutual:
 * each end must present a certificate and prove its key; no chain is the verdict, the zid of the
 * key is, and the caller reads it once the handshake is done.
 */
int wz_tls_session_open(struct wz_tls_session **out, int role, const struct wz_tls_identity *own,
			const struct wz_tls_io *io);

/** Point the session at `io`'s context for the calls that follow. */
void wz_tls_session_set_io_ctx(struct wz_tls_session *s, void *ctx);

/** Advance the handshake: 0 when done, WZ_TLS_WANT_READ/WRITE to call again, or an error. */
int wz_tls_session_handshake(struct wz_tls_session *s);

/** The zid of the key the peer's certificate carries, once the handshake is done. */
int wz_tls_session_peer_zid(const struct wz_tls_session *s, uint8_t zid[WZ_TLS_ZID_BYTES]);

/** The negotiated cipher suite's name, or NULL before the handshake is done. */
const char *wz_tls_session_suite(const struct wz_tls_session *s);

/** Protect and send up to `len` bytes: how many were taken, WZ_TLS_WANT_WRITE, or an error. */
int wz_tls_session_write(struct wz_tls_session *s, const unsigned char *buf, size_t len);

/**
 * Read up to `len` bytes of application data: how many, 0 when the peer ended the session
 * (close_notify or the end of the stream), WZ_TLS_WANT_READ, or an error.
 */
int wz_tls_session_read(struct wz_tls_session *s, unsigned char *buf, size_t len);

/** Whether bytes are held inside the session that a read would return without the transport. */
int wz_tls_session_pending(const struct wz_tls_session *s);

/** Tell the peer the session ends (close_notify); best effort. */
void wz_tls_session_close_notify(struct wz_tls_session *s);

/** Free the session. */
void wz_tls_session_free(struct wz_tls_session *s);

#ifdef __cplusplus
}
#endif

#endif /* WZ_TLS_H */
