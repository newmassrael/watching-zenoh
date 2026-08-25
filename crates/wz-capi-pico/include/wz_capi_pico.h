/*
 * SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * wz_capi_pico.h — §5.27 api-compat-pico, Round 1 C ABI.
 *
 * A zenoh-pico-compatible C surface exported by the wz `wz-capi-pico` cdylib.
 * A C program compiled against this header and linked against libwz_capi_pico
 * gets a wz AP (Linux + tokio) session behind the familiar `z_*` / `zp_*`
 * names.
 *
 * This header is a clean-room reproduction of the zenoh-pico ABI layout
 * contract for the types Round 1 exercises (an ABI is not copyrightable
 * expression); it does NOT vendor any zenoh-pico header. The owned struct
 * SIZES match zenoh-pico (LP64) for session / config / bytes / slice / string
 * / closure_sample / view_keyexpr; publisher / subscriber use a handle model
 * whose exact `Z_FEATURE`-dependent size-match is a follow-up audit.
 *
 * Round 1 surface: config, session open/close, keyexpr view, bytes/slice/
 * string, publisher, session-put, subscriber + sample closure. Follow-up
 * rounds add get/queryable, liveliness, scouting, attachments, and encoding
 * detail.
 */

#ifndef WZ_CAPI_PICO_H
#define WZ_CAPI_PICO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* z_clock_t is `struct timespec` on every Unix, as it is in zenoh-pico. */
#include <time.h>

typedef struct timespec z_clock_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ result */

/* zenoh-pico `z_result_t` == int8_t. */
typedef int8_t z_result_t;

#define Z_OK ((z_result_t)0)
#define Z_ERR_GENERIC ((z_result_t)-128)
#define Z_ERR_NULL ((z_result_t)-127)
#define Z_ERR_INVALID ((z_result_t)-1)

/* --------------------------------------------------------------- config keys */

#define Z_CONFIG_MODE_KEY ((uint8_t)0x40)
#define Z_CONFIG_CONNECT_KEY ((uint8_t)0x41)
#define Z_CONFIG_LISTEN_KEY ((uint8_t)0x42)

/* ------------------------------------------------------------------- session */
/* Owned session == pico refcount `{ void* _val; void* _cnt }` (16 B). The wz
 * session handle lives in `_val`. */
typedef struct { void *_val; void *_cnt; } z_owned_session_t;
typedef struct { void *_val; void *_cnt; } z_loaned_session_t;
typedef struct { z_owned_session_t _this; } z_moved_session_t;

/* -------------------------------------------------------------------- config */
typedef struct { void *handle; void *_pad[3]; } z_owned_config_t;  /* 32 B */
typedef struct { void *handle; void *_pad[3]; } z_loaned_config_t;
typedef struct { z_owned_config_t _this; } z_moved_config_t;

/* --------------------------------------------------------------------- bytes */
typedef struct { void *handle; void *_pad[3]; } z_owned_bytes_t;   /* 32 B */
typedef struct { void *handle; void *_pad[3]; } z_loaned_bytes_t;
typedef struct { z_owned_bytes_t _this; } z_moved_bytes_t;

/* --------------------------------------------------------------------- slice */
typedef struct { void *handle; void *_pad[3]; } z_owned_slice_t;   /* 32 B */
typedef struct { void *handle; void *_pad[3]; } z_loaned_slice_t;
typedef struct { z_owned_slice_t _this; } z_moved_slice_t;

/* -------------------------------------------------------------------- string */
/* Owned string owns a heap buffer behind `handle`; the loaned form is a
 * borrowed `{ start, len }` view. */
typedef struct { void *handle; void *_pad[3]; } z_owned_string_t;  /* 32 B */
typedef struct { const uint8_t *_start; size_t _len; } z_loaned_string_t;
typedef struct { z_owned_string_t _this; } z_moved_string_t;
typedef struct { const uint8_t *_start; size_t _len; size_t _pad[2]; } z_view_string_t;

/* ------------------------------------------------------------------- keyexpr */
/* A keyexpr view aliases the caller's NUL-terminated string (borrowed
 * `{ start, len }`); the caller keeps that string alive for the view. A
 * DECLARED keyexpr (z_declare_keyexpr) instead OWNS its literal and adds the
 * wire alias id. Both loan to z_loaned_keyexpr_t, which is why the literal
 * stays at slots 0/1 in each: _handle and _mapping are zero for a view, and
 * _mapping == 0 means "not declared" (0 is reserved on the wire). */
typedef struct {
    const uint8_t *_start; size_t _len; void *_handle; size_t _mapping;
} z_loaned_keyexpr_t;
typedef struct { const uint8_t *_start; size_t _len; size_t _pad[4]; } z_view_keyexpr_t; /* 48 B */
typedef struct {
    const uint8_t *_start; size_t _len; void *_handle; size_t _mapping; size_t _pad[2];
} z_owned_keyexpr_t; /* 48 B */
typedef struct { z_owned_keyexpr_t _this; } z_moved_keyexpr_t;

/* -------------------------------------------------------------------- sample */
/* Opaque: the callback only borrows it (valid during the call) and passes it
 * back to the sample accessors. */
typedef struct z_loaned_sample_t z_loaned_sample_t;

/* ---------------------------------------------------------- sample closure */
typedef void (*z_closure_sample_callback_t)(const z_loaned_sample_t *sample, void *context);
typedef void (*z_closure_drop_callback_t)(void *context);

/* Owned closure == pico `{ void* context; call; drop }` (24 B). */
typedef struct {
    void *context;
    z_closure_sample_callback_t call;
    z_closure_drop_callback_t drop;
} z_owned_closure_sample_t;
typedef struct {
    void *context;
    z_closure_sample_callback_t call;
    z_closure_drop_callback_t drop;
} z_loaned_closure_sample_t;
typedef struct { z_owned_closure_sample_t _this; } z_moved_closure_sample_t;

/* ----------------------------------------------------------------- publisher */
typedef struct { void *handle; void *_pad[3]; } z_owned_publisher_t;
typedef struct { void *handle; void *_pad[3]; } z_loaned_publisher_t;
typedef struct { z_owned_publisher_t _this; } z_moved_publisher_t;

/* ---------------------------------------------------------------- subscriber */
typedef struct { void *handle; void *_pad[3]; } z_owned_subscriber_t;
typedef struct { void *handle; void *_pad[3]; } z_loaned_subscriber_t;
typedef struct { z_owned_subscriber_t _this; } z_moved_subscriber_t;

/* ====================================================================== API */

/* --- config --- */
z_result_t z_config_default(z_owned_config_t *config);
z_result_t zp_config_insert(z_loaned_config_t *config, uint8_t key, const char *value);
z_result_t z_config_clone(z_owned_config_t *dst, const z_loaned_config_t *src);
void z_internal_config_null(z_owned_config_t *obj);
bool z_internal_config_check(const z_owned_config_t *obj);
const z_loaned_config_t *z_config_loan(const z_owned_config_t *obj);
z_loaned_config_t *z_config_loan_mut(z_owned_config_t *obj);
z_moved_config_t *z_config_move(z_owned_config_t *obj);
void z_config_take(z_owned_config_t *dst, z_moved_config_t *src);
void z_config_drop(z_moved_config_t *obj);
z_result_t z_config_take_from_loaned(z_owned_config_t *dst, z_loaned_config_t *src);

/* --- session (options accepted for ABI compat; ignored in Round 1) --- */
z_result_t z_open(z_owned_session_t *zs, z_moved_config_t *config, const void *options);
z_result_t z_close(z_loaned_session_t *zs, const void *options);
z_result_t zp_start_read_task(z_loaned_session_t *zs, const void *options);
z_result_t zp_stop_read_task(z_loaned_session_t *zs);
z_result_t zp_start_lease_task(z_loaned_session_t *zs, const void *options);
z_result_t zp_stop_lease_task(z_loaned_session_t *zs);
void z_internal_session_null(z_owned_session_t *obj);
bool z_internal_session_check(const z_owned_session_t *obj);
const z_loaned_session_t *z_session_loan(const z_owned_session_t *obj);
z_loaned_session_t *z_session_loan_mut(z_owned_session_t *obj);
z_moved_session_t *z_session_move(z_owned_session_t *obj);
void z_session_take(z_owned_session_t *dst, z_moved_session_t *src);
void z_session_drop(z_moved_session_t *obj);

/* --- keyexpr --- */
z_result_t z_view_keyexpr_from_str(z_view_keyexpr_t *keyexpr, const char *name);
bool z_view_keyexpr_is_empty(const z_view_keyexpr_t *keyexpr);
const z_loaned_keyexpr_t *z_view_keyexpr_loan(const z_view_keyexpr_t *keyexpr);
z_loaned_keyexpr_t *z_view_keyexpr_loan_mut(z_view_keyexpr_t *keyexpr);
void z_view_keyexpr_empty(z_view_keyexpr_t *keyexpr);
z_result_t z_keyexpr_as_view_string(const z_loaned_keyexpr_t *keyexpr, z_view_string_t *string);
const z_loaned_string_t *z_view_string_loan(const z_view_string_t *string);

/* declared keyexpr: binds the keyexpr to a numeric alias on every peer, so a
   later z_put on the DECLARED value emits the id instead of the literal.
   z_keyexpr_drop frees the local value only — retraction is z_undeclare_keyexpr,
   which is pico's split too (drop takes no session). */
z_result_t z_declare_keyexpr(const z_loaned_session_t *zs, z_owned_keyexpr_t *declared_keyexpr,
                             const z_loaned_keyexpr_t *keyexpr);
z_result_t z_undeclare_keyexpr(const z_loaned_session_t *zs, z_moved_keyexpr_t *keyexpr);
void z_internal_keyexpr_null(z_owned_keyexpr_t *obj);
bool z_internal_keyexpr_check(const z_owned_keyexpr_t *obj);
const z_loaned_keyexpr_t *z_keyexpr_loan(const z_owned_keyexpr_t *obj);
z_loaned_keyexpr_t *z_keyexpr_loan_mut(z_owned_keyexpr_t *obj);
z_moved_keyexpr_t *z_keyexpr_move(z_owned_keyexpr_t *obj);
void z_keyexpr_take(z_owned_keyexpr_t *dst, z_moved_keyexpr_t *src);
void z_keyexpr_drop(z_moved_keyexpr_t *obj);

/* --- liveliness (presence plane) --- */
/* A token going out of scope RETRACTS it: z_liveliness_token_drop notifies
   subscribers, matching pico, whose z_liveliness.c never calls the explicit
   undeclare. A liveliness subscriber's callback is an ordinary sample closure:
   a token appearing is Z_SAMPLE_KIND_PUT with an EMPTY payload, one going away
   is Z_SAMPLE_KIND_DELETE. */
typedef struct { uint8_t __dummy; } z_liveliness_token_options_t;
typedef struct { bool history; } z_liveliness_subscriber_options_t;
typedef struct { void *_handle; void *_pad[2]; } z_owned_liveliness_token_t;  /* 24 B */
typedef struct { void *_handle; void *_pad[2]; } z_loaned_liveliness_token_t;
typedef struct { z_owned_liveliness_token_t _this; } z_moved_liveliness_token_t;

z_result_t z_liveliness_token_options_default(z_liveliness_token_options_t *options);
z_result_t z_liveliness_subscriber_options_default(z_liveliness_subscriber_options_t *options);
z_result_t z_liveliness_declare_token(const z_loaned_session_t *zs, z_owned_liveliness_token_t *token,
                                      const z_loaned_keyexpr_t *keyexpr,
                                      const z_liveliness_token_options_t *options);
z_result_t z_liveliness_undeclare_token(z_moved_liveliness_token_t *token);
void z_internal_liveliness_token_null(z_owned_liveliness_token_t *obj);
bool z_internal_liveliness_token_check(const z_owned_liveliness_token_t *obj);
const z_loaned_liveliness_token_t *z_liveliness_token_loan(const z_owned_liveliness_token_t *obj);
z_loaned_liveliness_token_t *z_liveliness_token_loan_mut(z_owned_liveliness_token_t *obj);
z_moved_liveliness_token_t *z_liveliness_token_move(z_owned_liveliness_token_t *obj);
void z_liveliness_token_take(z_owned_liveliness_token_t *dst, z_moved_liveliness_token_t *src);
void z_liveliness_token_drop(z_moved_liveliness_token_t *obj);
z_result_t z_liveliness_declare_subscriber(const z_loaned_session_t *zs, z_owned_subscriber_t *sub,
                                           const z_loaned_keyexpr_t *keyexpr,
                                           z_moved_closure_sample_t *callback,
                                           z_liveliness_subscriber_options_t *options);

/* --- platform (libc shims pico programs reach for) --- */
void *z_malloc(size_t size);
void z_free(void *ptr);
z_result_t z_sleep_us(size_t time);
z_result_t z_sleep_ms(size_t time);
z_result_t z_sleep_s(size_t time);
z_clock_t z_clock_now(void);
unsigned long z_clock_elapsed_us(z_clock_t *instant);
unsigned long z_clock_elapsed_ms(z_clock_t *instant);
unsigned long z_clock_elapsed_s(z_clock_t *instant);
z_result_t z_bytes_from_buf(z_owned_bytes_t *bytes, uint8_t *data, size_t len,
                            void (*deleter)(void *data, void *context), void *context);
z_result_t z_bytes_from_static_buf(z_owned_bytes_t *bytes, const uint8_t *data, size_t len);
void z_view_keyexpr_from_str_unchecked(z_view_keyexpr_t *keyexpr, const char *name);
z_result_t z_declare_background_subscriber(const z_loaned_session_t *zs, const z_loaned_keyexpr_t *keyexpr,
                                           z_moved_closure_sample_t *callback, const void *options);

/* --- bytes / slice / string --- */
z_result_t z_bytes_copy_from_buf(z_owned_bytes_t *bytes, const uint8_t *data, size_t len);
z_result_t z_bytes_copy_from_str(z_owned_bytes_t *bytes, const char *value);
/* wz COPIES where pico ALIASES — see the Rust docstring; the C signature and
   ownership contract are identical, so a pico program cannot tell them apart
   except by the allocation cost. */
z_result_t z_bytes_from_static_str(z_owned_bytes_t *bytes, const char *value);
z_result_t z_bytes_to_slice(const z_loaned_bytes_t *bytes, z_owned_slice_t *dst);
z_result_t z_bytes_to_string(const z_loaned_bytes_t *bytes, z_owned_string_t *dst);
z_result_t z_bytes_clone(z_owned_bytes_t *dst, const z_loaned_bytes_t *src);
void z_internal_bytes_null(z_owned_bytes_t *obj);
bool z_internal_bytes_check(const z_owned_bytes_t *obj);
const z_loaned_bytes_t *z_bytes_loan(const z_owned_bytes_t *obj);
z_loaned_bytes_t *z_bytes_loan_mut(z_owned_bytes_t *obj);
z_moved_bytes_t *z_bytes_move(z_owned_bytes_t *obj);
void z_bytes_take(z_owned_bytes_t *dst, z_moved_bytes_t *src);
void z_bytes_drop(z_moved_bytes_t *obj);
z_result_t z_bytes_take_from_loaned(z_owned_bytes_t *dst, z_loaned_bytes_t *src);

const uint8_t *z_slice_data(const z_loaned_slice_t *slice);
size_t z_slice_len(const z_loaned_slice_t *slice);
z_result_t z_slice_clone(z_owned_slice_t *dst, const z_loaned_slice_t *src);
void z_internal_slice_null(z_owned_slice_t *obj);
bool z_internal_slice_check(const z_owned_slice_t *obj);
const z_loaned_slice_t *z_slice_loan(const z_owned_slice_t *obj);
z_loaned_slice_t *z_slice_loan_mut(z_owned_slice_t *obj);
z_moved_slice_t *z_slice_move(z_owned_slice_t *obj);
void z_slice_take(z_owned_slice_t *dst, z_moved_slice_t *src);
void z_slice_drop(z_moved_slice_t *obj);
z_result_t z_slice_take_from_loaned(z_owned_slice_t *dst, z_loaned_slice_t *src);

const char *z_string_data(const z_loaned_string_t *string);
size_t z_string_len(const z_loaned_string_t *string);
z_result_t z_string_clone(z_owned_string_t *dst, const z_loaned_string_t *src);
void z_internal_string_null(z_owned_string_t *obj);
bool z_internal_string_check(const z_owned_string_t *obj);
const z_loaned_string_t *z_string_loan(const z_owned_string_t *obj);
z_loaned_string_t *z_string_loan_mut(z_owned_string_t *obj);
z_moved_string_t *z_string_move(z_owned_string_t *obj);
void z_string_take(z_owned_string_t *dst, z_moved_string_t *src);
void z_string_drop(z_moved_string_t *obj);
z_result_t z_string_take_from_loaned(z_owned_string_t *dst, z_loaned_string_t *src);

/* --- publisher --- */
z_result_t z_declare_publisher(const z_loaned_session_t *zs, z_owned_publisher_t *publisher,
                               const z_loaned_keyexpr_t *keyexpr, const void *options);
z_result_t z_publisher_put(const z_loaned_publisher_t *publisher, z_moved_bytes_t *payload,
                           const void *options);
z_result_t z_undeclare_publisher(z_moved_publisher_t *publisher);
void z_internal_publisher_null(z_owned_publisher_t *obj);
bool z_internal_publisher_check(const z_owned_publisher_t *obj);
const z_loaned_publisher_t *z_publisher_loan(const z_owned_publisher_t *obj);
z_loaned_publisher_t *z_publisher_loan_mut(z_owned_publisher_t *obj);
z_moved_publisher_t *z_publisher_move(z_owned_publisher_t *obj);
void z_publisher_take(z_owned_publisher_t *dst, z_moved_publisher_t *src);
void z_publisher_drop(z_moved_publisher_t *obj);

/* --- session put --- */
z_result_t z_put(const z_loaned_session_t *zs, const z_loaned_keyexpr_t *keyexpr,
                 z_moved_bytes_t *payload, const void *options);

/* --- sample closure --- */
z_result_t z_closure_sample(z_owned_closure_sample_t *closure, z_closure_sample_callback_t call,
                            z_closure_drop_callback_t drop, void *context);
void z_internal_closure_sample_null(z_owned_closure_sample_t *closure);
bool z_internal_closure_sample_check(const z_owned_closure_sample_t *closure);
const z_loaned_closure_sample_t *z_closure_sample_loan(const z_owned_closure_sample_t *closure);
z_moved_closure_sample_t *z_closure_sample_move(z_owned_closure_sample_t *closure);
void z_closure_sample_take(z_owned_closure_sample_t *dst, z_moved_closure_sample_t *src);
void z_closure_sample_drop(z_moved_closure_sample_t *closure);

/* --- subscriber --- */
z_result_t z_declare_subscriber(const z_loaned_session_t *zs, z_owned_subscriber_t *subscriber,
                                const z_loaned_keyexpr_t *keyexpr,
                                z_moved_closure_sample_t *callback, const void *options);
z_result_t z_undeclare_subscriber(z_moved_subscriber_t *subscriber);
void z_internal_subscriber_null(z_owned_subscriber_t *obj);
bool z_internal_subscriber_check(const z_owned_subscriber_t *obj);
const z_loaned_subscriber_t *z_subscriber_loan(const z_owned_subscriber_t *obj);
z_loaned_subscriber_t *z_subscriber_loan_mut(z_owned_subscriber_t *obj);
z_moved_subscriber_t *z_subscriber_move(z_owned_subscriber_t *obj);
void z_subscriber_take(z_owned_subscriber_t *dst, z_moved_subscriber_t *src);
void z_subscriber_drop(z_moved_subscriber_t *obj);

/* --- sample accessors --- */
const z_loaned_keyexpr_t *z_sample_keyexpr(const z_loaned_sample_t *sample);
const z_loaned_bytes_t *z_sample_payload(const z_loaned_sample_t *sample);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WZ_CAPI_PICO_H */
