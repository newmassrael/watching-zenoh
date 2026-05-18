/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial */
/* SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael */
/*
 * Bindgen umbrella header for zenoh-pico-sys.
 *
 * Pulls in the zenoh-pico public surface (`zenoh-pico.h`) PLUS the
 * internal headers that expose the `_z_*` prefixed wire-codec
 * encode/decode functions + wbuf/zbuf primitives that Layer 3
 * byte-compare tests consume. The internal prefix indicates an
 * unstable ABI surface relative to zenoh-pico's public `z_*`
 * functions; this is by design — the watching-zenoh project is a
 * codec-level replacement, so we test against the internal codec
 * boundary, not the public application API.
 *
 * Allowlist policy (build.rs) still applies — this header is the
 * SUPERSET that bindgen can see; the allowlist narrows to exactly
 * the symbols each Layer 3 test round adds.
 */

#ifndef WZ_ZENOH_PICO_SYS_WRAPPER_H
#define WZ_ZENOH_PICO_SYS_WRAPPER_H

#include "zenoh-pico.h"

/* Internal headers for codec-layer byte-compare tests.
 *
 * - protocol/codec/transport.h: _z_*_encode for Init/Open/Close/Join/
 *   KeepAlive/Frame/Fragment + scouting envelope/transport envelope.
 * - protocol/codec/message.c siblings via message.h: _z_*_encode for
 *   Scout/Hello and the inner-MID body codecs (Put/Del/Query/Reply/
 *   Err/Timestamp/Encoding/...).
 * - protocol/iobuf.h: _z_wbuf_t / _z_zbuf_t + _z_wbuf_make /
 *   _z_wbuf_to_zbuf / _z_zbuf_get_rptr — the bytes-extraction path
 *   that lets Layer 3 read what the encoder wrote.
 */
#include "zenoh-pico/protocol/iobuf.h"
#include "zenoh-pico/protocol/codec/transport.h"
#include "zenoh-pico/protocol/codec/message.h"
#include "zenoh-pico/protocol/codec/network.h"
#include "zenoh-pico/protocol/codec/ext.h"
#include "zenoh-pico/protocol/ext.h"

/* Forward declarations for body-codec functions that have C-side
 * implementations in src/protocol/codec/message.c but no header
 * declaration (they are wrapped behind the public
 * `_z_scouting_message_encode` dispatcher in the upstream API).
 *
 * For Layer 3 byte-compare tests we need the body codec's output
 * directly (without the dispatcher's MID byte prefix), so we declare
 * the symbols here. The corresponding object code is already in
 * libzenohpico.a — declaring them here only changes the visibility
 * to bindgen + the rust linker, not the C-side build.
 */
#include "zenoh-pico/protocol/definitions/transport.h"  /* _z_s_msg_scout_t, _z_s_msg_hello_t */
z_result_t _z_scout_encode(_z_wbuf_t *wbf, uint8_t header, const _z_s_msg_scout_t *msg);
z_result_t _z_hello_encode(_z_wbuf_t *wbf, uint8_t header, const _z_s_msg_hello_t *msg);

#endif /* WZ_ZENOH_PICO_SYS_WRAPPER_H */
