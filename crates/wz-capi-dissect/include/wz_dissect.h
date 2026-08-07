/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * R311y586 (A7) — the C ABI over wz's dissection surface.
 *
 * MEMORY RULE, and it is the whole contract: every char* this library
 * returns is owned by this library. Release it with wz_dissect_string_free.
 * Nothing else crosses the boundary allocated, no callbacks run, and no
 * handle outlives the call that made it.
 *
 * THE JSON SHAPE IS NOT FROZEN. Field names are wz's walker names and may
 * gain siblings as walkers are added. Read by name and tolerate unknown
 * keys — that forward-compatibility is the reason this ABI hands back a
 * self-describing document instead of a struct tree. wz_dissect_abi_version
 * moves when a SYMBOL or the memory rule changes, never when the JSON gains
 * fields.
 */
#ifndef WZ_DISSECT_H
#define WZ_DISSECT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WZ_DISSECT_OK 0
#define WZ_DISSECT_ERR_INVALID_ARG (-1)
#define WZ_DISSECT_ERR_BAD_CAPTURE (-2)
#define WZ_DISSECT_ERR_DECODE (-3)

/* Symbol/memory-contract revision. Not a JSON-shape revision. */
int wz_dissect_abi_version(void);

/* Release a string this library returned. Null is a no-op. */
void wz_dissect_string_free(char *s);

/* Dissect ONE transport message. `base` is the coordinate spans are
 * reported in: pass the message's offset within a capture for capture
 * offsets, or 0 for message-relative ones. */
int wz_dissect_transport_message(const unsigned char *bytes, size_t len,
                                 size_t base, char **out);

/* Dissect a classic pcap file held in memory, returning a per-flow SUMMARY.
 * Deliberately a summary: a capture holds an unbounded number of messages
 * and one string carrying all of them is a shape that works for a test and
 * fails for a session. Walk the flows, then expand the messages you want
 * with wz_dissect_transport_message. */
int wz_dissect_pcap_summary(const unsigned char *bytes, size_t len, char **out);

#ifdef __cplusplus
}
#endif

#endif /* WZ_DISSECT_H */
