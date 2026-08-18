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
/* R311y854 -- the selector did not compile. Its own code and not
 * INVALID_ARG, because the two are answered by different people: an invalid
 * argument is the caller's bug, a selector is text an operator typed. */
#define WZ_DISSECT_ERR_SELECTOR (-4)

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

/* R311y748 (ABI 2) — the same summary, read under BOUNDED memory.
 *
 * wz_dissect_pcap_summary states no caps, so nothing in its
 * health.dropped_by_limits group can ever be non-zero however large the
 * capture is. This one reads under wz's live-tap preset, which is the
 * configuration whose caps bite, so a caller whose memory is finite has a
 * door — and what the bound cost is reported through that same group rather
 * than discarded quietly.
 *
 * A NAMED PRESET and not a limits struct: this ABI hands back a
 * self-describing document instead of a struct tree precisely so that the
 * next axis wz bounds is a preset edit rather than an ABI break. */
int wz_dissect_pcap_summary_bounded(const unsigned char *bytes, size_t len,
                                    char **out);

/* R311y851 (ABI 3) — the four ANALYSIS planes, which this ABI could not
 * reach at all: the keyexpr plane (which keys carry the traffic, with
 * subtree rollups and the declarations still unresolved), the node plane
 * (the capture keyed by zid, and the links where both ends named
 * themselves), the query plane (requests matched to their replies, with the
 * first-reply delay and the ones never answered), and the payload plane
 * (what the samples carry, judged against their own declaration).
 *
 * They were never missing from the library — wz-capture is this library's
 * own dependency, so all four were compiled in and had no symbol. What was
 * missing is the door, and a capability a consumer cannot call is one it
 * does not have.
 *
 * The summary above answers the TRANSPORT question and does not carry any
 * of this; ask for the one you want. Four walks of every frame is what this
 * costs, which is why it is a call and not part of the summary.
 *
 * `exchanges` and `payloads` are `null` — not an empty table — in a build
 * whose decoder cannot see the records they correlate. A plane that cannot
 * be fed is absent rather than empty, and `{"rows":[]}` would tell you this
 * capture had no queries in it. */
int wz_dissect_pcap_census(const unsigned char *bytes, size_t len, char **out);

/* R311y854 (ABI 4) — the same census, NARROWED by a selector in wz's own
 * filter language: `field op value` terms (key == robot/pose, kind == query,
 * bytes > 100, delay >= 10, ...) joined with and / or / not and parentheses.
 * The key term takes zenoh's own keyexpr wildcards; they are not spelled out
 * here because a slash followed by a star ends a C comment.
 * An EMPTY selector selects everything, so this is the identity of the call
 * above rather than a way to get nothing.
 *
 * THREE planes narrow and the NODE plane does not -- a node is not a record
 * the selector's terms describe, which is the same choice `wz-analyze
 * --select` makes. Read `narrowed_by_selector` off each plane rather than
 * inferring it from surviving rows; that inference is the one way to get
 * this wrong.
 *
 * Each narrowed plane carries `selection`: matched, rejected and UNDECIDED.
 * The third is why counts are reported beside the rows -- a keyexpr whose
 * declaration went past before the tap started cannot be judged, and without
 * it a short total reads as a whole one.
 *
 * A selector that does not compile returns WZ_DISSECT_ERR_SELECTOR and no
 * string. For the position, call wz_dissect_selector_diagnose. */
int wz_dissect_pcap_census_where(const unsigned char *bytes, size_t len,
                                 const char *selector, char **out);

/* R311y854 (ABI 4) — compile a selector and say what is wrong with it,
 * without a capture.
 *
 * Returns WZ_DISSECT_OK for any readable text and writes a JSON verdict:
 * {"ok":true}, or {"ok":false,"at":N,"message":"..."} where `at` is a BYTE
 * offset into the selector. A refused selector is a successful DIAGNOSIS,
 * not an error, which is why the memory rule is untouched: OK means a string
 * you own, an error means none.
 *
 * The useful moment to ask "is this valid, and if not where" is while the
 * expression is being typed -- before there is a capture to run it against,
 * and long before a caller would want to pay four walks of a file to find
 * out. */
int wz_dissect_selector_diagnose(const char *selector, char **out);

#ifdef __cplusplus
}
#endif

#endif /* WZ_DISSECT_H */
