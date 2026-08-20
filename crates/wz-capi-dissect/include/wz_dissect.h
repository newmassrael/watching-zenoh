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
/* R311y856 -- a payload declaration did not install. Its own code for the
 * reason SELECTOR is not INVALID_ARG: a selector and a format declaration
 * are two different texts a person writes, and a UI that could not tell
 * which box to send them back to would be answering neither. Call
 * wz_dissect_declarations_diagnose to learn which line and why. */
#define WZ_DISSECT_ERR_DECLARATION (-5)

/* R311y887 -- LIMIT PRESETS, for the doors that take one as an argument.
 *
 * An int and not a struct: a struct across this boundary would freeze wz's
 * DissectionLimits layout into the ABI, so the next axis it bounds would be a
 * break rather than an edit. An int grows by gaining VALUES, and a consumer
 * that does not know a new one simply never passes it.
 *
 * NONE is zero so a zero-initialised argument reads a file the way every door
 * here read one before presets existed. An UNKNOWN value is
 * WZ_DISSECT_ERR_INVALID_ARG and never a quiet fall back to unbounded -- a
 * caller that believes it asked for a ceiling must not be given none. */
#define WZ_DISSECT_LIMITS_NONE 0
#define WZ_DISSECT_LIMITS_LIVE_TAP 1

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

/* R311y885 (ABI 7) — the same planes, read under BOUNDED memory.
 *
 * The pairing wz_dissect_pcap_summary_bounded made for the transport
 * document, made here for the analysis one, and this is the half a live tap
 * needs: the census above reads with every cap set to none, which is right
 * for a file that ends and wrong for a link that does not. A framework
 * watching a running system could bound the document it did not need and
 * not the one it did.
 *
 * The same live-tap preset, for the same reason: a preset is an edit and a
 * limits struct across this boundary would be a break.
 *
 * The census document carries dropped_by_limits as of this revision -- the
 * same group the summary reports, from the same emitter -- so a plane made
 * short by an evicted flow says so instead of reading as a quiet network.
 * That key is present through BOTH census doors; behind this one it can be
 * non-zero.
 *
 * wz_dissect_pcap_census_where stays unbounded. Bounding a narrowed census
 * is a separate decision and is not improvised here. */
int wz_dissect_pcap_census_bounded(const unsigned char *bytes, size_t len,
                                   char **out);

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

/* R311y887 (ABI 8) -- the census with BOTH axes as arguments, and the shape
 * every read door that needs a ceiling takes from here on.
 *
 * Boundedness is orthogonal to everything else a read door varies, so a
 * `_bounded` twin per document multiplies: the summary got one, the census got
 * one, and a narrowed census under a ceiling would have been the fourth name
 * for the fourth combination. The preset is a parameter instead, so the fifth
 * combination needs no fifth name.
 *
 * An EMPTY selector selects everything, so ("", NONE) is
 * wz_dissect_pcap_census, ("", LIVE_TAP) is wz_dissect_pcap_census_bounded and
 * (expr, NONE) is wz_dissect_pcap_census_where. Those three keep their symbols
 * -- a published symbol is one somebody links -- and are not deprecated; they
 * are simply not the pattern a new combination follows.
 *
 * The document carries dropped_by_limits through every one of them, so a plane
 * made short by an evicted flow says so instead of reading as a quiet network.
 *
 * A bad selector is WZ_DISSECT_ERR_SELECTOR; an unknown preset is
 * WZ_DISSECT_ERR_INVALID_ARG. Neither hands back a string. */
int wz_dissect_pcap_census_where_limited(const unsigned char *bytes, size_t len,
                                         const char *selector, int limits,
                                         char **out);

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

/* R311y855 (ABI 5) — THE FIELD LAYER: every message in the capture,
 * dissected into the byte ranges it was decoded from.
 *
 * The summary above tells you to "walk the flows, then expand the messages
 * you want" with wz_dissect_transport_message. That walk was not possible:
 * the summary reports per-flow frame COUNTS, and a stream message's bytes
 * live in the REASSEMBLED per-direction stream, which exists only inside
 * this library -- so a caller holding the capture file cannot slice one out.
 * This call does the walk where the reassembly is and hands back the trees.
 *
 * Spans inside a tree are MESSAGE-RELATIVE. Where the message sits is on the
 * row: a stream row carries `message_at`, a byte offset into that
 * direction's retained stream, so a span added to it is a capture
 * coordinate; a datagram row carries `packet`, an INDEX, which must not be
 * added to anything. `offset_space` says which -- they are small numbers all
 * round and cannot be told apart by looking.
 *
 * Every row is a tree OR a `declined` string with the reason. The walk is
 * checked against the session that framed the message, so a coordinate that
 * does not name the message the session framed yields a refusal rather than
 * a confident tree about other bytes. Bytes a bounded read trimmed decline
 * the same way.
 *
 * max_messages_per_flow: 0 is UNBOUNDED, matching the command line's
 * default, and a capture holds an unbounded number of messages -- pass a
 * bound if you have a screen to fill. Each flow reports `shown` and
 * `omitted`, so a held-back listing is never mistaken for a capture that
 * ended. `capture_reread` reports whether the datagram half could read the
 * file a second time, which it must do to reach a datagram message's bytes. */
int wz_dissect_pcap_fields(const unsigned char *bytes, size_t len,
                           size_t max_messages_per_flow, char **out);

/* R311y856 (ABI 6) — THE FIELD LAYER WITH THE APPLICATION PAYLOADS DECODED,
 * under a mapping you declare.
 *
 * The command line has decoded payloads since R311y699 and this ABI could
 * not: the decoders lived in that binary, which this library must not depend
 * on. They moved beside the map; this is the door.
 *
 * declarations: one per line, NUL-terminated, in the spelling the command
 * line's two flags already write --
 *
 *     demo/temp=protobuf         a format rule: which decoder reads this
 *                                topic's payload
 *     demo/temp:1=temperature    a field name: protobuf's wire format
 *                                carries none, so a deployment that has a
 *                                schema declares it
 *
 * Patterns are zenoh's own keyexpr dialect, so a wildcard chunk covers a
 * subtree -- deliberately not spelled here, because that token cannot be
 * written inside a C block comment. ONE dialect for both surfaces, so a rule
 * tried in a terminal and then moved into a config file is not re-spelled.
 * An EMPTY text declares nothing, which makes this the same question
 * wz_dissect_pcap_fields answers.
 *
 * A declaration this build cannot install -- an unknown format name, a
 * pattern this build's matcher has no arm for, a line that is not a
 * declaration -- returns WZ_DISSECT_ERR_DECLARATION and no document. Not
 * skipped: a map quietly smaller than the text that built it leaves a reader
 * blaming the traffic for their own rule.
 *
 * Every walked row gains `payload_decode`, an object whose `state` is
 * `decoded`, `refused`, `encoding_mismatch`, `no_rule`, `keyexpr_unresolved`
 * or `no_payload`. The last three are ANSWERS, not omissions: a rule that
 * never fired and a rule that fired and found nothing send you to opposite
 * places, and `keyexpr_unresolved` is the ordinary shape of a capture that
 * began after the declarations went past. A decoded field's start/end are in
 * the MESSAGE's coordinate space, like every other span on the row.
 *
 * R311y873 -- `encoding_mismatch` is the sample's OWN declared encoding
 * disagreeing with the rule, and it carries `declared` rather than `why`.
 * Told apart from `refused` because the two send you to opposite places:
 * that one says the bytes are not this format, this one says the bytes are
 * exactly what their publisher said and the MAPPING is wrong. Folding the
 * two would send an operator to a wire with nothing to answer for.
 *
 * R311y874 -- a `decoded` block additionally carries `despite_encoding`: the
 * name the publisher declared when the rule was applied OVER that
 * declaration, and `null` on an ordinary decode. It is non-null exactly
 * where the publisher's own bytes refute its own label -- your rule was
 * right and the topic is mislabelled -- because a declaration this reader
 * can prove false must not veto the rule. Always present, never omitted: a
 * consumer that had to test for the key would read its absence as "nothing
 * was overridden", which is the assumption the field exists to stop.
 *
 * R311y875 -- the document additionally carries `payload_mapping`, a
 * top-level array summarising what your rules MET. Both findings above are
 * per message, and a capture where one mapping is wrong for every sample on a
 * topic reports it once per row -- in the listing you bound because it is
 * that long. Each entry is one (`keyexpr`, `format`, `declared`) triple with
 * `samples`, and `wrong` says which side to go fix:
 *
 *     `rule`         the publisher declared an encoding your decoder is not
 *                    for AND its bytes bear that out, so nothing was decoded
 *                    and your rule is what is wrong
 *     `publisher`    its declaration contradicts your rule and its own bytes
 *                    refute the declaration, so the rule won, the fields are
 *                    good, and the topic is mislabelled
 *
 * `note` carries the same sentence the command line prints, so a consumer
 * that only forwards findings does not have to compose one. Always present,
 * empty array when nothing is misbound -- the same rule despite_encoding
 * follows, for the same reason. The tally counts the messages this listing
 * WALKED, so a bound you passed bounds it too; each flow's `omitted` is what
 * makes that legible. The SET is complete for what was walked. */
int wz_dissect_pcap_fields_with_payloads(const unsigned char *bytes, size_t len,
                                         size_t max_messages_per_flow,
                                         const char *declarations, char **out);

/* R311y856 (ABI 6) — compile a declaration text and say what is wrong with
 * it, WITHOUT a capture.
 *
 * Always returns WZ_DISSECT_OK for readable text and writes a verdict:
 * {"ok":true,"installed":N}, or
 * {"ok":false,"line":N,"text":"...","message":"..."} where `line` counts
 * every line of the text from 0 -- blank ones included, so the number
 * indexes what you sent.
 *
 * The argument wz_dissect_selector_diagnose makes, arriving for the second
 * text a person types. A consumer told only "one of these is bad" makes the
 * operator bisect their own configuration. */
int wz_dissect_declarations_diagnose(const char *declarations, char **out);

#ifdef __cplusplus
}
#endif

#endif /* WZ_DISSECT_H */
