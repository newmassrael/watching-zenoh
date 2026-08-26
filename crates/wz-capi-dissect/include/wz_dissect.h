/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * R311y586 (A7) — the C ABI over wz's dissection surface.
 *
 * MEMORY RULE, and it is the whole contract: every char* this library
 * returns is owned by this library. Release it with wz_dissect_string_free.
 * Nothing else crosses the boundary allocated, no callbacks run, and no
 * handle outlives the call that made it.
 *
 * R2102 (ABI 11) REVISED THAT LAST CLAUSE, and this paragraph is the
 * revision rather than a note beside it. It used to be true without
 * exception; there is now exactly ONE exception and it is named:
 *
 *   - every char* is still owned by this library and still released with
 *     wz_dissect_string_free;
 *   - NO CALLBACKS RUN. Unchanged, and the live door below is built to keep
 *     it: records are written into a buffer YOU own and sized
 *     (wz_dissect_live_drain), never handed to a function pointer of yours
 *     that this library would call. A callback is a piece of your control
 *     flow executing inside this library, on a stack it owns, and that is
 *     what this ABI declines to admit;
 *   - ONE KIND OF HANDLE OUTLIVES ITS CALL: the opaque wz_dissect_live made
 *     by wz_dissect_live_open and released, exactly once, by
 *     wz_dissect_live_close. It is not thread-safe. Use one handle from one
 *     thread at a time, and open a handle per tap rather than sharing one.
 *
 * WHY IT COULD NOT STAY: a live tap is a dissection kept alive between
 * packets. A door that could not keep one would re-read the whole link on
 * every call, which is not a tap, it is a file read repeated. Widening the
 * sentence quietly was never available -- the clause is load-bearing, and
 * the callback half of it is the ground a previously proposed
 * callback-registration door was refused on. So the rule is restated here,
 * and wz_dissect_abi_version moves for the memory rule exactly as it moves
 * for a symbol.
 *
 * THE LIVE RECORDS ARE BINARY, alone among this library's outputs. That is
 * not a retreat from the self-describing-document design below: these
 * records carry no walker output. They are the fixed scalars that say a
 * message arrived -- when, on which flow, which way, how long, what kind --
 * and a live tap renders them at line rate, where a JSON round trip per
 * message is work proportional to the traffic for eight fields. A consumer
 * wanting the field TREE of one message still asks for it by name.
 *
 * THE JSON SHAPE IS NOT FROZEN. Field names are wz's walker names and may
 * gain siblings as walkers are added. Read by name and tolerate unknown
 * keys — that forward-compatibility is the reason this ABI hands back a
 * self-describing document instead of a struct tree. wz_dissect_abi_version
 * moves when a SYMBOL or the memory rule changes, never when the JSON gains
 * fields.
 *
 * EVERY DOCUMENT SAYS ITS OWN REVISION, and that is a different number from
 * the one above. Each one OPENS with
 *
 *     {"document":{"name":"census","revision":1}, ...}
 *
 * so a consumer reads it before parsing the body. The names are "census",
 * "fields", "summary", "readable_surfaces", "selector_diagnose" and
 * "declarations_diagnose" — one per door group, because a consumer calls the
 * door it wants and a single library-wide number would tell a reader of the
 * census that a document it never calls had moved.
 *
 * WHY IT EXISTS: reading by name is safe against ADDED keys and is not safe
 * against a key that is RENAMED or REMOVED, and wz_dissect_abi_version is
 * defined not to move for either. The document revision is the number that
 * does. A key never leaves without the revision before it having emitted it
 * alongside its replacement, so a consumer pinned to a revision always has one
 * revision's notice: read the revision, and refuse — or re-check — a value you
 * were not written against.
 *
 * R2119 — THE FIRST RENAME TO USE THAT NOTICE, so the paragraph above is now
 * a description of something that happened rather than a promise. At census
 * REVISION 2 the node rows carried two keys for one value:
 *
 *     "offset_space":"stream_byte","first_anchor":43,"first_packet":43
 *
 * `first_packet` was the old name and it was WRONG on a stream link, where
 * the value is a byte offset — `offset_space` beside it has said so since the
 * revision before. `first_anchor` is the name, and it is the one the
 * throughput rows already used.
 *
 * R2123 — AND REVISION 3 DROPPED IT, which is the whole dance run once end to
 * end: announced where a consumer could see it, then removed a revision later.
 * A program written against revision 1 or 2 that reads `first_packet` gets
 * nothing from revision 3, which is what the notice was for. Read
 * `first_anchor`.
 *
 * Revision 3 also ADDS `anchor_intervals` to each throughput row — one extent
 * per coordinate space that contributed, with the record count in each. A row
 * folds every flow and both directions, so `anchors_exact:false` says the
 * pair covers only part of it; the intervals say which parts there are and
 * how much of the row each holds.
 *
 * wz_dissect_transport_message is the one door with no such revision, and
 * deliberately: its document is a FIELD TREE whose keys are the walkers' own
 * names, generated per protocol element, so there is no fixed key set for a
 * revision to be about.
 *
 * The live door emits no document at all, so it is outside this scheme
 * rather than an omission from it. A field read by OFFSET cannot be read by
 * name and cannot tolerate an unknown one, so ONCE A LAYOUT HAS SHIPPED, a
 * layout change is a new struct and a new door, never a quiet
 * reinterpretation of the old one. That rule stands.
 *
 * R2108 (ABI 12) USED AN EXCEPTION TO IT, ONCE, AND THIS PARAGRAPH IS THE
 * RECORD OF WHY — because an exception nobody wrote down is read by the next
 * person as a precedent, and this one is not.
 *
 * The struct was called wz_dissect_record_v1 for one day. R2108 renamed it to
 * wz_dissect_record and widened it in place rather than adding a _v2 beside
 * it. The conditions that permitted that, all measured on 2026-08-25 rather
 * than assumed:
 *
 *   - this repository has ZERO tags and ZERO releases, and its latest-release
 *     endpoint answers 404, so no layout here has ever been published as a
 *     release artifact;
 *   - wz_dissect_record_v1 reached origin at 15:46 that same day;
 *   - the only known downstream consumer's own report predates that push and
 *     says its integration begins by moving its pin AFTER a push, so it had
 *     not taken the struct.
 *
 * NONE OF THAT WILL BE TRUE OF THE NEXT LAYOUT CHANGE. If any of those three
 * has stopped holding when you read this, the rule above applies unmodified:
 * add a new struct and a new door.
 *
 * WHAT ACTUALLY CARRIES COMPATIBILITY IS THE NUMBER, not a suffix on a name.
 * wz_dissect_abi_version() is the instrument: a consumer pinned to 11 meets 12
 * and parts company there, which is the whole mechanism. A version suffix on
 * the type was a SECOND marker for the same fact, and two markers for one fact
 * are two things that can disagree — which is why the suffix is gone rather
 * than incremented.
 */
#ifndef WZ_DISSECT_H
#define WZ_DISSECT_H

#include <stddef.h>
#include <stdint.h>

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
 * next axis wz bounds is a preset edit rather than an ABI break.
 *
 * Round 2042 -- and the group carries a `caps` object naming the CEILING each
 * loss was measured against: frames_per_flow, stream_bytes_per_direction,
 * skipped_packets, max_flows_per_table, max_scout_askers. `null` on an axis
 * with no ceiling, never a number and never omitted, so an unbounded run and
 * a bounded one no longer render identically. Before this a `0` said nothing
 * about whether a cap existed to bite, which is the whole distinction this
 * bounded door was added to make. Reading a loss beside its ceiling is also
 * how you tell which cap is NEAREST without waiting for one to bite. */
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
 * capture had no queries in it.
 *
 * SUBSUMED BY wz_dissect_pcap_census_where_limited -- that door takes the
 * selector and the limit preset as ARGUMENTS, so it answers this question and
 * two more. This symbol is kept, not withdrawn: a published symbol is one a
 * consumer already links. New code should reach for the current shape.
 * (R2116, open-debt item 466 -- checked against the library's own `doors`
 * axis, so this line cannot go stale unnoticed.) */
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
 * is a separate decision and is not improvised here.
 *
 * SUBSUMED BY wz_dissect_pcap_census_where_limited -- the preset this door
 * hard-codes is an argument there, which is what stopped a `_bounded` twin
 * being added per document. Kept and still linkable. (R2116, item 466.) */
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
 * string. For the position, call wz_dissect_selector_diagnose.
 *
 * SUBSUMED BY wz_dissect_pcap_census_where_limited -- same selector, plus the
 * ceiling this door cannot take. A narrowed census over a link that does not
 * end is the case this one leaves unserved. (R2116, item 466.) */
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
 * WZ_DISSECT_ERR_INVALID_ARG. Neither hands back a string.
 *
 * @bound limits work-ceiling -- it bounds the WALK, and what the walk
 * dropped is reported in dropped_by_limits. */
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
 * max_messages_shown_per_flow: 0 is UNBOUNDED, matching the command line's
 * default, and a capture holds an unbounded number of messages -- pass a
 * bound if you have a screen to fill. Each flow reports `shown` and
 * `omitted`, so a held-back listing is never mistaken for a capture that
 * ended. `capture_reread` reports whether the datagram half could read the
 * file a second time, which it must do to reach a datagram message's bytes.
 *
 * SUBSUMED BY wz_dissect_pcap_fields_limited -- that door takes the DISSECTION
 * ceiling as an argument, which this one has no way to state: the bound here
 * trims the listing after the whole walk is already built. Kept and still
 * linkable. (R2116, item 466.)
 *
 * @bound max_messages_shown_per_flow trims-output -- the whole walk is paid
 * for and only the DOCUMENT is shortened; each flow's `shown` and `omitted`
 * report the trim. (R2120, item 467: the old spelling promised a ceiling
 * this argument has never enforced.) */
int wz_dissect_pcap_fields(const unsigned char *bytes, size_t len,
                           size_t max_messages_shown_per_flow, char **out);

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
 *     #profile=c:u16be,f:u8      R2114 -- a format DEFINITION: a record this
 *                                library does not ship, described so a rule
 *                                can name it like any other format
 *
 * THE DEFINITION IS WHY THIS DOOR TAKES TEXT AND NOT A FUNCTION POINTER.
 * A deployment with its own profile table used to have to build this
 * workspace to see its own payloads; the obvious remedy -- register a decoder
 * callback -- would have voided the memory rule at the top of this header,
 * which says no callbacks run. Data can be versioned, diagnosed before there
 * is a capture, and refused by line. Code cannot.
 *
 * A layout is `<name>:<type>` items separated by commas, read in order from
 * byte zero. Types are fixed-width integers and floats with their endianness
 * in the spelling, `bytesN` for N raw bytes, and `rest` -- legal only last --
 * for a variable tail. Ask wz_dissect_readable_surfaces for the spellings
 * this build reads rather than copying a list into your own notes. A field's
 * declared NAME is the path it is reported under.
 *
 * Bytes the layout does not account for are a FINDING and not a quiet
 * success: a short description over a long record decodes every field it
 * names and none of them are wrong, which is the worst way to be looking at
 * the wrong record.
 *
 * A definition may appear before or after the rules that use it, and it may
 * not take a name this build already ships -- redefining one would change
 * what every other config file's rules mean on this run alone.
 *
 * A topic whose own name carries `:` or `=` (or a leading `#`) is written
 * with a backslash before it.
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
 * Round 2025 (item 285) -- `encoding_mismatch` additionally carries
 * `declaration_checked`, a boolean, and it is the difference between a
 * finding and a default. `true` means the bytes were inspected and they bear
 * the publisher's label out, so the mapping really is the thing that is
 * wrong. `false` means the label is BINARY or unknown -- `application/cdr`,
 * which is what every ROS 2 publisher declares -- so nothing could weigh it
 * and the veto is this reader's policy rather than a measurement. The
 * outcome is the same either way and the warrant is not: an operator whose
 * CDR traffic is being withheld under a protobuf rule can now see that
 * nothing checked the label it is being withheld on. An ADDED key, so a
 * consumer that does not read it is unaffected.
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
 * makes that legible. The SET is complete for what was walked.
 *
 * Round 2031 -- and `payload_refusals` beside it, the THIRD finding: a rule
 * that was actually applied and whose decoder then REFUSED the bytes. Neither
 * side is caught out by the other there, so it is not a misbinding and does
 * not appear in the array above; until this round it existed only per message,
 * once per row in a listing you bound because it is that long. Each entry is
 * one (`keyexpr`, `format`) pair with `samples`, one sample's reason as
 * `example`, a `note`, and `under` -- what the publisher had said, which is
 * what decides where to look:
 *
 *     `corroborated`  the publisher declared an encoding your rule IS for and
 *                     the decoder still refused; both claims agree and the
 *                     bytes are the odd one out, so look at the capture
 *     `unclaimed`     nothing was declared that this reader could weigh, so
 *                     your rule is the only claim and the traffic contradicts
 *                     it; check the rule first
 *     `refuted`       the publisher declared something its own bytes refute,
 *                     your rule was applied over that label, and it refused
 *                     too -- both are wrong about this traffic
 *
 * Always present, empty array when nothing refused, and bounded by the same
 * walk: `payload_mapping_counts_exact` covers BOTH tallies, because being a
 * floor is a property of the walk rather than of either finding.
 *
 * SUBSUMED BY wz_dissect_pcap_fields_limited -- that door takes the same
 * declarations text AND the dissection ceiling, so it is this call with the
 * one thing it cannot say. Kept and still linkable. (R2116, item 466.)
 *
 * @bound max_messages_shown_per_flow trims-output -- as above: the walk is
 * paid for in full and `shown`/`omitted` report what the document left
 * out. */
int wz_dissect_pcap_fields_with_payloads(const unsigned char *bytes, size_t len,
                                         size_t max_messages_shown_per_flow,
                                         const char *declarations, char **out);

/* R311y917 (ABI 10) — THE FIELD LAYER UNDER A CEILING, with both of its
 * other axes as arguments.
 *
 * The summary has had a bounded form since ABI 2 and the census since ABI 7.
 * The field layer had none, and it is the plane that walks EVERY MESSAGE of
 * the capture -- so it is the one a live tap can least afford unbounded.
 * max_messages_shown_per_flow is not a ceiling: it trims the OUTPUT after the whole
 * dissection has been built, so asking for ten messages still costs you the
 * whole file.
 *
 * ONE door and not two more twins, on the shape
 * wz_dissect_pcap_census_where_limited settled: an EMPTY declarations text
 * declares nothing, so ("", NONE) is wz_dissect_pcap_fields and
 * (text, NONE) is wz_dissect_pcap_fields_with_payloads. Both of those stay
 * exported -- a symbol this ABI has published is one you may already link.
 *
 * limits is WZ_DISSECT_LIMITS_NONE or WZ_DISSECT_LIMITS_LIVE_TAP. An unknown
 * value is WZ_DISSECT_ERR_INVALID_ARG and never a quiet fall back to
 * unbounded.
 *
 * The field document gained `dropped_by_limits` in the same round -- the same
 * five counters the summary's health object and the census document carry --
 * so a listing made short by an evicted flow says so instead of reading like
 * a capture that ended. Present with every counter zero when no ceiling was
 * asked for, so "no caps" and "caps that did not bite" are distinguishable.
 *
 * THE TWO BOUNDS ON THIS DOOR ARE NOT THE SAME KIND, which is the whole
 * reason it takes both:
 *
 * @bound max_messages_shown_per_flow trims-output -- the DOCUMENT is
 * shortened after the walk; `shown`/`omitted` report it.
 * @bound limits work-ceiling -- the WALK is bounded; dropped_by_limits
 * reports it. */
int wz_dissect_pcap_fields_limited(const unsigned char *bytes, size_t len,
                                   size_t max_messages_shown_per_flow,
                                   const char *declarations, int limits,
                                   char **out);

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

/* R311y913 (ABI 9) — what this build can READ, without a capture.
 *
 * Writes {"link_types":"0 NULL, 1 ETHERNET, …",
 *         "ext_bodies":{"zbuf":"Auth/pubkey, …","z64":"Declare/node_id, …"},
 *         "payload_field_types":"u8, i8, u16le, …"}
 *
 * R2114 -- the document is at REVISION 2 and the third key is why. A consumer
 * writing a format DEFINITION (see the declarations door above) needs the
 * type spellings before it has a capture to try them on, and a list copied
 * into its own notes ages the moment this table grows. Read the revision off
 * the envelope rather than assuming the key is there.
 *
 * Two questions `wz-analyze --help` has answered for a while and this surface
 * could not. Both matter for the same reason: an unread capture reports
 * `messages decoded: 0`, and so does a capture with no zenoh traffic in it, so
 * a consumer that cannot ask which link types this build decodes cannot tell
 * its operator to re-capture. Likewise an extension body this build does not
 * open goes out as `value` -- raw bytes -- which reads exactly like "there was
 * no structure here".
 *
 * The strings are DERIVED from the link-type match and the two body dispatches
 * themselves, and are the same strings the terminal prints. A consumer wanting
 * them as lists splits on ", " and cannot be shown a different answer than
 * `--help` gives. */
int wz_dissect_readable_surfaces(char **out);

/* ── R2102 (ABI 11) — THE LIVE DOOR ──────────────────────────────────────
 *
 * Every door above takes a whole capture and hands back a document. That is
 * right for a FILE, which ends, and wrong for a LINK, which does not: a
 * consumer watching a running system could either re-hand the same growing
 * buffer in and pay a full re-dissection per call, or cut the stream into
 * windows and lose every message that straddles a cut.
 *
 * This is the other shape. Open a handle, feed it packets as they arrive,
 * and take the messages that became decodable into a buffer you own:
 *
 *     wz_dissect_live *h;
 *     if (wz_dissect_live_open(WZ_DISSECT_LIMITS_LIVE_TAP, &h)) { ... }
 *     for (;;) {
 *         wz_dissect_live_push(h, link_type, ts_ns, pkt, pkt_len);
 *         wz_dissect_record buf[256];
 *         size_t n;
 *         while (!wz_dissect_live_drain(h, buf, 256, &n) && n) {
 *             ...                        // render buf[0..n]
 *             if (n < 256) break;        // a short count means drained
 *         }
 *     }
 *     wz_dissect_live_close(h);
 *
 * READ THE MEMORY RULE AT THE TOP OF THIS FILE FIRST. This family is the
 * one exception to it, the exception is stated there, and nothing else in
 * this header creates anything you have to give back except a char*.
 */

/* A live dissection. Opaque: its size and contents are this library's, and
 * a consumer holds only the pointer. */
typedef struct wz_dissect_live wz_dissect_live;

/* The `ts_ns` you pass when you have no clock reading, and the value a
 * record carries back when nothing timed it.
 *
 * NOT zero, and that is the whole reason it is spelled out: zero is a legal
 * instant, and a sentinel colliding with it would report a tap whose clock
 * starts at zero as a tap with no clock. */
#define WZ_DISSECT_NO_TIMESTAMP UINT64_MAX

/* wz_dissect_record.kind — the message kinds. Derived from the decoder's
 * own variants (`InboundFrame::kind_code`), so a kind this build gained
 * appears here and in that match on the same commit.
 *
 * 0 and 255 sit at the ends deliberately. UNDECODABLE is not a message kind
 * at all -- it is this reader failing -- and UNKNOWN is a MID this build
 * does not recognise, which is a fact about the wire. Both are answers, and
 * neither is the absence of one. The numbers in between are contiguous so a
 * kind added later gets the next one and a consumer's switch falls through
 * to its own default rather than onto a neighbour's case. */
#define WZ_DISSECT_KIND_UNDECODABLE 0
#define WZ_DISSECT_KIND_INIT 1
#define WZ_DISSECT_KIND_OPEN 2
#define WZ_DISSECT_KIND_CLOSE 3
#define WZ_DISSECT_KIND_KEEPALIVE 4
#define WZ_DISSECT_KIND_FRAME 5
#define WZ_DISSECT_KIND_FRAGMENT 6
#define WZ_DISSECT_KIND_JOIN 7
#define WZ_DISSECT_KIND_OAM 8
#define WZ_DISSECT_KIND_UNKNOWN 255

/* wz_dissect_record.origin — which of a flow's message lists this came
 * out of. A flow can carry several at once (a UDP conversation may hold
 * cleartext datagrams AND messages recovered from inside QUIC), and they
 * are different lists rather than one interleaved one. */
#define WZ_DISSECT_ORIGIN_STREAM 1
#define WZ_DISSECT_ORIGIN_DATAGRAM 2
#define WZ_DISSECT_ORIGIN_QUIC_STREAM 3
#define WZ_DISSECT_ORIGIN_QUIC_DATAGRAM 4
#define WZ_DISSECT_ORIGIN_SERIAL 5

/* wz_dissect_record.anchor_space — how to read `anchor`. They are small
 * numbers either way and cannot be told apart by looking, which is why the
 * record says. A PACKET index must not be added to anything. */
#define WZ_DISSECT_ANCHOR_PACKET 0
#define WZ_DISSECT_ANCHOR_STREAM_BYTES 1

/* wz_dissect_record.flags — zero for an ordinary message. */
/* The frame's wire length exceeded the batch_size its session's InitAck
 * agreed to: a protocol violation by the sender. The message still
 * decoded, and is reported rather than dropped -- dropping is what makes a
 * non-conforming peer invisible. */
#define WZ_DISSECT_FLAG_EXCEEDS_NEGOTIATED_BATCH 0x1u
/* This message cannot occur on the link that carried it (an INIT or OPEN on
 * a multicast-capable link), so it was decoded and reported but NOT folded
 * into the session context. */
#define WZ_DISSECT_FLAG_INADMISSIBLE_ON_LINK 0x2u
/* The first message after the reader recovered its framing. Whatever stood
 * between the loss and this message was skipped. */
#define WZ_DISSECT_FLAG_AFTER_RESYNC 0x4u

/* ONE decoded transport message.
 *
 * 56 bytes, 8-aligned, with every field explicitly sized. Both sides assert
 * that -- `the_record_layout_is_the_one_the_header_declares` in the Rust
 * crate and a sizeof/offsetof block in tests/c_abi_consumer.c -- because
 * this is the one output of this library that is raw memory rather than
 * text: a field inserted or widened gives a consumer plausible garbage (an
 * anchor that is half a timestamp) with no error anywhere.
 *
 * The `_v1` is the compatibility statement. A field read by OFFSET cannot
 * tolerate an unknown one, so a layout change is a new struct and a new
 * door, never a new meaning for this one. */
typedef struct wz_dissect_record {
    /* This reader's clock AS OF this message, in nanoseconds, or
     * WZ_DISSECT_NO_TIMESTAMP if it was never set.
     *
     * Two things that look alike and are not:
     *
     *   - the clock is MILLISECONDS, so what comes back is the nanosecond
     *     value you pushed, truncated to the millisecond it fell in and
     *     widened again. The narrowing happens at the boundary rather than
     *     in your code so there is one rounding rule in the system;
     *   - a push carrying WZ_DISSECT_NO_TIMESTAMP leaves the clock WHERE IT
     *     STOOD, so a record can carry the instant of an earlier packet.
     *     That is a different fact from having no clock, and only the
     *     second reports the sentinel. */
    uint64_t ts_ns;
    /* The CONVERSATION: a number this handle assigns each flow it sees, from
     * zero, in order of first appearance. Stable for the life of the handle,
     * meaningless outside it.
     *
     * Everything one UDP conversation carries shares this -- the cleartext
     * messages and whatever was recovered from inside QUIC alike -- because
     * that is what grouping by "connection" means. */
    uint64_t flow_id;
    /* The COORDINATE SPACE: a number per message LIST, on the same counter,
     * so a flow_id and a list_id are never the same number.
     *
     * TWO RECORDS' ANCHORS ARE COMPARABLE EXACTLY WHEN THIS MATCHES, and that
     * is the whole of what the field is for. A flow can carry several lists at
     * once, and the QUIC-stream ones are byte offsets that each start at zero
     * -- so grouping by (flow_id, origin) would put two streams' byte 0 in one
     * space and read two distinct messages as one. `origin` cannot express the
     * difference, because a stream's identity is a number the wire chose.
     *
     * It also moves when a list is REPLACED: a flow evicted and reopened under
     * the same 5-tuple restarts its offsets, so it gets a new id rather than
     * inheriting coordinates that no longer mean anything. */
    uint64_t list_id;
    /* Where the message sits. Read it according to `anchor_space`: a packet
     * INDEX (which is your own push ordinal, counting from zero) or a byte
     * offset within one direction of this list's stream. Comparable only
     * against a record carrying the same `list_id`. */
    uint64_t anchor;
    /* The length the framing unit DECLARED, in bytes. */
    uint64_t unit_len;
    /* Which message of its framing unit this is, from zero. A batch puts
     * several messages at one anchor and this is what keeps them apart. */
    uint32_t batch_index;
    /* Byte offset of this message within its framing unit. */
    uint32_t unit_offset;
    /* 0 = direction A (conventionally the initiator), 1 = B. */
    uint8_t direction;
    /* WZ_DISSECT_ANCHOR_*. */
    uint8_t anchor_space;
    /* WZ_DISSECT_ORIGIN_*. */
    uint8_t origin;
    /* WZ_DISSECT_KIND_*. */
    uint8_t kind;
    /* WZ_DISSECT_FLAG_* bits, or zero. */
    uint32_t flags;
} wz_dissect_record;

/* Open a live dissection. `limits` is WZ_DISSECT_LIMITS_LIVE_TAP for a link,
 * or WZ_DISSECT_LIMITS_NONE for a bounded replay you want nothing discarded
 * from. An unknown value is WZ_DISSECT_ERR_INVALID_ARG and never a quiet
 * fall back to unbounded: on a door whose input does not end, a caller that
 * believes it asked for a ceiling must not be given none.
 *
 * On WZ_DISSECT_OK, `*out` is a handle to be released exactly once with
 * wz_dissect_live_close.
 *
 * @bound limits work-ceiling -- it bounds what the handle RETAINS between
 * packets, and wz_dissect_live_lost is what it discarded. */
int wz_dissect_live_open(int limits, wz_dissect_live **out);

/* Feed one captured packet. `link_type` is its pcap link type -- the same
 * numbering wz_dissect_readable_surfaces reports.
 *
 * `ts_ns` is when the packet was captured, or WZ_DISSECT_NO_TIMESTAMP; see
 * the record's own field for what this reader does with it.
 *
 * A packet on a link this build does not decode is COUNTED as skipped and
 * returns WZ_DISSECT_OK. A tap sees whatever the interface gives it, and a
 * call that failed per packet would make an ordinary mixed capture look
 * like a broken consumer -- which teaches a consumer to ignore the return
 * value, and that is worse than not having one. */
int wz_dissect_live_push(wz_dissect_live *h, unsigned int link_type,
                         uint64_t ts_ns, const unsigned char *bytes,
                         size_t len);

/* Take the messages decoded since the last drain into `out`, which holds
 * `cap` records; `*written` receives how many were filled.
 *
 * If more are ready than `cap` holds, the rest stay, in order -- drain in a
 * loop until you get a short count. A `cap` of zero writes nothing and is
 * legal: it is how you ask the handle to bring its own accounting up to
 * date without taking anything.
 *
 * ORDER: records are grouped by the flow-list they came from, each list in
 * the order it decoded them. They are NOT globally sorted by time. Sort on
 * `ts_ns` if you need that -- a live reader cannot do it for you without
 * holding messages back until nothing older can arrive, and on a link that
 * moment never comes.
 *
 * @bound cap buffer-capacity -- it is the size of YOUR array. This library
 * imposes nothing by it and discards nothing for it: what does not fit
 * stays, and `*written` says what did. */
int wz_dissect_live_drain(wz_dissect_live *h, wz_dissect_record *out,
                          size_t cap, size_t *written);

/* Messages this handle decoded and then DISCARDED before you drained them,
 * cumulative: a ceiling trimming a flow's list, or a flow evicted to stay
 * inside the flow cap.
 *
 * Read it when you RENDER, not once per drain, which is why it is its own
 * door rather than another out-parameter. Non-zero is the one thing that
 * separates "the link went quiet" from "this reader could not keep up", and
 * a bounded read that could not say so would be reporting a floor as a
 * total. `0` for a null handle. */
uint64_t wz_dissect_live_lost(const wz_dissect_live *h);

/* Release a live handle. Null is a no-op, so your cleanup path needs no
 * guard of its own -- the same rule wz_dissect_string_free follows, and the
 * commonest source of a double free at an FFI seam. */
void wz_dissect_live_close(wz_dissect_live *h);

/* R2108 -- the record's layout, AS THE BUILT LIBRARY SEES IT.
 *
 * Fills `out` with, in order: size, align, then the offset of every field of
 * wz_dissect_record in declaration order. Returns how many values that is. A
 * null `out`, or a `cap` below the count, writes nothing and returns the
 * count, so a caller sizes first and reads second.
 *
 * THIS IS NOT A DOOR FOR CONSUMERS. A program that includes this header
 * already has the layout from the compiler; asking the library for it would be
 * asking the same question twice and believing the second answer. It exists so
 * a GATE outside both languages can read the layout out of the artifact and
 * hold it against a pin that sits beside the ABI revision -- because the two
 * pins that used to hold it, a Rust test and a C block, are edited by the same
 * commit that changes the layout, and two pins that move together are one.
 *
 * @bound cap buffer-capacity -- the size of YOUR array. Below the count it
 * writes nothing and still RETURNS the count, so it never truncates. */
size_t wz_dissect_record_layout(size_t *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* WZ_DISSECT_H */
