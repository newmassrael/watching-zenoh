/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * R2300 (open-debt item 631) — WZ'S OWN DOORS IN libwz_capi_c.
 *
 * WHAT IS AND IS NOT IN THIS FILE, because the library has two surfaces
 * and only one of them is here:
 *
 *   - libwz_capi_c is a DROP-IN for zenoh-c. Every z_* / zc_* / ze_*
 *     symbol it exports is upstream's, and upstream's own zenoh.h is
 *     what declares them. This file does NOT redeclare any of those; a
 *     second declaration of a drop-in symbol is a second place for the
 *     ABI to drift, which is the whole failure a drop-in exists to
 *     avoid. Include zenoh.h for those, and include it BEFORE this file
 *     — the declarations below use its types.
 *
 *   - The doors below are wz's OWN. They have no upstream counterpart
 *     and no upstream header can declare them. Upstream zenoh-c has
 *     sixteen config functions at the pinned checkout and not one of
 *     them validates anything, which is why the four verdict doors
 *     carry the wz_capi_c_ prefix rather than a zc_ one: a zc_ spelling
 *     would promise a name a caller could port back to zenoh-c, and
 *     there is nothing there to port to.
 *
 * EVERY wz_capi_c_ SYMBOL THE LIBRARY EXPORTS IS DECLARED HERE. That is
 * a checked property, not an intention — `capi_c_wz_door_header.py`
 * derives the exported set from the sources and reds on a door this
 * file does not declare, and on a declaration here that names no door.
 * A partial header would leave "is this one declared?" as a question a
 * consumer has to answer by reading Rust, which is the position item
 * 631 found them in.
 *
 * MEMORY RULE: every const char* returned below is 'static and owned by
 * this library. Do NOT free one. The z_owned_string_t out-parameters
 * are the ordinary zenoh-c ownership: you own them, release them with
 * z_string_drop, and they hold a gravestone on any error return.
 *
 * THREADS: every door here is safe to call from any thread. They read
 * immutable tables or borrow a config the caller is responsible for not
 * mutating concurrently.
 */

#ifndef WZ_CAPI_C_H
#define WZ_CAPI_C_H

#include <stddef.h>
#include <stdint.h>

/* For z_loaned_config_t, z_owned_string_t and z_result_t. This header
 * declares none of them: they are upstream's types and upstream's
 * header owns them. */
#include "zenoh.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * THE REVISION OF THIS DOOR SET (R2301, open-debt item 634).
 *
 * WHAT THIS NUMBER IS ABOUT, which is narrower than the library: it
 * moves when the set of wz_capi_c_* symbols changes, or when the
 * memory rule stated above changes. It says NOTHING about the drop-in
 * z_* / zc_* / ze_* surface — that is upstream zenoh-c's contract and
 * upstream's header declares it. A number minted here could only be a
 * second, disagreeing opinion about somebody else's ABI.
 *
 * HOW TO USE THE PAIR. The macro is what you COMPILED against; the
 * function is what you are RUNNING against. They differ only when a
 * build is linked to a library it was not compiled for, which is the
 * one failure a header cannot detect on its own:
 *
 *     if (wz_capi_c_abi_version() != WZ_CAPI_C_ABI_REVISION) { ... }
 *
 * Starts at 1: this door set had no revision before R2301, so there is
 * no earlier number to be compatible with.
 *
 * ⚠ THIS PAIR IS NOT A FEATURE PROBE, and the check above is the wrong
 * shape for "does this library have door X". A consumer asked exactly
 * that (R2799), reasonably, because nothing here said otherwise.
 *
 * To test for ONE door, RESOLVE THE SYMBOL -- dlsym, or a weak
 * reference -- and branch on that. It observes the artifact; a number
 * only DECLARES something about it, and the two come apart:
 *
 *   - `== N` refuses a later library that still has the door, because
 *     the revision moves on any symbol-set change;
 *   - `>= N` is not a guarantee either, since a REMOVAL is an ABI event
 *     too and leaves the number above N;
 *   - neither actually asks the question.
 *
 * Use the revision to EXPLAIN an absence, not to predict a presence:
 * on a failed lookup, report the number so the message reads "library
 * reports revision 1; that door arrives at 2" instead of a bare missing
 * symbol. Resolve wz_capi_c_abi_version itself before calling it on
 * that path -- a library old enough to lack a door may predate the
 * version door as well, and a probe that crashes while diagnosing is
 * worse than the gap it was diagnosing.
 *
 * `capi_c_abi_pin.py` is what keeps it honest, and it is the worked
 * example of the paragraph above: it reads the symbol SET out of the
 * BUILT library and the number by CALLING it, holding the two against
 * each other rather than inferring one from the other. A symbol added
 * without moving this number is red rather than shipped.
 * ------------------------------------------------------------------ */

#define WZ_CAPI_C_ABI_REVISION 13

/* The revision the LOADED library reports. See the block above for why
 * this exists beside the macro. */
int32_t wz_capi_c_abi_version(void);

/* ------------------------------------------------------------------ *
 * The layout report — the drop-in's half of the ABI layout gate.
 * ------------------------------------------------------------------ */

/* Write at most `cap` footprints through `out` (ignored when NULL) and
 * return how many this build has. A short buffer gets a truncated
 * prefix and a count saying so; it is never written past. */
size_t wz_capi_c_layout(size_t *out, size_t cap);

/* The name of layout entry `index`, or NULL past the end. */
const char *wz_capi_c_layout_name(size_t index);

/* ------------------------------------------------------------------ *
 * The honoured config keys — which keys wz's JSON5 reader applies.
 *
 * TWO DOORS, AND THE FIRST IS NOT A COMPLETE ANSWER. The list below is
 * the exactly-named FINITE part of the surface. The honoured set itself
 * is INFINITE: `plugins/storage_manager/storages/<name>/key_expr` is
 * honoured for every <name> an operator writes, and no list holds every
 * name. Walking the list therefore yields `plugins` and nothing beneath
 * it.
 *
 * To classify a key — which is what a tool reading somebody's config
 * document is doing — ASK wz_capi_c_config_disposition. Use the list
 * when you want the set wz NAMES, for instance to diff two builds'
 * surfaces; use the predicate when you have a key and want the answer.
 * ------------------------------------------------------------------ */

/* How many config keys wz honours when reading a stock zenoh config. */
size_t wz_capi_c_config_honoured_count(void);

/* The name of honoured key `index`, or NULL past the end. Walk it until
 * NULL rather than trusting the count. */
const char *wz_capi_c_config_honoured(size_t index);

/* The three answers wz_capi_c_config_disposition writes. The numbers
 * are ABI; a fourth would move WZ_CAPI_C_ABI_REVISION.
 *
 * HONOURED             writing this key changes what this build does.
 * DECLARED_UNHONOURED  this build reads a document carrying the key,
 *                      applies nothing from it, AND SAYS SO ON PURPOSE.
 * UNKNOWN              this build has NO STATEMENT about the key: a
 *                      misspelling, or surface upstream grew later.
 *
 * The last two are the pair a boolean would merge, and they are
 * opposite advice to whoever wrote the key — one is a supported
 * deployment, the other is a mistake in their file. */
#define WZ_CAPI_C_CONFIG_HONOURED 0
#define WZ_CAPI_C_CONFIG_DECLARED_UNHONOURED 1
#define WZ_CAPI_C_CONFIG_UNKNOWN 2

/* What this build says about the config key `path`, written through
 * `out` as one of the three above.
 *
 * `path` is NUL-terminated and uses `/` SEPARATORS --
 * "transport/unicast/max_sessions", not a dotted or JSON-pointer
 * spelling. Nothing is normalised on the way in: a separator this door
 * silently accepted would make a misspelling look like a key, which is
 * the one thing WZ_CAPI_C_CONFIG_UNKNOWN exists to keep visible.
 *
 * Z_OK, or Z_ENULL for a null argument and Z_EPARSE for a path that is
 * not UTF-8. `*out` is set to WZ_CAPI_C_CONFIG_UNKNOWN before anything
 * else, so a caller that ignores the return reads "no statement" rather
 * than whatever was on its stack. */
z_result_t wz_capi_c_config_disposition(const char *path, int32_t *out);

/* ------------------------------------------------------------------ *
 * Emitting and judging a config (R2300, open-debt item 631).
 *
 * All four read the z_owned_config_t you already built with
 * zc_config_from_file / zc_config_insert_json5 / z_config_default.
 * There is no second config type to keep in step.
 * ------------------------------------------------------------------ */

/* Render the config a STOCK ZENOH NODE would have been started with,
 * as the JSON5 `zenohd -c` reads.
 *
 * NOT zc_config_to_string, which echoes back EXACTLY the keys YOU
 * stated and nothing else. This one RESOLVES them, so the document it
 * writes also carries every honoured key you never mentioned -- which
 * is what a real zenoh node would have run with. A caller writing a
 * file for zenohd wants this one; a caller echoing its own
 * configuration wants that one.
 *
 * (Both nest. R2303 corrected the older claim that the two differed by
 * SPELLING: upstream's zc_config_to_string emits a nested document and
 * refuses a flat one, so wz's flat emit was a defect, not a variant.)
 *
 * If you write the result to a file for `zenohd -c`, THE FILE MUST HAVE
 * A .json5, .json OR .yaml EXTENSION. zenoh dispatches its config
 * parser on the extension and panics on a file without one, before
 * reading a single byte — so nothing about the text can hint at it.
 *
 * Z_OK, or Z_ENULL / Z_EPARSE. ON AN ERROR THE STRING CARRIES THE
 * REASON and names the key at fault, so the text is a config document
 * only when the return is Z_OK. Check it. */
z_result_t wz_capi_c_config_to_json5(const z_loaned_config_t *config,
                                     z_owned_string_t *out_config_string);

/* Every reason this config cannot work, ONE PER LINE, judged as a stock
 * zenohd would — every link scheme zenoh carries is assumed available.
 *
 * A line is
 *
 *     <VariantName>: <a human-readable message>
 *
 * The NAME is the stable half: it moves only when the defect enum gains
 * or renames a variant, which is an ABI-visible event. The MESSAGE is
 * prose and may be reworded in any release. Branch on the name; show
 * the message.
 *
 * An empty string is a clean verdict ON A Z_OK RETURN, and only there:
 * a config that could not be READ returns Z_ENULL / Z_EPARSE and writes
 * the reason into the same string. An unchecked reader therefore sees a
 * defect it does not recognise rather than a clean bill, which is the
 * direction of that mistake worth having — but check the return. */
z_result_t wz_capi_c_config_validate(const z_loaned_config_t *config,
                                     z_owned_string_t *out_defects);

/* wz_capi_c_config_validate, plus the one verdict that depends on who
 * is reading: an endpoint whose scheme THIS BUILD was not compiled with
 * collects ProtocolNotCompiledIn here and nothing there.
 *
 * A caller standing a wz node up from a config wants this; a caller
 * writing a config for a stock zenohd wants the other. The two are
 * separate doors rather than one door with a flag because the question
 * differs, not a parameter.
 *
 * Use wz_capi_c_config_link_scheme to find out what this build does
 * carry. */
z_result_t wz_capi_c_config_validate_for_build(const z_loaned_config_t *config,
                                               z_owned_string_t *out_defects);

/* What an open of this config would ask of the operating system (revision 7),
 * as ONE JSON object with the keys of the target-build manifest
 * (docs/target-build-contract.md T9):
 *
 *     {"requires": [...], "may_require": [...] or null, "unknown": [...]}
 *
 * requires is what every run of the config cannot go on without;
 * may_require is the rest a run may ask for, null when part of it has no
 * facility name, and unknown says why. The words are the manifest's
 * facility vocabulary. The config is read through the same plan z_open
 * runs, and is not consumed.
 *
 * Z_OK with the object, or the code z_open would refuse the config with,
 * the string then naming the refusal and its keys. */
z_result_t wz_capi_c_config_device_requires(const z_loaned_config_t *config,
                                            z_owned_string_t *out_requirement);

/* Every reason this SET of configs cannot work TOGETHER, one per line,
 * in the same <VariantName>: <message> form.
 *
 * The questions one config cannot answer: a node dialling an endpoint
 * nobody listens on, two nodes claiming one address, a set in which
 * nothing accepts. Each node would start cleanly and nothing would
 * attach.
 *
 * `configs` is an array of `count` loaned configs. A count of zero is a
 * valid question with an empty answer. A NULL `configs` with a non-zero
 * count is Z_ENULL. An element that is NULL or unreadable fails the
 * WHOLE call rather than being skipped — a verdict over a subset is a
 * different verdict, and narrowing the set silently is how a green
 * answer stops meaning anything.
 *
 * This reads the set as CLOSED: "nobody listens on it" means nobody
 * HERE. For a set that attaches to a zenoh node you do not own, use the
 * door below — a closed reading of a fragment reports every outward
 * dial as dangling. */
z_result_t wz_capi_c_config_validate_topology(const z_loaned_config_t *const *configs,
                                              size_t count,
                                              z_owned_string_t *out_defects);

/* The same question for a set that attaches to listeners YOU DO NOT
 * OWN — a handful of nodes talking to a zenohd somebody else runs,
 * which is the most ordinary fragment there is.
 *
 * `external` is an array of `external_count` NUL-terminated endpoint
 * strings: the addresses of those outside nodes. Declaring them changes
 * three verdicts, and each is a real failure of a real deployment:
 *
 *   - a dial answered by a declared listener is no longer dangling;
 *   - a declaration ANSWERING NO DIAL is UnusedExternalListener: the
 *     deployment believes it attaches somewhere it does not;
 *   - a declaration the set ALREADY answers is ExternalShadowsListener,
 *     and one that does not parse is MalformedExternalListener.
 *
 * With `external_count` zero this is exactly the closed door above.
 * A non-UTF-8 declaration is Z_EPARSE naming its index, rather than
 * being decoded lossily: an endpoint is matched by STRING, and a
 * replacement character would compare unequal to what you meant while
 * looking plausible in the report. */
z_result_t wz_capi_c_config_validate_topology_with_external(
    const z_loaned_config_t *const *configs,
    size_t count,
    const char *const *external,
    size_t external_count,
    z_owned_string_t *out_defects);

/* ------------------------------------------------------------------ *
 * The config verdict as ROWS. Revision 4.
 *
 * The verdict doors above answer in lines, `<VariantName>: <message>`,
 * and a line is for a person. A caller that attaches each reason to the
 * config field it is about would have to parse the message to find the
 * key, and the message is prose that may be reworded in any release.
 * These doors answer in a TABLE instead, read a column at a time from
 * one owned handle.
 *
 * A verdict is a list of FINDINGS, one per defect (the count of lines
 * the string doors would have written), and a finding can point at
 * several places: Unreachable at the three keys that could have given a
 * node a peer, a listen collision at every node claiming the address.
 * So the table is FLAT: one ROW per (finding, place), the finding's own
 * columns repeated. Walk the rows for places; group them by
 * wz_capi_c_config_verdict_row_finding for defects.
 *
 * COLUMNS. variant and message are on every row. The other three are on
 * a row only when the finding has one, and their readers say so: they
 * return false, with an EMPTY view, when it has none.
 *
 *   variant   the stable name, the same one the string doors put before
 *             the colon. Branch on this.
 *   message   the prose. Show this.
 *   node      the node, under the name YOU gave it, else its `id`, else
 *             node[<index>]. Absent for a config judged on its own and
 *             for a declaration typed at argv.
 *   key       the config key path at fault, `/`-separated as zenoh
 *             spells it: transport/link/tx/batch_size. Absent when no
 *             key is at fault: the text was not JSON5, or the finding is
 *             about an endpoint declared at argv.
 *   endpoint  the endpoint the defect is about, as given.
 *
 * A REFUSAL IS A ROW. A config that cannot be READ returns the code its
 * string door returns (Z_EPARSE for a config the reader refuses, Z_ENULL
 * for none) AND the reason as rows, with the key at fault in the key
 * column when the refusal is about one. The set door reports EVERY
 * refusal in the call, not the first; the code is the first's, and no
 * verdict is produced while anything is refused. A refusal is named as
 * a defect is: OutOfRange, UnknownMode, NestConflict and the rest of the
 * reader's own for a config; NoConfig, NoExternal, ExternalNotUtf8,
 * NameNotUtf8 (Z_EPARSE) and NameEmpty (Z_EINVAL) for an argument.
 *
 * MEMORY. The verdict is yours and is freed by
 * wz_capi_c_config_verdict_drop. It is written on EVERY path that can
 * write one, the refusing paths included, and holds a gravestone where
 * the door could not read its arguments at all (Z_ENULL for a NULL array
 * with a non-zero count). A NULL `out` is the one case with nowhere to
 * write. A z_view_string_t read from a verdict borrows from it and is
 * valid until it is dropped; nothing is copied to you.
 * ------------------------------------------------------------------ */

/* Owned / loaned / moved. One pointer each: wz's own types, with no
 * upstream footprint to match. */
typedef struct wz_capi_c_owned_config_verdict_t { void *_handle; } wz_capi_c_owned_config_verdict_t;
typedef struct wz_capi_c_loaned_config_verdict_t { void *_handle; } wz_capi_c_loaned_config_verdict_t;
typedef struct wz_capi_c_moved_config_verdict_t {
  wz_capi_c_owned_config_verdict_t _this;
} wz_capi_c_moved_config_verdict_t;

/* wz_capi_c_config_validate, in rows. A config that cannot be read
 * returns the code that door returns and ONE refusal row. */
z_result_t wz_capi_c_config_validate_rows(const z_loaned_config_t *config,
                                          wz_capi_c_owned_config_verdict_t *out);

/* wz_capi_c_config_validate_for_build, in rows: the same verdict plus
 * ProtocolNotCompiledIn for a scheme this build lacks. */
z_result_t wz_capi_c_config_validate_for_build_rows(
    const z_loaned_config_t *config,
    wz_capi_c_owned_config_verdict_t *out);

/* wz_capi_c_config_validate_topology_with_external, in rows and with
 * YOUR names for the nodes.
 *
 * `names` is NULL, or an array of `count` entries, each NULL or a
 * NUL-terminated, non-empty UTF-8 name. A NULL array or entry leaves that
 * node to its default name. A name is a label and not an identity: two
 * nodes given one name are still two nodes. `external` is NULL or an
 * array of `external_count` NUL-terminated UTF-8 endpoints, as for the
 * door above; zero of them is the closed reading. */
z_result_t wz_capi_c_config_validate_topology_rows(
    const z_loaned_config_t *const *configs,
    const char *const *names,
    size_t count,
    const char *const *external,
    size_t external_count,
    wz_capi_c_owned_config_verdict_t *out);

/* How many rows the verdict has; 0 for a NULL verdict. */
size_t wz_capi_c_config_verdict_len(const wz_capi_c_loaned_config_verdict_t *this_);
/* How many findings: the count of defects. 0 for a NULL verdict. */
size_t wz_capi_c_config_verdict_finding_count(
    const wz_capi_c_loaned_config_verdict_t *this_);
/* Which finding row `index` belongs to, counted from 0 in reporting
 * order. Rows of one finding are adjacent and share it. Z_ENULL for a
 * NULL verdict or `out`, Z_EINVAL for an index past the end. */
z_result_t wz_capi_c_config_verdict_row_finding(
    const wz_capi_c_loaned_config_verdict_t *this_, size_t index, size_t *out);

/* The variant name and the prose, on every row. Z_ENULL / Z_EINVAL as
 * above, with an empty view. */
z_result_t wz_capi_c_config_verdict_row_variant(
    const wz_capi_c_loaned_config_verdict_t *this_, size_t index,
    z_view_string_t *out);
z_result_t wz_capi_c_config_verdict_row_message(
    const wz_capi_c_loaned_config_verdict_t *this_, size_t index,
    z_view_string_t *out);

/* The columns a row may lack: false, with an empty view, when this row
 * has no value (or the verdict or index is not valid). */
bool wz_capi_c_config_verdict_row_node(
    const wz_capi_c_loaned_config_verdict_t *this_, size_t index,
    z_view_string_t *out);
bool wz_capi_c_config_verdict_row_key(
    const wz_capi_c_loaned_config_verdict_t *this_, size_t index,
    z_view_string_t *out);
bool wz_capi_c_config_verdict_row_endpoint(
    const wz_capi_c_loaned_config_verdict_t *this_, size_t index,
    z_view_string_t *out);

const wz_capi_c_loaned_config_verdict_t *wz_capi_c_config_verdict_loan(
    const wz_capi_c_owned_config_verdict_t *this_);
/* Release the verdict and every view read from it. A second drop is a
 * no-op. */
void wz_capi_c_config_verdict_drop(wz_capi_c_moved_config_verdict_t *this_);
void wz_capi_c_internal_config_verdict_null(wz_capi_c_owned_config_verdict_t *this_);
bool wz_capi_c_internal_config_verdict_check(
    const wz_capi_c_owned_config_verdict_t *this_);

/* ------------------------------------------------------------------ *
 * Link schemes: what this build carries, and what stock zenoh does.
 *
 * Both lists are needed and neither implies the other. Their DIFFERENCE
 * is exactly the set of endpoints a stock zenohd would accept and this
 * build would refuse — the population
 * wz_capi_c_config_validate_for_build discriminates on. A consumer
 * holding one list cannot compute it.
 * ------------------------------------------------------------------ */

/* How many link schemes THIS BUILD can bind and dial. */
size_t wz_capi_c_config_link_scheme_count(void);

/* The name of this build's link scheme `index`, or NULL past the end. */
const char *wz_capi_c_config_link_scheme(size_t index);

/* How many link schemes STOCK ZENOH carries. */
size_t wz_capi_c_config_zenoh_link_scheme_count(void);

/* The name of stock zenoh's link scheme `index`, or NULL past the
 * end. */
const char *wz_capi_c_config_zenoh_link_scheme(size_t index);

/* ------------------------------------------------------------------ *
 * The sending side of an end-to-end protected message (revision 5).
 * Present in every build: it is wz's own surface, with no upstream
 * zenoh-c counterpart to be a drop-in for.
 *
 * WHAT IT IS FOR. A process that stays up and repeats a message must
 * advance the message's counter on every send. wz_dissect_e2e_wrap (in
 * the dissect library) builds one frame from values you write, the
 * counter among them, and a caller that numbers its own frames keeps
 * using it. This sender keeps the counter instead, so the rule for when
 * it advances is in one place. The frame comes out of the same writer,
 * so the two libraries cannot disagree about a header.
 *
 * ONE SENDER PER MESSAGE. Two messages that share a profile keep two
 * senders and so two counters; a periodic message is one sender called
 * again and again. One handle may be used from several threads: the
 * counter and the frame are taken under one lock, so two calls get two
 * values.
 *
 * THE COUNTER.
 *  - wz_capi_c_e2e_sender_new takes the value the FIRST frame carries.
 *    A process restarted on reconnect passes it again.
 *  - A frame that is built carries the next value, and the next value
 *    moves by one. A frame that is refused builds nothing and consumes
 *    no value.
 *  - The counter does NOT wrap by default. The frame that carries the
 *    largest value the counter field holds is built, and the next call
 *    is refused, with a reason that names the field and the value.
 *    WZ_CAPI_C_E2E_ROLLOVER_WRAP counts on from zero instead, and is
 *    chosen by name.
 *  - A start value that does not fit the field is refused by the first
 *    frame, like any value that does not fit, and consumes nothing.
 *  - The values text must NOT state the counter field; a text that does
 *    is refused, because there is no rule for which would win.
 *
 * REFUSALS ARE DOCUMENTS. As for every document door in the dissect
 * library, a text this library was handed and refused is a successful
 * diagnosis: wz_capi_c_e2e_sender_wrap returns Z_OK and writes the
 * e2e_wrap document, with "ok":false, the reason and the place. The
 * return value says whether the call was well formed; the document
 * says whether a frame was built, and its "frame" is the frame as
 * lowercase hex. The constructor is the exception: a sender that does
 * not exist cannot be handed back, so a profile that is not one is
 * Z_EPARSE with the same kind of document in `refusal`.
 *
 * The profile and the values text are those of wz_dissect_e2e_wrap,
 * described in wz_dissect.h, with one difference: the sender writes the
 * counter field the profile names.
 * ------------------------------------------------------------------ */

/* What the counter does after the frame that carried its largest value. */
typedef int32_t wz_capi_c_e2e_rollover_t;
#define WZ_CAPI_C_E2E_ROLLOVER_REFUSE 0
#define WZ_CAPI_C_E2E_ROLLOVER_WRAP 1

typedef struct wz_capi_c_owned_e2e_sender_t { void *_handle; } wz_capi_c_owned_e2e_sender_t;
typedef struct wz_capi_c_loaned_e2e_sender_t { void *_handle; } wz_capi_c_loaned_e2e_sender_t;
typedef struct wz_capi_c_moved_e2e_sender_t { wz_capi_c_owned_e2e_sender_t _this; } wz_capi_c_moved_e2e_sender_t;

/* A sender for the message `profile_json` describes, whose first frame
 * carries `first_counter`. `this_` holds a gravestone on every error.
 * `refusal` may be NULL; when it is not, it is empty on success and on
 * Z_EPARSE holds the document that says why the profile was refused.
 * Z_ENULL for a null `this_` or `profile_json`, Z_EINVAL for text that
 * is not UTF-8 or a `rollover` this library does not know, Z_EPARSE for
 * a profile that is not one. */
z_result_t wz_capi_c_e2e_sender_new(wz_capi_c_owned_e2e_sender_t *this_,
                                    const char *profile_json,
                                    uint64_t first_counter,
                                    wz_capi_c_e2e_rollover_t rollover,
                                    z_owned_string_t *refusal);

/* Build the next frame of the message. `values_json` holds every header
 * field the sender and the mechanism do not supply, and may carry the
 * body as an "@body" member; `payload` is the body already serialized
 * (NULL only when `payload_len` is 0), and giving a body both ways is a
 * refusal. Z_OK for any call that was well formed, whether or not a
 * frame was built: read "ok" in the document. A frame that is not built
 * consumes no counter value. `out` holds a gravestone on every error
 * return. Z_ENULL for a null argument, Z_EINVAL for text that is not
 * UTF-8. */
z_result_t wz_capi_c_e2e_sender_wrap(
    const wz_capi_c_loaned_e2e_sender_t *this_, const char *values_json,
    const uint8_t *payload, size_t payload_len, z_owned_string_t *out);

/* The value the next frame carries. false, and nothing written, when
 * the largest value was sent and the sender does not wrap, or when an
 * argument is null. */
bool wz_capi_c_e2e_sender_next(const wz_capi_c_loaned_e2e_sender_t *this_,
                               uint64_t *out);

/* Make `value` the one the next frame carries. A value past the counter
 * field's width is accepted here and refused by the frame, as a start
 * value is. Z_ENULL for a null or empty handle. */
z_result_t wz_capi_c_e2e_sender_set(
    const wz_capi_c_loaned_e2e_sender_t *this_, uint64_t value);

const wz_capi_c_loaned_e2e_sender_t *wz_capi_c_e2e_sender_loan(
    const wz_capi_c_owned_e2e_sender_t *this_);
void wz_capi_c_e2e_sender_drop(wz_capi_c_moved_e2e_sender_t *this_);
void wz_capi_c_internal_e2e_sender_null(wz_capi_c_owned_e2e_sender_t *this_);
bool wz_capi_c_internal_e2e_sender_check(
    const wz_capi_c_owned_e2e_sender_t *this_);

/* ------------------------------------------------------------------ *
 * What one message may weigh (revision 6).
 *
 * A z_put, z_delete, z_publisher_put or z_publisher_delete whose message
 * is larger than this session sends is refused BEFORE anything leaves,
 * with WZ_CAPI_C_E_VALUE_TOO_LARGE rather than the Z_EINVAL it used to
 * share with every other refusal. A refused message uses no sequence
 * number: the next value goes out as if this one had not been asked, and
 * the session carries on. The same code answers a key the codec cannot
 * carry. The number is outside zenoh-c's Z_E* range, so no upstream code
 * can take it.
 * ------------------------------------------------------------------ */

#define WZ_CAPI_C_E_VALUE_TOO_LARGE (-100)

/* The most bytes of ONE encoded message this session sends, through
 * `out`. The count is the whole network message (header, key,
 * extensions, payload and their headers), so a value is a little smaller
 * than it, by the key and a few tens of bytes: use the number to say a
 * limit and to size values, and the code above to know a particular put
 * was over. Z_ENULL for a null or closed `session` or a null `out`. */
z_result_t wz_capi_c_session_max_message_bytes(const z_loaned_session_t *session,
                                               size_t *out);

/* ------------------------------------------------------------------ *
 * Group membership: zenoh-ext's Group / Member / GroupEvent (R2932).
 * Revision 3. Present only where Z_FEATURE_UNSTABLE_API is, as every
 * ze_ door is: upstream marks zenoh-ext's group unstable.
 *
 * WHY wz_capi_c_ AND NOT ze_. Upstream zenoh-c has NO group surface
 * at the pinned checkout, so there is no ze_ name to be a drop-in
 * for, and a ze_ name wz invented would be a guess about a symbol
 * upstream has not defined -- a wrong guess is a drop-in symbol with
 * the wrong meaning, which is worse than none.
 *
 * THE NAMING RULE. Each name here is what zenoh-c's own convention
 * for its zenoh-ext surface (the ze_advanced_* family) produces for
 * the Rust item, with ze_ spelt wz_capi_c_ (and ZE_ as WZ_CAPI_C_):
 *
 *   type T         ze_{owned,loaned,moved}_<t>_t, ze_<t>_loan,
 *                  ze_<t>_drop, ze_<t>_clone,
 *                  ze_internal_<t>_null / _check
 *   method T::m    ze_<t>_<m>(object, ...); a constructor takes its
 *                  out-parameter first: Group::join -> ze_group_join
 *   builder        ze_<t>_options_t + ze_<t>_options_default
 *   stream result  a ze_closure_<item> callback, as zenoh-c does
 *   enum E         ze_<e>_t with ZE_<E>_<VARIANT>
 *
 * So when upstream ships the surface, a caller renames wz_capi_c_ to
 * ze_ and the rest should match. The least certain names are the
 * member field readers (info, lease_ms, liveliness, refresh_ratio)
 * and the group_event readers: upstream keeps those fields private or
 * unpacks events with `match`, so those names apply the rule to a
 * FIELD rather than to a method upstream has.
 *
 * ONE C SESSION, ONE GROUP. A wz session reaches its peers through
 * one link each; the group you join is joined over every one of
 * them and over the session itself, and what these doors report is
 * the union: a member reached through two links is ONE member, and
 * JOIN / LEAVE / LEASE_EXPIRED fire when it enters or leaves the
 * union. A member only a lost link could see is reported
 * LEASE_EXPIRED when that link goes, not one lease later as upstream
 * would. Other groups joined on the same session see each other.
 *
 * STRINGS. A z_view_string_t written here borrows from the object it
 * was read from and is valid while that object is.
 *
 * THREADS. The event closure runs on a library thread, never on the
 * thread that called a door, and never twice at once for one group.
 * From inside it you may read the view, the size, the leader and any
 * member; wz_capi_c_group_subscribe answers Z_EBUSY_MUTEX there, and
 * wz_capi_c_group_wait_for_view_size answers at once rather than
 * waiting on a delivery the callback itself is holding up.
 * ------------------------------------------------------------------ */

#if defined(Z_FEATURE_UNSTABLE_API)

/* zenoh-ext MemberLiveliness. */
typedef int wz_capi_c_member_liveliness_t;
#define WZ_CAPI_C_MEMBER_LIVELINESS_AUTO 0
#define WZ_CAPI_C_MEMBER_LIVELINESS_MANUAL 1

/* zenoh-ext GroupEvent's variants. NEW_LEADER is declared and never
 * sent, upstream and here alike. */
typedef int wz_capi_c_group_event_kind_t;
#define WZ_CAPI_C_GROUP_EVENT_KIND_JOIN 0
#define WZ_CAPI_C_GROUP_EVENT_KIND_LEAVE 1
#define WZ_CAPI_C_GROUP_EVENT_KIND_LEASE_EXPIRED 2
#define WZ_CAPI_C_GROUP_EVENT_KIND_NEW_LEADER 3

/* Owned / loaned / moved. One pointer each: wz's own types, with no
 * upstream footprint to match. */
typedef struct wz_capi_c_owned_member_t { void *_handle; } wz_capi_c_owned_member_t;
typedef struct wz_capi_c_loaned_member_t { void *_handle; } wz_capi_c_loaned_member_t;
typedef struct wz_capi_c_moved_member_t { wz_capi_c_owned_member_t _this; } wz_capi_c_moved_member_t;
typedef struct wz_capi_c_owned_group_t { void *_handle; } wz_capi_c_owned_group_t;
typedef struct wz_capi_c_loaned_group_t { void *_handle; } wz_capi_c_loaned_group_t;
typedef struct wz_capi_c_moved_group_t { wz_capi_c_owned_group_t _this; } wz_capi_c_moved_group_t;

/* An event, lent to the event closure for the length of one call. */
typedef struct wz_capi_c_loaned_group_event_t wz_capi_c_loaned_group_event_t;

typedef struct wz_capi_c_owned_closure_member_t {
  void *_context;
  void (*_call)(const wz_capi_c_loaned_member_t *member, void *context);
  void (*_drop)(void *context);
} wz_capi_c_owned_closure_member_t;
typedef wz_capi_c_owned_closure_member_t wz_capi_c_loaned_closure_member_t;
typedef struct wz_capi_c_moved_closure_member_t {
  wz_capi_c_owned_closure_member_t _this;
} wz_capi_c_moved_closure_member_t;

typedef struct wz_capi_c_owned_closure_group_event_t {
  void *_context;
  void (*_call)(const wz_capi_c_loaned_group_event_t *event, void *context);
  void (*_drop)(void *context);
} wz_capi_c_owned_closure_group_event_t;
typedef wz_capi_c_owned_closure_group_event_t wz_capi_c_loaned_closure_group_event_t;
typedef struct wz_capi_c_moved_closure_group_event_t {
  wz_capi_c_owned_closure_group_event_t _this;
} wz_capi_c_moved_closure_group_event_t;

/* zenoh-ext Member's builder. `info` is consumed by
 * wz_capi_c_member_new on every path; NULL for none. */
typedef struct wz_capi_c_member_options_t {
  z_moved_string_t *info;
  uint64_t lease_ms;
  float refresh_ratio;
  wz_capi_c_member_liveliness_t liveliness;
  z_priority_t priority;
} wz_capi_c_member_options_t;

/* Upstream's Member::new defaults: no info, an 18 s lease refreshed
 * at 0.75 of it, AUTO liveliness, Z_PRIORITY_DATA_HIGH. */
void wz_capi_c_member_options_default(wz_capi_c_member_options_t *this_);

/* Member::new(id) plus the builder; NULL options are the defaults.
 * Z_EINVAL for an id with a wildcard (upstream refuses it too), an
 * info that is not UTF-8, or an unknown liveliness. */
z_result_t wz_capi_c_member_new(wz_capi_c_owned_member_t *this_,
                                const z_loaned_keyexpr_t *id,
                                wz_capi_c_member_options_t *options);

/* Member::id. */
z_result_t wz_capi_c_member_id(const wz_capi_c_loaned_member_t *this_,
                               z_view_string_t *out);
/* The member's info; false, with an empty view, when it has none. */
bool wz_capi_c_member_info(const wz_capi_c_loaned_member_t *this_,
                           z_view_string_t *out);
uint64_t wz_capi_c_member_lease_ms(const wz_capi_c_loaned_member_t *this_);
wz_capi_c_member_liveliness_t wz_capi_c_member_liveliness(
    const wz_capi_c_loaned_member_t *this_);
float wz_capi_c_member_refresh_ratio(const wz_capi_c_loaned_member_t *this_);

const wz_capi_c_loaned_member_t *wz_capi_c_member_loan(
    const wz_capi_c_owned_member_t *this_);
z_result_t wz_capi_c_member_clone(wz_capi_c_owned_member_t *dst,
                                  const wz_capi_c_loaned_member_t *this_);
void wz_capi_c_member_drop(wz_capi_c_moved_member_t *this_);
void wz_capi_c_internal_member_null(wz_capi_c_owned_member_t *this_);
bool wz_capi_c_internal_member_check(const wz_capi_c_owned_member_t *this_);

void wz_capi_c_closure_member(
    wz_capi_c_owned_closure_member_t *this_,
    void (*call)(const wz_capi_c_loaned_member_t *member, void *context),
    void (*drop)(void *context), void *context);
void wz_capi_c_internal_closure_member_null(wz_capi_c_owned_closure_member_t *this_);
bool wz_capi_c_internal_closure_member_check(
    const wz_capi_c_owned_closure_member_t *this_);
const wz_capi_c_loaned_closure_member_t *wz_capi_c_closure_member_loan(
    const wz_capi_c_owned_closure_member_t *this_);
void wz_capi_c_closure_member_call(const wz_capi_c_loaned_closure_member_t *closure,
                                   const wz_capi_c_loaned_member_t *member);
void wz_capi_c_closure_member_drop(wz_capi_c_moved_closure_member_t *this_);

void wz_capi_c_closure_group_event(
    wz_capi_c_owned_closure_group_event_t *this_,
    void (*call)(const wz_capi_c_loaned_group_event_t *event, void *context),
    void (*drop)(void *context), void *context);
void wz_capi_c_internal_closure_group_event_null(
    wz_capi_c_owned_closure_group_event_t *this_);
bool wz_capi_c_internal_closure_group_event_check(
    const wz_capi_c_owned_closure_group_event_t *this_);
const wz_capi_c_loaned_closure_group_event_t *wz_capi_c_closure_group_event_loan(
    const wz_capi_c_owned_closure_group_event_t *this_);
void wz_capi_c_closure_group_event_call(
    const wz_capi_c_loaned_closure_group_event_t *closure,
    const wz_capi_c_loaned_group_event_t *event);
void wz_capi_c_closure_group_event_drop(wz_capi_c_moved_closure_group_event_t *this_);

/* Which kind of event this is. */
wz_capi_c_group_event_kind_t wz_capi_c_group_event_kind(
    const wz_capi_c_loaned_group_event_t *this_);
/* The id of the member the event is about, for every kind. */
z_result_t wz_capi_c_group_event_member_id(const wz_capi_c_loaned_group_event_t *this_,
                                           z_view_string_t *out);
/* The joining member of a JOIN, valid for the callback; NULL for the
 * other kinds, for which upstream carries only an id. */
const wz_capi_c_loaned_member_t *wz_capi_c_group_event_member(
    const wz_capi_c_loaned_group_event_t *this_);

/* Group::join. `member` is consumed on every path; `this_` holds a
 * gravestone on failure. Z_EINVAL for a group or member id that is not
 * a canonical, wildcard-free key expression. */
z_result_t wz_capi_c_group_join(wz_capi_c_owned_group_t *this_,
                                const z_loaned_session_t *session,
                                const z_loaned_keyexpr_t *group,
                                wz_capi_c_moved_member_t *member);
/* Group::group_id and Group::local_member_id. */
z_result_t wz_capi_c_group_group_id(const wz_capi_c_loaned_group_t *this_,
                                    z_view_string_t *out);
z_result_t wz_capi_c_group_local_member_id(const wz_capi_c_loaned_group_t *this_,
                                           z_view_string_t *out);
/* Group::size: every member, this one included. */
size_t wz_capi_c_group_size(const wz_capi_c_loaned_group_t *this_);
/* Group::view: `callback` once per member, ordered by id and this
 * member included, on the calling thread; then it is dropped. */
z_result_t wz_capi_c_group_view(const wz_capi_c_loaned_group_t *this_,
                                wz_capi_c_moved_closure_member_t *callback);
/* Group::leader: the member with the greatest id, as an owned copy. */
z_result_t wz_capi_c_group_leader(const wz_capi_c_loaned_group_t *this_,
                                  wz_capi_c_owned_member_t *out);
/* Group::subscribe: later events go to `callback`. Last-wins, as
 * upstream's is; the replaced closure is dropped before this returns. */
z_result_t wz_capi_c_group_subscribe(const wz_capi_c_loaned_group_t *this_,
                                     wz_capi_c_moved_closure_group_event_t *callback);
/* Group::wait_for_view_size: whether the view reached `size` within
 * `timeout_ms`. */
bool wz_capi_c_group_wait_for_view_size(const wz_capi_c_loaned_group_t *this_,
                                        size_t size, uint64_t timeout_ms);
const wz_capi_c_loaned_group_t *wz_capi_c_group_loan(const wz_capi_c_owned_group_t *this_);
/* Leave the group. The event closure's drop has run when this returns,
 * unless it is called from inside that closure. */
void wz_capi_c_group_drop(wz_capi_c_moved_group_t *this_);
void wz_capi_c_internal_group_null(wz_capi_c_owned_group_t *this_);
bool wz_capi_c_internal_group_check(const wz_capi_c_owned_group_t *this_);

#endif /* Z_FEATURE_UNSTABLE_API */

/* ------------------------------------------------------------------ *
 * The observation plane (revision 8).
 *
 * Four instruments zenoh-c has not, each a feature of the library that
 * is OFF in a build made as the reference is: a library built without
 * one does not export its doors, and a program that calls one it was
 * not built with fails to link, which is the report it is owed. They
 * are the node's own (one clock registry, one event log, one
 * supervisor, one resource sampler for the process), and the zenoh-pico
 * ABI's wz_ext_* doors drive the same four, so a program that moves
 * between the two ABIs finds the same behaviour under another prefix.
 *
 * The library holds no thread and no timer for any of them: the
 * program calls `check` and `poll` on its own cadence.
 *
 * Codes. Z_EINVAL for a value the door does not take, Z_ENULL for a
 * null pointer it needs, Z_EGENERIC for a refusal with no more to say
 * (a snapshot not yet taken, a checkpoint that cannot be stopped while
 * its hook runs), and WZ_CAPI_C_E_FULL for a bounded thing with no room
 * (every clock registered, a full log that drops its newest event, a
 * buffer smaller than the record). The last is wz's own and outside
 * zenoh-c's Z_E* range, as WZ_CAPI_C_E_VALUE_TOO_LARGE is.
 * ------------------------------------------------------------------ */

#define WZ_CAPI_C_E_FULL (-101)

/* ---- The clock a program registers (feature clock-source) ---------- *
 *
 * `z_timestamp_new` stamps with the registered clock in place of the
 * system clock. The read callback returns 0 with `*secs` (since the
 * Unix epoch) and `*nanos` (within the second, below 10^9) written, or
 * any other value when the clock cannot say what time it is; it is
 * called from whichever thread stamps, possibly several at once. After
 * unregister returns the library calls it no more, though a call
 * already running on another thread may still be inside it.
 *
 * The library cannot tell whether the clock follows a reference. The
 * program can, and reports it; a build whose clock-quality-stamping
 * policy is trusted-only stamps nothing until it has. */

typedef int8_t (*wz_capi_c_clock_read_fn)(void *context, uint64_t *secs, uint32_t *nanos);

typedef uint8_t wz_capi_c_clock_event_t;
#define WZ_CAPI_C_CLOCK_SYNC_ACQUIRED 0
#define WZ_CAPI_C_CLOCK_SYNC_LOST 1
#define WZ_CAPI_C_CLOCK_HOLDOVER_EXPIRED 2

/* Register `read` after the clocks already registered (the first that
 * can say what time it is answers); `out_handle`, when not NULL,
 * receives the handle unregister takes. Z_ENULL for a NULL `read`,
 * WZ_CAPI_C_E_FULL when every clock the build allows is taken. */
z_result_t wz_capi_c_clock_source_register(wz_capi_c_clock_read_fn read, void *context,
                                           uint32_t *out_handle);
/* Z_EINVAL for a handle that is not registered. */
z_result_t wz_capi_c_clock_source_unregister(uint32_t handle);
/* One of the three events above; Z_EINVAL for another value. Reporting
 * what is already so is not an error. */
z_result_t wz_capi_c_clock_report(wz_capi_c_clock_event_t event);

/* ---- The event log (feature event-ring) ---------------------------- *
 *
 * An event is a level, a source and up to the build's integers. It
 * carries no text: the format it is read with is a constant the reader
 * holds, keyed by the source. One ring for the process; what a full
 * one gives up is the build's event-ring-full policy.
 *
 * A reader keeps its own cursor (a sequence number, 0 at the start), so
 * any number of programs read one log and none takes an event from
 * another. A log that has wrapped tells the reader how many it missed
 * before it hands over the oldest left. Under drop-newest nothing is
 * freed by reading: the program says how far it is done with
 * (release), and that makes room. */

#define WZ_CAPI_C_EVENT_RECORD 0 /* an event */
#define WZ_CAPI_C_EVENT_EMPTY 1  /* nothing newer than the cursor */
#define WZ_CAPI_C_EVENT_LOST 2   /* events were overwritten; `sequence` says how many */

/* The level and the sources the library writes with; a program's own
 * levels and sources are below. */
#define WZ_CAPI_C_EVENT_LEVEL_LIBRARY 255
#define WZ_CAPI_C_EVENT_SOURCE_LIBRARY 0xFF00
/* A supervised checkpoint missed its deadline; one integer, its number. */
#define WZ_CAPI_C_EVENT_SOURCE_SUPERVISION_EXPIRED 0xFF01

typedef struct wz_capi_c_event_t {
    uint8_t kind;
    uint8_t level;
    uint8_t arg_count; /* integers the event carries (more than fit the buffer is allowed) */
    uint8_t reserved;
    uint16_t source;
    uint16_t reserved2;
    uint64_t sequence; /* the event's number; for LOST, how many are gone */
    uint64_t timestamp; /* NTP64, or 0 where the clock did not know the date */
} wz_capi_c_event_t;

/* WZ_CAPI_C_E_FULL when a full log under drop-newest refused the event
 * (it was counted); Z_ENULL for a NULL `args` with a count. */
z_result_t wz_capi_c_event_emit(uint8_t level, uint16_t source, const uint64_t *args,
                                size_t arg_count);
/* Read the event at `*cursor` into `out`, its integers into `args` (up
 * to `args_capacity`; `args` may be NULL when that is 0). `*cursor`
 * moves past the event read or past the events lost. Z_ENULL for a
 * NULL `cursor` or `out`, or a NULL `args` with a capacity. */
z_result_t wz_capi_c_event_read(uint64_t *cursor, wz_capi_c_event_t *out, uint64_t *args,
                                size_t args_capacity);
/* Every event before sequence number `upto` has been read and may be
 * overwritten. Only forward. */
z_result_t wz_capi_c_event_release(uint64_t upto);
/* Events a full log refused under drop-newest; 0 under overwrite-oldest. */
uint32_t wz_capi_c_event_dropped(void);

/* ---- The supervisor (feature supervision) -------------------------- *
 *
 * A program that must keep making progress starts a checkpoint with a
 * timeout and feeds it on every pass, and calls check on its own
 * cadence; check runs the hook once for each checkpoint whose deadline
 * has passed. The supervisor is healthy only while every supervised
 * checkpoint has been fed in time, so a node that feeds a hardware
 * watchdog feeds it from healthy and from nowhere else. Time is
 * milliseconds since the first call, in 32 bits that wrap, which the
 * comparison survives.
 *
 * The hook runs on the thread that called check, with no lock of the
 * library held, so it may call any of these doors; stop on the
 * checkpoint whose hook is running is refused until the hook returns.
 * The expiry is written to the event log first, in a build that has it. */

typedef void (*wz_capi_c_supervision_hook_fn)(void *context, uint8_t checkpoint);

#define WZ_CAPI_C_SUPERVISION_DISARMED 0
#define WZ_CAPI_C_SUPERVISION_ARMED 1
#define WZ_CAPI_C_SUPERVISION_EXPIRING 2
#define WZ_CAPI_C_SUPERVISION_EXPIRED 3
#define WZ_CAPI_C_SUPERVISION_NO_SUCH_CHECKPOINT 255

/* Clear the hook with a NULL `hook`. With none set an expired checkpoint
 * is still marked expired and makes the supervisor unhealthy. */
z_result_t wz_capi_c_supervision_set_hook(wz_capi_c_supervision_hook_fn hook, void *context);
/* A deadline `timeout_ms` after now and after each feed. Z_EINVAL for a
 * checkpoint the build does not have, or a timeout of 0 or past
 * 2147483647 ms. A checkpoint already supervised is left as it is. */
z_result_t wz_capi_c_supervision_start(uint8_t checkpoint, uint32_t timeout_ms);
/* Start the deadline again; a checkpoint that is not armed ignores it.
 * Z_EINVAL for a checkpoint the build does not have. */
z_result_t wz_capi_c_supervision_feed(uint8_t checkpoint);
/* Z_EGENERIC when its hook is running; Z_EINVAL for a checkpoint the
 * build does not have. */
z_result_t wz_capi_c_supervision_stop(uint8_t checkpoint);
z_result_t wz_capi_c_supervision_check(void);
/* 1 when at least one checkpoint is supervised and every supervised
 * one is armed, 0 otherwise. */
uint8_t wz_capi_c_supervision_healthy(void);
uint8_t wz_capi_c_supervision_state(uint8_t checkpoint);

/* ---- The resource snapshot (feature resource-snapshot) ------------- *
 *
 * A fixed-layout, versioned record (it starts with its own layout
 * version and size, little-endian, so a reader of an older build can
 * tell a newer one): the CPU use, the heap and the tasks the platform
 * reports, and how the messages the session received were spaced. The
 * platform is the program's: it sets a source that answers what it can,
 * and a part it cannot answer is marked unavailable in the record, not
 * read as zero. poll takes a snapshot when the build's period has
 * passed since the last; read copies the latest out.
 *
 * The source runs on the thread that called poll, with no lock of the
 * library held. Time is microseconds since the first call, in 32 bits
 * that wrap. A hosted node serves the same record as JSON at
 * wz/@/<zid>/snapshot on its own. */

typedef struct wz_capi_c_resource_reading_t {
    uint8_t available; /* WZ_CAPI_C_SNAPSHOT_HAS_*: which of the readings below the source answers */
    uint8_t reserved;
    uint16_t cpu_permille; /* busy share of the CPU since the last reading, in thousandths */
    uint16_t tasks;
    uint16_t reserved2;
    uint64_t heap_in_use;
    uint64_t heap_high_water;
} wz_capi_c_resource_reading_t;

#define WZ_CAPI_C_SNAPSHOT_HAS_CPU 1
#define WZ_CAPI_C_SNAPSHOT_HAS_HEAP 2
#define WZ_CAPI_C_SNAPSHOT_HAS_TASKS 4

/* Fill `out` and return 0, or return anything else when the source
 * cannot answer at all, which takes the snapshot with no part available. */
typedef int8_t (*wz_capi_c_snapshot_source_fn)(void *context, wz_capi_c_resource_reading_t *out);

/* Clear the source with a NULL `read`. With none set a snapshot is
 * still taken, with the message counts and no part of the platform's. */
z_result_t wz_capi_c_snapshot_set_source(wz_capi_c_snapshot_source_fn read, void *context);
/* 1 when a snapshot was taken, 0 when none was due, Z_ENULL for a NULL
 * or closed session. The first call takes one. */
z_result_t wz_capi_c_snapshot_poll(const z_loaned_session_t *session);
/* The bytes read writes; it grows with the build's histogram buckets. */
size_t wz_capi_c_snapshot_size(void);
/* Copy the latest snapshot into `out` (`capacity` bytes) and its length
 * into `*length`. Z_EGENERIC before the first snapshot, WZ_CAPI_C_E_FULL
 * when `capacity` is less than wz_capi_c_snapshot_size, Z_ENULL for a
 * NULL `out` or `length`. */
z_result_t wz_capi_c_snapshot_read(uint8_t *out, size_t capacity, size_t *length);

/* The conformance digest of this build (docs/build-configuration.md,
 * decision C15): "sha256:" and 64 lowercase hex digits, NUL-terminated and
 * static. It is the digest wz_config.py prints in the conformance statement
 * of the configuration the library was built with (every capability of the
 * ABI and whether the build has it, every limit and policy value), so a
 * tester holding a statement can tell whether this library is that build.
 * Present in every build. */
const char *wz_capi_c_conformance_digest(void);

/* A NODE'S LIFECYCLE VERBS FROM A CLIENT (revision 10): the key a verb is
 * asked by, and the answer read back. In builds with the `lifecycle-doors`
 * feature, which is OFF by default (zenoh-c has no such doors): a client that
 * asks a node's verbs builds the library with it on. Both are pure calls over the caller's
 * memory, with no session and no allocation, and both are the library's one
 * copy: the key is the one a declared node's querier stated with the same
 * words asks (both are held to scripts/lib/verb_key_vectors.txt), and the
 * reading is the one the node's own HOST-WZ-VERDICT line makes.
 *
 *     wz_capi_c_lifecycle_words_t w = { .verb = "close", .of = node_zid,
 *                                       .about = peer_zid };
 *     char key[WZ_CAPI_C_LIFECYCLE_KEY_MAX]; const char *why = NULL;
 *     if (wz_capi_c_lifecycle_key(&w, key, sizeof key, &why) == Z_OK)
 *         ... z_get(session, key, ...), then for each reply's payload:
 *     wz_capi_c_lifecycle_read_t r;
 *     wz_capi_c_lifecycle_read(bytes, len, &r);
 *     if (r.kind == WZ_CAPI_C_LIFECYCLE_VERDICT) ... r.verdict, r.reason */

/* The bytes a key buffer needs: the longest key (a reset of u64's largest
 * generation between two 32-digit zids) and its NUL. */
#define WZ_CAPI_C_LIFECYCLE_KEY_MAX 110

/* The words a verb's key is made from; every pointer a NUL-terminated C
 * string. `verb` is open, close, reset or status; `of` the zid of the node
 * asked and `about` the zid of the peer, lower-case hex as z_id_to_string
 * prints them; `whatami` client, peer or router (NULL: client); a reset takes
 * `generation` with `has_generation` true, every other verb none; `mode` dial
 * or passive, an open's (NULL: dial). */
typedef struct wz_capi_c_lifecycle_words_t {
  const char *verb;
  const char *of;
  const char *about;
  const char *whatami;
  bool has_generation;
  uint64_t generation;
  const char *mode;
} wz_capi_c_lifecycle_words_t;

/* Make the key `@/<of>/<whatami>/session/<verb>/<about>`, with
 * `<generation>/` before `<about>` for a reset and `passive/` for a passive
 * open, into `out` (`out_len` bytes, NUL included). Z_OK; Z_EINVAL when the
 * words make no key, `*refusal` (when not NULL) then naming why with one of
 * no-such-verb, no-such-role, no-such-mode, of-is-no-zid, about-is-no-zid,
 * reset-takes-a-generation, only-reset-takes-a-generation,
 * only-open-is-passive, or NULL for a buffer shorter than the key; Z_ENULL
 * for a NULL `words`, `verb`, `of`, `about` or `out`, or a word that is not
 * UTF-8. Nothing is written to `out` on a refusal. */
z_result_t wz_capi_c_lifecycle_key(const wz_capi_c_lifecycle_words_t *words,
                                   char *out, size_t out_len,
                                   const char **refusal);

/* What an answer was read as. */
typedef int32_t wz_capi_c_lifecycle_kind_t;
/* No document a node writes: empty, another document, cut short. */
#define WZ_CAPI_C_LIFECYCLE_UNREADABLE 0
/* A verb's verdict on a peer, in band or on the control channel. */
#define WZ_CAPI_C_LIFECYCLE_VERDICT 1
/* The control channel's answer to `whoami`. */
#define WZ_CAPI_C_LIFECYCLE_WHOAMI 2
/* The control channel's answer to a line that is no command. */
#define WZ_CAPI_C_LIFECYCLE_ERROR 3

/* An answer read back. Every `const char *` is a static string this library
 * owns, or NULL where the kind does not carry it: `verdict` the verdict word
 * (opening, closing, resetting, already_closed, not_found, duplicate, status,
 * refused), `reason` a refusal's sentence, byte for byte the vocabulary's
 * `verdicts.reasons`, `error` the control channel's error word. A `has_` flag
 * says whether the number beside it was in the answer: `links` on closing and
 * resetting, `generation` on duplicate, `open` and `closing` (the node's links
 * to the peer) and `intent` on status. `zid` is the node's zid on whoami,
 * NUL-terminated, in the spelling a key and a config's `id` take (lower-case
 * hex, no leading zero, no `+`), and empty otherwise. The same struct, member
 * for member, is wz_dissect_lifecycle_answer in wz_dissect.h, filled by
 * wz_dissect_lifecycle_read: one reading, for a process that links no
 * session library. */
typedef struct wz_capi_c_lifecycle_read_t {
  wz_capi_c_lifecycle_kind_t kind;
  const char *verdict;
  const char *reason;
  const char *error;
  bool has_links;
  uint32_t links;
  bool has_generation;
  uint64_t generation;
  bool has_held;
  uint32_t open;
  uint32_t closing;
  bool has_intent;
  bool intent;
  char zid[33];
} wz_capi_c_lifecycle_read_t;

/* Read an answer a node gave: a verb's reply payload in band, or one line its
 * control channel answered with (line end cut). `out` is filled from scratch.
 * An answer that is no document a node writes reads as
 * WZ_CAPI_C_LIFECYCLE_UNREADABLE, which is a reading and still Z_OK. Only the
 * node's own spelling is read: its members in the order the node writes them
 * (`verdict` first), with no white space, so the same members in another order
 * are UNREADABLE. Z_ENULL for a NULL `out`, or a NULL `bytes` with a non-zero
 * `len`. */
z_result_t wz_capi_c_lifecycle_read(const uint8_t *bytes, size_t len,
                                    wz_capi_c_lifecycle_read_t *out);

/* THE IDENTITY A CLIENT PRESENTS (revision 11): a P-256 key and a
 * certificate self-signed over it, made on this computer by the contract of a
 * declared node's `--make-identity`, and the zid the key names. A pure call
 * over two paths: no session, no runtime. Call it once, before the first
 * session over TLS:
 *
 *     wz_capi_c_identity_t id;
 *     if (wz_capi_c_identity_make("me.crt", "me.key", &id) == Z_OK)
 *         ... the config names me.crt and me.key as
 *             transport/link/tls/connect_certificate and connect_private_key,
 *             enable_mtls true, and `id` the zid id.zid
 *
 * Neither file there: both are made, the key first and readable by its owner
 * alone (0600), each created exclusively, so nothing is ever replaced. Both
 * there: nothing is made. Only one there: nothing is made, and the missing one
 * is named. Either way the two files are then read back as the TLS link reads
 * them, the key must be the certificate's own and its owner's alone, and the
 * zid is the one a peer computes from the certificate. In builds with the
 * `identity-make` feature, on unix. The feature is OFF by default (the
 * certificate writer it links is large for a door called once): a program
 * that makes its identity builds the library with it on. */

/* The bytes the zid's text takes: at most 32 hex digits and its NUL. */
#define WZ_CAPI_C_IDENTITY_ZID_MAX 33

/* An identity made or found, or why there is none. `made`: this call made both
 * files. `zid`: lower-case hex as z_id_to_string prints it, NUL-terminated,
 * empty on a refusal. On a refusal `file` is "the certificate", "the private
 * key" or "the identity" and `reason` the contract's sentence, static strings
 * this library owns; both NULL otherwise. */
typedef struct wz_capi_c_identity_t {
  bool made;
  char zid[WZ_CAPI_C_IDENTITY_ZID_MAX];
  const char *file;
  const char *reason;
} wz_capi_c_identity_t;

/* Make the identity whose certificate is the file `certificate` and whose
 * private key is the file `private_key`, both PEM, unless both are there, and
 * write the zid into `out`, filled from scratch. Z_OK when the identity is
 * there; Z_EIO when it is not, with `file` and `reason` (nothing is made then,
 * and nothing that was there changes); Z_ENULL for a NULL argument. */
z_result_t wz_capi_c_identity_make(const char *certificate,
                                   const char *private_key,
                                   wz_capi_c_identity_t *out);

/* ------------------------------------------------------------------ *
 * THE STATEMENTS OF A CALL BEYOND THE ZENOH-C OPTIONS (revision 12), in
 * builds with the `switch-doors` feature, which is OFF by default.
 *
 * Four things a call can state that zenoh-c has no field for:
 *
 *   - the links an entity may use (a subscriber, a queryable, a
 *     publisher, a put, a get): `link_mask`, one bit per link slot;
 *     slot 0 is the link the session dialled and listener n is slot
 *     n + 1. No bit set is no restriction: every link, as zenoh-c does;
 *   - a retry for a publish that found no link with room: `attempts`
 *     further passes, `delay_ms` apart (255 and 65535 at most);
 *   - an all-or-none publish: it reaches every link it may use or none;
 *   - the one node a get or a querier is addressed to: `target`.
 *
 * They are not fields of the z_* option structs, whose layout is
 * upstream's, so each is made through a door that takes what its z_*
 * twin takes and one more argument, a pointer to the statements. NULL
 * and a struct filled by its _default function state nothing, and a
 * call that states nothing is the call the z_* function makes.
 *
 * EACH STATEMENT IS A POLICY OF THE SESSION MODEL, OFF IN A BUILD MADE
 * AS UPSTREAM IS (entity-link-restriction, publisher-admission-retry,
 * multi-route-atomic-tx, targeted-query). A stated value is refused
 * before anything is sent or declared while its policy is off, with
 * WZ_CAPI_C_E_POLICY_OFF; the same call is taken by a build whose
 * policy is on. Z_EINVAL says the value itself is wrong whatever the
 * build: a retry of no pass, no delay, more than 255 passes or 65535
 * ms, or a target of no byte. A refused declaration leaves its
 * out-parameter in the gravestone state; a closure, a payload and the
 * owned fields of the options are consumed on a refusal as on a
 * success, which is what the z_* twins do on every path.
 *
 * A session that is a node (the `router-node` role) writes to its
 * faces by its own tables and reads none of these statements: a call
 * stating one there answers Z_EUNAVAILABLE, the code every operation a
 * node does not carry answers, and sends or declares nothing.
 * ------------------------------------------------------------------ */

/* A call stated something this build's policy does not allow. Nothing
 * was sent or declared. Outside zenoh-c's Z_E* range, as
 * WZ_CAPI_C_E_VALUE_TOO_LARGE is. */
#define WZ_CAPI_C_E_POLICY_OFF (-102)

/* What a subscriber or a queryable declaration states. */
typedef struct wz_capi_c_entity_ext_t {
  uint64_t link_mask;
} wz_capi_c_entity_ext_t;

/* What a put, a delete or a publisher declaration states. `attempts` zero
 * states no retry; `all_or_none` non-zero states the all-or-none form. */
typedef struct wz_capi_c_publish_ext_t {
  uint64_t link_mask;
  uint32_t attempts;
  uint32_t delay_ms;
  uint8_t all_or_none;
} wz_capi_c_publish_ext_t;

/* What a get or a querier declaration states. `has_target` non-zero
 * addresses the query to the node whose identity `target` holds, as
 * z_info_zid reports it for a session; `target` is read only then. */
typedef struct wz_capi_c_query_ext_t {
  uint64_t link_mask;
  uint8_t has_target;
  z_id_t target;
} wz_capi_c_query_ext_t;

/* Write the statement of nothing: no link restriction, no retry, no
 * all-or-none form, no target. NULL is no write. */
void wz_capi_c_entity_ext_default(wz_capi_c_entity_ext_t *this_);
void wz_capi_c_publish_ext_default(wz_capi_c_publish_ext_t *this_);
void wz_capi_c_query_ext_default(wz_capi_c_query_ext_t *this_);

/* z_put, z_delete and z_declare_publisher with a statement (`ext`, NULL
 * for none). Every put and delete on a declared publisher is made as the
 * declaration stated. */
z_result_t wz_capi_c_put_ext(const z_loaned_session_t *session,
                             const z_loaned_keyexpr_t *key_expr,
                             z_moved_bytes_t *payload, z_put_options_t *options,
                             const wz_capi_c_publish_ext_t *ext);
z_result_t wz_capi_c_delete_ext(const z_loaned_session_t *session,
                                const z_loaned_keyexpr_t *key_expr,
                                z_delete_options_t *options,
                                const wz_capi_c_publish_ext_t *ext);
z_result_t wz_capi_c_declare_publisher_ext(const z_loaned_session_t *session,
                                           z_owned_publisher_t *publisher,
                                           const z_loaned_keyexpr_t *key_expr,
                                           z_publisher_options_t *options,
                                           const wz_capi_c_publish_ext_t *ext);

/* z_get and z_declare_querier with a statement (`ext`, NULL for none).
 * Every get on a declared querier is asked as the declaration stated. */
z_result_t wz_capi_c_get_ext(const z_loaned_session_t *session,
                             const z_loaned_keyexpr_t *key_expr,
                             const char *parameters,
                             z_moved_closure_reply_t *callback,
                             z_get_options_t *options,
                             const wz_capi_c_query_ext_t *ext);
z_result_t wz_capi_c_declare_querier_ext(const z_loaned_session_t *session,
                                         z_owned_querier_t *querier,
                                         const z_loaned_keyexpr_t *key_expr,
                                         z_querier_options_t *options,
                                         const wz_capi_c_query_ext_t *ext);

/* z_declare_subscriber and z_declare_queryable limited to the links `ext`
 * names (NULL for no limit): the entity is declared to the nodes behind
 * those links only, and a link that comes up later is declared to only if
 * its slot is named. */
z_result_t wz_capi_c_declare_subscriber_ext(
    const z_loaned_session_t *session, z_owned_subscriber_t *subscriber,
    const z_loaned_keyexpr_t *key_expr, z_moved_closure_sample_t *callback,
    z_subscriber_options_t *options, const wz_capi_c_entity_ext_t *ext);
z_result_t wz_capi_c_declare_queryable_ext(
    const z_loaned_session_t *session, z_owned_queryable_t *queryable,
    const z_loaned_keyexpr_t *key_expr, z_moved_closure_query_t *callback,
    z_queryable_options_t *options, const wz_capi_c_entity_ext_t *ext);

/* Revision 13: z_liveliness_declare_token and
 * z_liveliness_declare_subscriber limited to the links `ext` names (NULL
 * for no limit), as an entity above is. A token is announced to the nodes
 * behind those links only, and a multicast group, which no slot names, is
 * not told of it; a liveliness subscriber on the session itself hears it
 * whatever the restriction says. */
z_result_t wz_capi_c_liveliness_declare_token_ext(
    const z_loaned_session_t *session, z_owned_liveliness_token_t *token,
    const z_loaned_keyexpr_t *key_expr,
    const z_liveliness_token_options_t *options,
    const wz_capi_c_entity_ext_t *ext);
z_result_t wz_capi_c_liveliness_declare_subscriber_ext(
    const z_loaned_session_t *session, z_owned_subscriber_t *subscriber,
    const z_loaned_keyexpr_t *key_expr, z_moved_closure_sample_t *callback,
    z_liveliness_subscriber_options_t *options,
    const wz_capi_c_entity_ext_t *ext);

#ifdef __cplusplus
}
#endif

#endif /* WZ_CAPI_C_H */
