/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

#define WZ_CAPI_C_ABI_REVISION 4

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
 * The config verdict as ROWS (ZA-3469). Revision 4.
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

#ifdef __cplusplus
}
#endif

#endif /* WZ_CAPI_C_H */
