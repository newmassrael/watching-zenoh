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
 * `capi_c_abi_pin.py` is what keeps it honest. It reads the symbol set
 * out of the BUILT library and the number by CALLING it, so a symbol
 * added without moving this number is red rather than shipped.
 * ------------------------------------------------------------------ */

#define WZ_CAPI_C_ABI_REVISION 1

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
 * ------------------------------------------------------------------ */

/* How many config keys wz honours when reading a stock zenoh config. */
size_t wz_capi_c_config_honoured_count(void);

/* The name of honoured key `index`, or NULL past the end. Walk it until
 * NULL rather than trusting the count. */
const char *wz_capi_c_config_honoured(size_t index);

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

#ifdef __cplusplus
}
#endif

#endif /* WZ_CAPI_C_H */
