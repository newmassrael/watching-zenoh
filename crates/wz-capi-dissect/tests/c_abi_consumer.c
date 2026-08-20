/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * R311y587 — the C consumer the dissection ABI exists for, as a GATE.
 *
 * R311y586 proved this by hand: gcc against the header, link the cdylib, read
 * the tree. A by-hand proof is exactly the shape that rots — it is true on the
 * day it is run and silently stops being run. The Rust tests in the crate
 * cover the functions; only a real C translation unit covers the things that
 * are ONLY true across the boundary: that the header compiles, that the
 * symbols export under the names it declares, that the calling convention
 * agrees, and that a string allocated in Rust can be released from C.
 *
 * Driven by run-ci Layer C1bo. Exit 0 = pass; every failure prints what it
 * expected before returning non-zero, because a lane that fails without
 * saying why costs a whole round to diagnose.
 */
#include "wz_dissect.h"

#include <stdio.h>
#include <string.h>

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("  C1bo FAIL: ");                                           \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
            return 1;                                                          \
        }                                                                      \
    } while (0)

int main(void) {
    /* The symbol/memory-contract revision. A consumer refuses a library whose
     * memory rules moved; this asserts the value the header was written for. */
    /* R311y887 -- 8 since wz_dissect_pcap_census_where_limited joined the
     * symbol set. This header's contract is the symbol SET, not a symbol's
     * signature, so adding one moves the revision; the two statements of that
     * contract had drifted and were reconciled in R311y748. The census DOCUMENT
     * gained a dropped_by_limits key in R311y885 and the WZ_DISSECT_LIMITS_*
     * constants arrived here, and neither moves this number: a document key is
     * read by name and a constant is compiled in, while a symbol is linked. */
    CHECK(wz_dissect_abi_version() == 8, "abi version is %d, expected 8",
          wz_dissect_abi_version());

    /* A KeepAlive: one header byte, the smallest complete transport message,
     * so what is under test is the boundary and not a codec. */
    unsigned char keepalive[1] = {0x04};
    char *json = NULL;
    int rc = wz_dissect_transport_message(keepalive, sizeof keepalive, 0, &json);
    CHECK(rc == WZ_DISSECT_OK, "transport_message rc=%d", rc);
    CHECK(json != NULL, "OK came back with no string");
    CHECK(strstr(json, "\"name\"") != NULL, "no field names in %s", json);
    CHECK(strstr(json, "KeepAlive") != NULL, "not a KeepAlive tree: %s", json);
    /* Released through the LIBRARY's free, not the C runtime's: the allocator
     * that made it is the only one that may release it. */
    wz_dissect_string_free(json);

    /* Freeing null is a no-op, so a consumer's cleanup path needs no guard of
     * its own -- the commonest source of a double free at an FFI seam. */
    wz_dissect_string_free(NULL);

    /* A decode failure must be an ERROR CODE. A panic unwinding across
     * extern "C" is undefined behaviour, and this call is what would trip it. */
    char *none = NULL;
    unsigned char empty[1] = {0};
    rc = wz_dissect_transport_message(empty, 0, 0, &none);
    CHECK(rc == WZ_DISSECT_ERR_DECODE, "empty input rc=%d, expected DECODE", rc);
    CHECK(none == NULL, "an error handed back a string");

    /* Nulls are refused before anything is dereferenced. */
    rc = wz_dissect_transport_message(NULL, 0, 0, &none);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null bytes rc=%d", rc);
    rc = wz_dissect_transport_message(keepalive, 1, 0, NULL);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null out rc=%d", rc);

    /* A DAMAGED capture is diagnosed, not crashed on and not silently empty.
     * R311y608 -- the fixture is a TRUNCATED pcapng: the magic and nothing
     * after it. It used to stand for "pcapng", which the reader refused
     * wholesale; it now dispatches on the magic and reads both formats, so what
     * is left here is the claim that actually matters at a C boundary -- a
     * malformed file comes back as a CODE rather than unwinding through it. */
    unsigned char truncated[8] = {0x0A, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0};
    char *summary = NULL;
    rc = wz_dissect_pcap_summary(truncated, sizeof truncated, &summary);
    CHECK(rc == WZ_DISSECT_ERR_BAD_CAPTURE, "truncated pcapng rc=%d", rc);
    CHECK(summary == NULL, "a bad capture handed back a string");

    /* R311y608 -- and a WHOLE capture comes back with its health report. The
     * three counters this reads (`health`, `fragment_stats`,
     * `capture_reported_drops`) had no consumer outside wz-capture's own tests
     * for three rounds; this is the C side of the reader that closed them.
     *
     * The file is a classic pcap laid out by hand -- 24-byte global header
     * (magic, 2.4, zone, sigfigs, snaplen, linktype=1) then one record header
     * (ts_sec, ts_usec, caplen, origlen) and four bytes too short to be a
     * frame. What is under test is the SUMMARY's shape, so the packet only has
     * to reach the walker, not decode. */
    unsigned char pcap[24 + 16 + 4] = {
        0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
        /* record: ts_sec=0, ts_usec=0, caplen=4, origlen=4 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        /* the four packet bytes */
        0x00, 0x00, 0x00, 0x00};
    rc = wz_dissect_pcap_summary(pcap, sizeof pcap, &summary);
    CHECK(rc == WZ_DISSECT_OK, "whole pcap rc=%d", rc);
    CHECK(summary != NULL, "OK came back with no string");
    CHECK(strstr(summary, "\"health\"") != NULL, "no health report: %s", summary);
    /* null and 0 are different answers: the classic format has nowhere to
     * record a drop count, so silence must not read as a clean bill. */
    CHECK(strstr(summary, "\"capture_reported_drops\":null") != NULL,
          "silence reported as a figure: %s", summary);
    wz_dissect_string_free(summary);

    /* R311y748 -- and the BOUNDED door is reachable from C at all. A
     * `#[no_mangle] pub extern "C"` function that only Rust tests call is not
     * known to be linkable: the Rust side proves what the caps DO (an eviction
     * that the unbounded door cannot report), and this proves the symbol
     * survives into the cdylib a consumer ships against. The two claims are
     * separate and this file owns the second one.
     *
     * The same hand-laid pcap: too small for any cap to bite, which is right
     * here -- what is under test is the symbol and its contract, not the
     * bound. */
    char *bounded = NULL;
    rc = wz_dissect_pcap_summary_bounded(pcap, sizeof pcap, &bounded);
    CHECK(rc == WZ_DISSECT_OK, "bounded summary rc=%d", rc);
    CHECK(bounded != NULL, "OK came back with no string");
    CHECK(strstr(bounded, "\"dropped_by_limits\"") != NULL,
          "the bounded door must still report what its caps cost: %s", bounded);
    wz_dissect_string_free(bounded);

    /* Same memory rule, same refusals: a bad capture is a code here too. */
    bounded = NULL;
    rc = wz_dissect_pcap_summary_bounded(truncated, sizeof truncated, &bounded);
    CHECK(rc == WZ_DISSECT_ERR_BAD_CAPTURE, "bounded truncated rc=%d", rc);
    CHECK(bounded == NULL, "a bad capture handed back a string");
    rc = wz_dissect_pcap_summary_bounded(NULL, 0, &bounded);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "bounded null bytes rc=%d", rc);

    /* R311y851 -- and the CENSUS door is reachable from C at all, with the
     * four plane keys a consumer indexes.
     *
     * What this file owns is the symbol surviving into the cdylib and the
     * document's top-level shape; the Rust side owns the claim that each plane
     * carries what the wire named, which needs a capture with zenoh records in
     * it. Both claims are needed and neither implies the other -- before this
     * round all four planes were compiled into this library and had no symbol,
     * which is precisely the state a Rust-only test cannot detect.
     *
     * The same hand-laid pcap: its single packet decodes to nothing, so every
     * plane is EMPTY here, and that is right for this claim. An empty plane is
     * still a plane -- the assertion is that the keys exist, because a consumer
     * that indexes a key which is absent for an idle capture crashes on the
     * quietest network rather than on the busiest. */
    char *census = NULL;
    rc = wz_dissect_pcap_census(pcap, sizeof pcap, &census);
    CHECK(rc == WZ_DISSECT_OK, "census rc=%d", rc);
    CHECK(census != NULL, "OK came back with no string");
    CHECK(strstr(census, "\"keyexprs\"") != NULL, "no keyexpr plane: %s",
          census);
    CHECK(strstr(census, "\"nodes\"") != NULL, "no node plane: %s", census);
    CHECK(strstr(census, "\"exchanges\"") != NULL, "no query plane: %s", census);
    CHECK(strstr(census, "\"payloads\"") != NULL, "no payload plane: %s",
          census);
    /* The control for the four above: the SUMMARY door must not carry them, or
     * they would not be evidence that this door is what added them. */
    rc = wz_dissect_pcap_summary(pcap, sizeof pcap, &summary);
    CHECK(rc == WZ_DISSECT_OK, "summary rc=%d", rc);
    CHECK(strstr(summary, "\"keyexprs\"") == NULL,
          "the summary carries the keyexpr plane, so the census door is not "
          "what added it: %s",
          summary);
    wz_dissect_string_free(summary);

    /* R311y885 -- the BOUNDED census door is reachable from C, hands back a
     * census, and says what its ceilings cost.
     *
     * The Rust side owns the claim that the live-tap flow cap BITES, which
     * needs a capture of 1 025 distinct 5-tuples. This file owns the two claims
     * that are only true at the boundary: that the symbol survives into the
     * cdylib at all, and that what comes back through it is the CENSUS document
     * rather than the summary -- a door that bounded correctly and returned the
     * wrong document would satisfy every assertion made about the number.
     *
     * dropped_by_limits is asserted on BOTH doors deliberately. It is zero here
     * because this pcap is one packet, and a key that only appeared when a cap
     * bit would leave a consumer unable to tell "no caps" from "caps that did
     * not bite" -- which is the whole reason the group is emitted. */
    char *capped = NULL;
    rc = wz_dissect_pcap_census_bounded(pcap, sizeof pcap, &capped);
    CHECK(rc == WZ_DISSECT_OK, "census_bounded rc=%d", rc);
    CHECK(capped != NULL, "OK came back with no string");
    CHECK(strstr(capped, "\"keyexprs\"") != NULL,
          "the bounded door did not hand back a census: %s", capped);
    CHECK(strstr(capped, "\"dropped_by_limits\"") != NULL,
          "a bounded census that cannot say what it dropped is silent: %s",
          capped);
    CHECK(strstr(census, "\"dropped_by_limits\"") != NULL,
          "the unbounded census must carry the group too, or a reader cannot "
          "tell no-caps from caps-that-did-not-bite: %s",
          census);
    wz_dissect_string_free(capped);
    wz_dissect_string_free(census);

    /* R311y887 -- the PARAMETERISED census door, and the claim that matters at
     * this boundary: the preset really is an argument.
     *
     * The Rust side owns the byte-for-byte equalities against the three named
     * doors. This file owns what only C can say: that the symbol is in the
     * cdylib with the signature the header declares, that the two
     * WZ_DISSECT_LIMITS_* macros a consumer compiles in are the values the
     * library reads, and that an UNKNOWN preset is refused rather than falling
     * back to unbounded -- the failure that would hand a caller an uncapped
     * read while it believed otherwise. */
    char *limited = NULL;
    rc = wz_dissect_pcap_census_where_limited(pcap, sizeof pcap, "",
                                              WZ_DISSECT_LIMITS_LIVE_TAP,
                                              &limited);
    CHECK(rc == WZ_DISSECT_OK, "census_where_limited rc=%d", rc);
    CHECK(limited != NULL, "OK came back with no string");
    CHECK(strstr(limited, "\"keyexprs\"") != NULL,
          "the limited door did not hand back a census: %s", limited);
    CHECK(strstr(limited, "\"dropped_by_limits\"") != NULL,
          "a bounded census that cannot say what it dropped is silent: %s",
          limited);
    wz_dissect_string_free(limited);

    limited = NULL;
    rc = wz_dissect_pcap_census_where_limited(pcap, sizeof pcap, "",
                                              WZ_DISSECT_LIMITS_NONE, &limited);
    CHECK(rc == WZ_DISSECT_OK, "census_where_limited NONE rc=%d", rc);
    CHECK(limited != NULL, "OK came back with no string");
    wz_dissect_string_free(limited);

    limited = NULL;
    rc = wz_dissect_pcap_census_where_limited(pcap, sizeof pcap, "", 12345,
                                              &limited);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG,
          "an unknown preset must be refused, not read as unbounded: rc=%d",
          rc);
    CHECK(limited == NULL, "a refused preset handed back a string");

    /* Same memory rule, same refusals -- through BOTH census doors. */
    capped = NULL;
    rc = wz_dissect_pcap_census_bounded(truncated, sizeof truncated, &capped);
    CHECK(rc == WZ_DISSECT_ERR_BAD_CAPTURE, "census_bounded truncated rc=%d",
          rc);
    CHECK(capped == NULL, "a bad capture handed back a string");
    rc = wz_dissect_pcap_census_bounded(NULL, 0, &capped);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "census_bounded null bytes rc=%d",
          rc);

    census = NULL;
    rc = wz_dissect_pcap_census(truncated, sizeof truncated, &census);
    CHECK(rc == WZ_DISSECT_ERR_BAD_CAPTURE, "census truncated rc=%d", rc);
    CHECK(census == NULL, "a bad capture handed back a string");
    rc = wz_dissect_pcap_census(NULL, 0, &census);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "census null bytes rc=%d", rc);

    /* R311y854 -- the SELECTOR doors are reachable from C, and the two halves
     * of their contract hold across the boundary.
     *
     * The Rust side owns the claim that a selector narrows what the census
     * reports, which needs a capture with two keyexprs in it. This file owns
     * the two claims that are only true at the boundary: that both symbols
     * survive into the cdylib, and that a malformed selector comes back as
     * WZ_DISSECT_ERR_SELECTOR -- its OWN code -- with no string to free, while
     * the diagnostic call SUCCEEDS on the same text and hands one back. A
     * consumer that could not tell those two apart would either leak or free a
     * pointer it never received. */
    char *narrowed = NULL;
    rc = wz_dissect_pcap_census_where(pcap, sizeof pcap, "", &narrowed);
    CHECK(rc == WZ_DISSECT_OK, "empty selector rc=%d", rc);
    CHECK(narrowed != NULL, "OK came back with no string");
    CHECK(strstr(narrowed, "\"narrowed_by_selector\":false") != NULL,
          "the node plane must say it takes no selector: %s", narrowed);
    wz_dissect_string_free(narrowed);

    narrowed = NULL;
    rc = wz_dissect_pcap_census_where(pcap, sizeof pcap, "key === x", &narrowed);
    CHECK(rc == WZ_DISSECT_ERR_SELECTOR, "bad selector rc=%d, expected %d", rc,
          WZ_DISSECT_ERR_SELECTOR);
    CHECK(narrowed == NULL, "a refused selector handed back a string");

    char *verdict = NULL;
    rc = wz_dissect_selector_diagnose("key === x", &verdict);
    CHECK(rc == WZ_DISSECT_OK, "diagnose rc=%d -- a refused selector is a "
                               "successful diagnosis, not an error", rc);
    CHECK(verdict != NULL, "OK came back with no string");
    CHECK(strstr(verdict, "\"ok\":false") != NULL, "not a refusal: %s", verdict);
    CHECK(strstr(verdict, "\"at\":") != NULL, "no position: %s", verdict);
    wz_dissect_string_free(verdict);

    verdict = NULL;
    rc = wz_dissect_selector_diagnose("key == demo/**", &verdict);
    CHECK(rc == WZ_DISSECT_OK, "diagnose rc=%d", rc);
    CHECK(strcmp(verdict, "{\"ok\":true}") == 0, "not a pass: %s", verdict);
    wz_dissect_string_free(verdict);

    /* R311y855 -- the FIELD door is reachable from C, and its document has the
     * shape a consumer indexes: both flow halves and the honesty valve on the
     * second read. The Rust side owns the claim that a tree and its coordinate
     * are correct, which needs a capture with zenoh messages in it; this file
     * owns that the symbol survives into the cdylib and that the top-level keys
     * are there for an idle capture too -- a consumer that indexes a key which
     * is absent on quiet traffic crashes on the quietest network. */
    char *fields = NULL;
    rc = wz_dissect_pcap_fields(pcap, sizeof pcap, 0, &fields);
    CHECK(rc == WZ_DISSECT_OK, "fields rc=%d", rc);
    CHECK(fields != NULL, "OK came back with no string");
    CHECK(strstr(fields, "\"stream_flows\"") != NULL, "no stream half: %s",
          fields);
    CHECK(strstr(fields, "\"datagram_flows\"") != NULL, "no datagram half: %s",
          fields);
    CHECK(strstr(fields, "\"capture_reread\":true") != NULL,
          "the datagram half must say whether it could read the file again: %s",
          fields);
    wz_dissect_string_free(fields);

    /* Same memory rule, same refusals. */
    fields = NULL;
    rc = wz_dissect_pcap_fields(truncated, sizeof truncated, 0, &fields);
    CHECK(rc == WZ_DISSECT_ERR_BAD_CAPTURE, "fields truncated rc=%d", rc);
    CHECK(fields == NULL, "a bad capture handed back a string");
    rc = wz_dissect_pcap_fields(NULL, 0, 0, &fields);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "fields null bytes rc=%d", rc);

    /* R311y856 -- the payload seam a product LINKS. The Rust side owns the
     * claim that a declared rule decodes real bytes, which needs a capture
     * with a payload in it; this file owns that both symbols survive into the
     * cdylib, that the declaration dialect is accepted here, and that an
     * uninstallable declaration is REFUSED rather than silently dropped --
     * the silence that would leave a reader blaming the traffic for their own
     * rule. */
    char *decoded = NULL;
    rc = wz_dissect_pcap_fields_with_payloads(pcap, sizeof pcap, 0,
                                              "demo/temp=protobuf", &decoded);
    CHECK(rc == WZ_DISSECT_OK, "fields_with_payloads rc=%d", rc);
    CHECK(decoded != NULL, "OK came back with no string");
    CHECK(strstr(decoded, "\"stream_flows\"") != NULL,
          "the declared door must still be the field layer: %s", decoded);
    wz_dissect_string_free(decoded);

    decoded = NULL;
    rc = wz_dissect_pcap_fields_with_payloads(pcap, sizeof pcap, 0,
                                              "demo/temp=nosuchformat",
                                              &decoded);
    CHECK(rc == WZ_DISSECT_ERR_DECLARATION,
          "an unknown format must be its own refusal, got rc=%d", rc);
    CHECK(decoded == NULL, "a refused declaration handed back a string");

    /* And the diagnostic answers with no capture at all, which is the whole
     * point of it: a UI asks while the text is being typed. */
    char *declared = NULL;
    rc = wz_dissect_declarations_diagnose("demo/temp=protobuf", &declared);
    CHECK(rc == WZ_DISSECT_OK, "diagnose rc=%d", rc);
    CHECK(strcmp(declared, "{\"ok\":true,\"installed\":1}") == 0,
          "a good declaration text must verify: %s", declared);
    wz_dissect_string_free(declared);

    declared = NULL;
    rc = wz_dissect_declarations_diagnose("nonsense", &declared);
    CHECK(rc == WZ_DISSECT_OK, "a refusal is a successful diagnosis, rc=%d", rc);
    CHECK(strstr(declared, "\"ok\":false") != NULL, "verdict: %s", declared);
    CHECK(strstr(declared, "\"line\":0") != NULL,
          "the verdict must name the line: %s", declared);
    wz_dissect_string_free(declared);

    printf("  C1bo: C consumer linked the cdylib and read the tree\n");
    return 0;
}
