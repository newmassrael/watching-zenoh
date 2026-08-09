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
    CHECK(wz_dissect_abi_version() == 1, "abi version is %d, expected 1",
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

    printf("  C1bo: C consumer linked the cdylib and read the tree\n");
    return 0;
}
