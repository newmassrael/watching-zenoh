/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

#include <stddef.h>
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

/* R2102 -- Ethernet + IPv4 + UDP carrying `payload`, built HERE in C.
 *
 * The Rust tests build the same frame from the same rules, and that is not a
 * duplicate to be factored away: the point of this file is that a C
 * translation unit can drive the live door with bytes it produced itself,
 * which is what a consumer will actually do. A fixture handed across the
 * boundary would be testing this library against its own idea of a packet.
 *
 * The IPv4 header checksum is REAL and the UDP one is left zero, which RFC 768
 * permits an IPv4 sender to do -- so this is a sender that declined rather than
 * one that got it wrong, and nothing in the report lands in the corruption
 * bucket. Returns the frame length. */
/* RFC 1071 over `n` bytes, folded onto whatever `seed` already accumulated --
 * which is what lets the TCP checksum add a pseudo-header without a second
 * implementation of the arithmetic. */
static unsigned long ones_complement(const unsigned char *b, size_t n,
                                     unsigned long seed) {
    size_t i;
    for (i = 0; i + 1 < n; i += 2) {
        seed += (unsigned long)((b[i] << 8) | b[i + 1]);
    }
    if (n & 1) {
        seed += (unsigned long)(b[n - 1] << 8);
    }
    return seed;
}

static unsigned short fold(unsigned long sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)((~sum) & 0xFFFF);
}

/* The Ethernet + IPv4 head both builders share. `proto` is 17 or 6, `paylen`
 * is what follows the IP header. Returns the offset of the transport header. */
static size_t ipv4_head(unsigned char *out, unsigned char proto, size_t paylen) {
    unsigned short ck;
    memset(out, 0, 64);
    out[12] = 0x08; /* ethertype IPv4 */
    out[13] = 0x00;
    out[14] = 0x45; /* v4, IHL 5 */
    out[16] = (unsigned char)((20 + paylen) >> 8);
    out[17] = (unsigned char)((20 + paylen) & 0xFF);
    out[22] = 64; /* TTL */
    out[23] = proto;
    out[26] = 10; /* 10.0.0.1 */
    out[27] = 0;
    out[28] = 0;
    out[29] = 1;
    out[30] = 10; /* 10.0.0.2 */
    out[31] = 0;
    out[32] = 0;
    out[33] = 2;
    ck = fold(ones_complement(out + 14, 20, 0));
    out[24] = (unsigned char)(ck >> 8);
    out[25] = (unsigned char)(ck & 0xFF);
    return 34;
}

static size_t udp_keepalive_frame(unsigned char *out) {
    static const unsigned char payload[1] = {0x04}; /* a whole KeepAlive */
    size_t n = ipv4_head(out, 17, 8 + sizeof payload);

    /* UDP: 7447 both ways. The checksum is left ZERO deliberately -- RFC 768
     * lets an IPv4 sender decline it, so this is a sender that declined rather
     * than one that got it wrong, and nothing lands in the corruption bucket.
     * IPv4 and TCP have no such form, which is why theirs are computed. */
    out[n + 0] = 0x1D;
    out[n + 1] = 0x17;
    out[n + 2] = 0x1D;
    out[n + 3] = 0x17;
    out[n + 5] = (unsigned char)(8 + sizeof payload);
    n += 8;

    memcpy(out + n, payload, sizeof payload);
    n += sizeof payload;
    return n < 60 ? 60 : n; /* Ethernet's minimum frame. */
}

/* R2102 -- the same message on a STREAM link, which is a different message
 * LIST and a different coordinate space. Having both in this file is what
 * makes the `origin` and `anchor_space` fields discriminating here: a test
 * that only ever saw datagrams would pass against a library that answered one
 * constant for every message. */
static size_t tcp_keepalive_frame(unsigned char *out, unsigned long seq) {
    /* A zenoh stream frames each unit with a 2-byte little-endian length
     * prefix, so one KeepAlive on the wire is 01 00 04. */
    static const unsigned char payload[3] = {0x01, 0x00, 0x04};
    unsigned long sum;
    unsigned short ck;
    size_t n = ipv4_head(out, 6, 20 + sizeof payload);

    out[n + 0] = 0x04; /* source port 1111 */
    out[n + 1] = 0x57;
    out[n + 2] = 0x1D; /* destination port 7447 */
    out[n + 3] = 0x17;
    out[n + 4] = (unsigned char)((seq >> 24) & 0xFF);
    out[n + 5] = (unsigned char)((seq >> 16) & 0xFF);
    out[n + 6] = (unsigned char)((seq >> 8) & 0xFF);
    out[n + 7] = (unsigned char)(seq & 0xFF);
    out[n + 12] = 5 << 4; /* data offset */
    out[n + 13] = 0x10;   /* ACK */
    out[n + 15] = 64;     /* window */
    memcpy(out + n + 20, payload, sizeof payload);

    /* The pseudo-header, then the segment, through the same accumulator. */
    sum = ones_complement(out + 26, 8, 0); /* src + dst addresses */
    sum += 6;                              /* protocol */
    sum += 20 + sizeof payload;            /* TCP length */
    ck = fold(ones_complement(out + n, 20 + sizeof payload, sum));
    out[n + 16] = (unsigned char)(ck >> 8);
    out[n + 17] = (unsigned char)(ck & 0xFF);

    n += 20 + sizeof payload;
    return n < 60 ? 60 : n;
}

/* R2102 -- the LIVE door, driven from C.
 *
 * Split out of main because it is a whole capability rather than one more
 * call: a handle that survives between calls, packets fed one at a time, and
 * records taken into a buffer THIS translation unit declared on its own stack.
 * That last part is the half no Rust test can make -- the struct layout under
 * test is the one the C compiler computed from the header, not the one Rust
 * computed from its own definition. If the two ever disagree, this is where it
 * shows. */
static int check_live_door(void) {
    wz_dissect_live *h = NULL;
    unsigned char frame[64];
    size_t frame_len;
    wz_dissect_record_v1 records[8];
    size_t written = 999;
    size_t i;
    int rc;

    /* THE LAYOUT, computed by the C compiler from this header. The Rust side
     * asserts the same numbers from its own definition. Both have to be edited
     * to change the layout, which is the point -- this is the one output of
     * this library that is raw memory, so a field inserted or widened gives a
     * consumer plausible garbage with no error anywhere. */
    CHECK(sizeof(wz_dissect_record_v1) == 48,
          "the record is %zu bytes, expected 48", sizeof(wz_dissect_record_v1));
    CHECK(offsetof(wz_dissect_record_v1, ts_ns) == 0, "ts_ns offset");
    CHECK(offsetof(wz_dissect_record_v1, flow_id) == 8, "flow_id offset");
    CHECK(offsetof(wz_dissect_record_v1, anchor) == 16, "anchor offset");
    CHECK(offsetof(wz_dissect_record_v1, unit_len) == 24, "unit_len offset");
    CHECK(offsetof(wz_dissect_record_v1, batch_index) == 32, "batch_index offset");
    CHECK(offsetof(wz_dissect_record_v1, unit_offset) == 36, "unit_offset offset");
    CHECK(offsetof(wz_dissect_record_v1, direction) == 40, "direction offset");
    CHECK(offsetof(wz_dissect_record_v1, anchor_space) == 41, "anchor_space offset");
    CHECK(offsetof(wz_dissect_record_v1, origin) == 42, "origin offset");
    CHECK(offsetof(wz_dissect_record_v1, kind) == 43, "kind offset");
    CHECK(offsetof(wz_dissect_record_v1, flags) == 44, "flags offset");

    /* An unknown preset is REFUSED. A consumer that believes it asked for a
     * ceiling must not be handed an unbounded read of a link that never ends. */
    rc = wz_dissect_live_open(9, &h);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "unknown preset rc=%d", rc);
    CHECK(h == NULL, "a refused open handed back a handle");

    rc = wz_dissect_live_open(WZ_DISSECT_LIMITS_LIVE_TAP, &h);
    CHECK(rc == WZ_DISSECT_OK, "live_open rc=%d", rc);
    CHECK(h != NULL, "OK came back with no handle");

    /* THE HANDLE OUTLIVES THE CALL, which is the revision this ABI made. Three
     * packets, three separate calls, one dissection. */
    frame_len = udp_keepalive_frame(frame);
    for (i = 0; i < 3; i++) {
        rc = wz_dissect_live_push(h, 1 /* ETHERNET */,
                                  (uint64_t)(i + 1) * 1000000u, frame, frame_len);
        CHECK(rc == WZ_DISSECT_OK, "live_push %zu rc=%d", i, rc);
    }

    /* A packet on a link this build cannot read is COUNTED, not refused: a tap
     * sees whatever the interface gives it. */
    rc = wz_dissect_live_push(h, 0xDEAD, WZ_DISSECT_NO_TIMESTAMP, frame, frame_len);
    CHECK(rc == WZ_DISSECT_OK, "an unreadable link type must not be an error: %d", rc);

    rc = wz_dissect_live_drain(h, records, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "live_drain rc=%d", rc);
    CHECK(written == 3, "expected 3 records across 3 pushes, got %zu", written);

    for (i = 0; i < written; i++) {
        CHECK(records[i].kind == WZ_DISSECT_KIND_KEEPALIVE,
              "record %zu kind=%u, expected KEEPALIVE", i,
              (unsigned)records[i].kind);
        CHECK(records[i].origin == WZ_DISSECT_ORIGIN_DATAGRAM,
              "record %zu origin=%u, expected DATAGRAM", i,
              (unsigned)records[i].origin);
        CHECK(records[i].anchor_space == WZ_DISSECT_ANCHOR_PACKET,
              "a datagram message anchors to a packet index");
        /* The push ordinal IS the anchor, and asserting the SEQUENCE is what
         * separates a live handle from a door that re-dissected per call: the
         * latter would answer 0 every time. */
        CHECK(records[i].anchor == (uint64_t)i, "record %zu anchor=%llu", i,
              (unsigned long long)records[i].anchor);
        CHECK(records[i].ts_ns == (uint64_t)(i + 1) * 1000000u,
              "record %zu ts_ns=%llu", i, (unsigned long long)records[i].ts_ns);
        CHECK(records[i].flags == 0, "an ordinary KeepAlive flags nothing");
        CHECK(records[i].flow_id == records[0].flow_id,
              "one conversation must carry one flow id");
    }

    /* A drained message must not come back. A watermark that did not advance
     * would hand the same three over forever, which a consumer reads as the
     * link repeating itself. */
    written = 999;
    rc = wz_dissect_live_drain(h, records, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "second live_drain rc=%d", rc);
    CHECK(written == 0, "a drained message came back: %zu", written);

    /* Nothing was discarded, so nothing may be reported lost. */
    CHECK(wz_dissect_live_lost(h) == 0, "lost=%llu with no ceiling reached",
          (unsigned long long)wz_dissect_live_lost(h));

    /* A SHORT BUFFER takes a prefix and leaves the rest, in order. This is the
     * contract a consumer loops on, and the failure it rules out costs data
     * rather than time: a drain that advanced past records it did not write
     * would lose them while every count downstream still looked plausible. */
    for (i = 0; i < 2; i++) {
        rc = wz_dissect_live_push(h, 1, WZ_DISSECT_NO_TIMESTAMP, frame, frame_len);
        CHECK(rc == WZ_DISSECT_OK, "live_push rc=%d", rc);
    }
    written = 999;
    rc = wz_dissect_live_drain(h, records, 1, &written);
    CHECK(rc == WZ_DISSECT_OK, "short live_drain rc=%d", rc);
    CHECK(written == 1, "a buffer of one takes exactly one, got %zu", written);
    CHECK(records[0].anchor == 4, "the older of the two first, got %llu",
          (unsigned long long)records[0].anchor);
    /* A push with NO clock reading leaves the observer's clock WHERE IT STOOD,
     * so this record carries the last instant that was supplied (3 ms, from the
     * third push above) rather than the sentinel. That is the honest answer and
     * a consumer has to know it: `ts_ns` is when this reader's clock last
     * moved, not a per-packet stamp it invented. The sentinel means the clock
     * was NEVER set -- checked below, on a handle where it never was. */
    CHECK(records[0].ts_ns == 3000000u,
          "a timestamp-less push must leave the clock where it stood, got %llu",
          (unsigned long long)records[0].ts_ns);
    written = 999;
    rc = wz_dissect_live_drain(h, records, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "remainder live_drain rc=%d", rc);
    CHECK(written == 1, "the remainder is one record, got %zu", written);
    CHECK(records[0].anchor == 5, "and it is the one left behind, got %llu",
          (unsigned long long)records[0].anchor);

    /* Nulls are refused before anything is dereferenced. A panic unwinding
     * across extern "C" is undefined behaviour and these are the calls that
     * would trip it. */
    rc = wz_dissect_live_push(NULL, 1, 0, frame, frame_len);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null handle push rc=%d", rc);
    rc = wz_dissect_live_push(h, 1, 0, NULL, 0);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null bytes push rc=%d", rc);
    rc = wz_dissect_live_drain(h, NULL, 8, &written);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null buffer drain rc=%d", rc);
    rc = wz_dissect_live_drain(h, records, 8, NULL);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null written drain rc=%d", rc);
    rc = wz_dissect_live_open(WZ_DISSECT_LIMITS_LIVE_TAP, NULL);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null out open rc=%d", rc);
    CHECK(wz_dissect_live_lost(NULL) == 0, "a null handle has lost nothing");

    /* Closing null is a no-op, so a cleanup path needs no guard of its own. */
    wz_dissect_live_close(NULL);
    wz_dissect_live_close(h);

    /* A HANDLE WHOSE CLOCK WAS NEVER SET reports the sentinel, and the sentinel
     * is not zero -- zero is a legal instant, and a tap whose clock starts at
     * its own zero must not be reported as a tap with no clock at all. A fresh
     * handle, because on the one above the clock HAD been set and the value
     * would be that reading rather than this distinction. */
    h = NULL;
    rc = wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &h);
    CHECK(rc == WZ_DISSECT_OK, "second live_open rc=%d", rc);
    rc = wz_dissect_live_push(h, 1, WZ_DISSECT_NO_TIMESTAMP, frame, frame_len);
    CHECK(rc == WZ_DISSECT_OK, "clockless push rc=%d", rc);
    written = 999;
    rc = wz_dissect_live_drain(h, records, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "clockless drain rc=%d", rc);
    CHECK(written == 1, "expected one record, got %zu", written);
    CHECK(records[0].ts_ns == WZ_DISSECT_NO_TIMESTAMP,
          "a clock that was never set must report as never set, got %llu",
          (unsigned long long)records[0].ts_ns);

    /* A STREAM message on the same handle: a different list, a different
     * coordinate space, and a different flow. Without this arm the `origin` and
     * `anchor_space` assertions above would pass against a library that
     * answered one constant for every message -- a datagram-only test cannot
     * tell a discriminator from a default. */
    frame_len = tcp_keepalive_frame(frame, 1000);
    rc = wz_dissect_live_push(h, 1, 5000000u, frame, frame_len);
    CHECK(rc == WZ_DISSECT_OK, "tcp push rc=%d", rc);
    written = 999;
    rc = wz_dissect_live_drain(h, records, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "tcp drain rc=%d", rc);
    CHECK(written == 1, "a stream KeepAlive is one message, got %zu", written);
    CHECK(records[0].kind == WZ_DISSECT_KIND_KEEPALIVE, "kind=%u",
          (unsigned)records[0].kind);
    CHECK(records[0].origin == WZ_DISSECT_ORIGIN_STREAM,
          "a TCP flow's messages come from the STREAM list, got %u",
          (unsigned)records[0].origin);
    CHECK(records[0].anchor_space == WZ_DISSECT_ANCHOR_STREAM_BYTES,
          "and their anchor is a byte offset, not a packet index, got %u",
          (unsigned)records[0].anchor_space);
    /* The 2-byte length prefix framed one message of one byte. */
    CHECK(records[0].unit_len == 1, "unit_len=%llu, expected 1",
          (unsigned long long)records[0].unit_len);
    wz_dissect_live_close(h);

    /* A CEILING THAT BITES IS COUNTED, through the shipped preset rather than a
     * number invented for a test.
     *
     * WZ_DISSECT_LIMITS_LIVE_TAP keeps 10 000 decoded messages per flow, so
     * feeding two more than that and draining afterwards is the whole of the
     * shape: the oldest two are gone, and a reader that only counted what it
     * received would read a FLOOR as a total. This is the assertion that makes
     * wz_dissect_live_lost a measurement rather than a field that is always
     * zero. */
    h = NULL;
    rc = wz_dissect_live_open(WZ_DISSECT_LIMITS_LIVE_TAP, &h);
    CHECK(rc == WZ_DISSECT_OK, "ceiling live_open rc=%d", rc);
    frame_len = udp_keepalive_frame(frame);
    for (i = 0; i < 10002; i++) {
        rc = wz_dissect_live_push(h, 1, (uint64_t)(i + 1) * 1000000u, frame, frame_len);
        CHECK(rc == WZ_DISSECT_OK, "ceiling push %zu rc=%d", i, rc);
    }
    CHECK(wz_dissect_live_lost(h) == 0,
          "nothing is lost until a drain looks: the counter is what the "
          "CONSUMER missed, got %llu", (unsigned long long)wz_dissect_live_lost(h));
    written = 999;
    rc = wz_dissect_live_drain(h, records, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "ceiling drain rc=%d", rc);
    CHECK(written == 8, "the buffer takes what it holds, got %zu", written);
    CHECK(wz_dissect_live_lost(h) == 2,
          "the ceiling discarded 2 of 10002 and must say so, got %llu",
          (unsigned long long)wz_dissect_live_lost(h));
    /* And the first record handed out is the OLDEST SURVIVOR, not the oldest
     * message: a drain that resumed from a watermark the trim invalidated would
     * be reading the list at the wrong place entirely. */
    CHECK(records[0].anchor == 2, "expected the third packet, got %llu",
          (unsigned long long)records[0].anchor);
    wz_dissect_live_close(h);
    return 0;
}

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
    /* R311y913 -- 9 since wz_dissect_readable_surfaces joined it.
     * R311y917 -- 10 since wz_dissect_pcap_fields_limited joined it.
     * R2102 -- 11, and this is the first bump that moves for BOTH halves of
     * the rule: five wz_dissect_live_* symbols, AND the memory contract, which
     * now admits exactly one handle that outlives its call. The second half is
     * why the number is the right place to publish it -- a consumer that
     * refuses a library whose memory rules moved has nothing else to ask. */
    CHECK(wz_dissect_abi_version() == 11, "abi version is %d, expected 11",
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

    /* R311y917 -- the FIELD layer under a ceiling, on the same claim: the
     * symbol is in the cdylib with the signature the header declares, the
     * preset really is an argument, and an unknown one is refused rather than
     * read as unbounded. The Rust side owns the byte-for-byte equalities
     * against the two field doors this one subsumes. */
    char *bounded_fields = NULL;
    rc = wz_dissect_pcap_fields_limited(pcap, sizeof pcap, 0, "",
                                        WZ_DISSECT_LIMITS_LIVE_TAP,
                                        &bounded_fields);
    CHECK(rc == WZ_DISSECT_OK, "fields_limited rc=%d", rc);
    CHECK(bounded_fields != NULL, "OK came back with no string");
    CHECK(strstr(bounded_fields, "\"stream_flows\"") != NULL,
          "the limited door did not hand back a field document: %s",
          bounded_fields);
    CHECK(strstr(bounded_fields, "\"dropped_by_limits\"") != NULL,
          "a bounded field listing that cannot say what it dropped is silent: %s",
          bounded_fields);
    wz_dissect_string_free(bounded_fields);

    bounded_fields = NULL;
    rc = wz_dissect_pcap_fields_limited(pcap, sizeof pcap, 0, "",
                                        WZ_DISSECT_LIMITS_NONE,
                                        &bounded_fields);
    CHECK(rc == WZ_DISSECT_OK, "fields_limited NONE rc=%d", rc);
    CHECK(bounded_fields != NULL, "OK came back with no string");
    wz_dissect_string_free(bounded_fields);

    bounded_fields = NULL;
    rc = wz_dissect_pcap_fields_limited(pcap, sizeof pcap, 0, "", 12345,
                                        &bounded_fields);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG,
          "an unknown preset must be refused on the field door too: rc=%d", rc);
    CHECK(bounded_fields == NULL, "a refused preset handed back a string");

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
    CHECK(strcmp(verdict,
                 "{\"document\":{\"name\":\"selector_diagnose\",\"revision\":1},"
                 "\"ok\":true}") == 0,
          "not a pass: %s", verdict);
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
    CHECK(strcmp(declared,
                 "{\"document\":{\"name\":\"declarations_diagnose\",\"revision\":1},"
                 "\"ok\":true,\"installed\":1}") == 0,
          "a good declaration text must verify: %s", declared);
    wz_dissect_string_free(declared);

    declared = NULL;
    rc = wz_dissect_declarations_diagnose("nonsense", &declared);
    CHECK(rc == WZ_DISSECT_OK, "a refusal is a successful diagnosis, rc=%d", rc);
    CHECK(strstr(declared, "\"ok\":false") != NULL, "verdict: %s", declared);
    CHECK(strstr(declared, "\"line\":0") != NULL,
          "the verdict must name the line: %s", declared);
    wz_dissect_string_free(declared);

    /* R311y913 (unregistered item 435) -- the library says what it can READ,
     * with no capture. The two lists are the same strings `wz-analyze --help`
     * prints, derived from the link-type match and the two body dispatches, so
     * a consumer and a person at a terminal are told one fact.
     *
     * Checked from C rather than only from Rust because that is what this lane
     * is for: the door takes ONE out-parameter and no bytes, which is a calling
     * convention nothing else here exercises. */
    char *surfaces = NULL;
    rc = wz_dissect_readable_surfaces(&surfaces);
    CHECK(rc == WZ_DISSECT_OK, "readable_surfaces rc=%d", rc);
    CHECK(surfaces != NULL, "OK came back with no string");
    CHECK(strstr(surfaces, "\"link_types\"") != NULL, "no link types in %s",
          surfaces);
    /* A NAME rather than only the key: an empty list would satisfy the key. */
    CHECK(strstr(surfaces, "ETHERNET") != NULL,
          "the link-type line must name a type it reads: %s", surfaces);
    CHECK(strstr(surfaces, "\"z64\"") != NULL, "no z64 bodies in %s", surfaces);
    CHECK(strstr(surfaces, "/qos") != NULL,
          "the z64 line must name a body it opens: %s", surfaces);
    wz_dissect_string_free(surfaces);

    /* Null out is the argument error, not a crash -- the rule every door here
     * follows, and this one has no other argument to get wrong. */
    rc = wz_dissect_readable_surfaces(NULL);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG,
          "a null out-pointer must be refused, got rc=%d", rc);

    /* R2100 (open-debt item 509) -- THE REVISION EVERY DOCUMENT CARRIES, read
     * from the side that needs it.
     *
     * wz_dissect_abi_version() above is the SYMBOL contract and is defined not
     * to move for a JSON change. That left a key RENAME or REMOVAL -- a real
     * break for a consumer reading by name, which is what this header tells it
     * to do -- with no number anywhere that could express it. Each document now
     * opens with its own, so a consumer pins the shape it was written against
     * and refuses one it has not seen, exactly as it already does with the ABI
     * revision.
     *
     * Asserted HERE and not only in Rust because that is the whole claim: a
     * revision a linking product cannot read is not a signal to a consumer. */
    struct {
        const char *name;
        char *doc;
    } revisioned[4];
    revisioned[0].name = "census";
    revisioned[0].doc = NULL;
    rc = wz_dissect_pcap_census(pcap, sizeof pcap, &revisioned[0].doc);
    CHECK(rc == WZ_DISSECT_OK, "census rc=%d", rc);
    revisioned[1].name = "summary";
    revisioned[1].doc = NULL;
    rc = wz_dissect_pcap_summary(pcap, sizeof pcap, &revisioned[1].doc);
    CHECK(rc == WZ_DISSECT_OK, "summary rc=%d", rc);
    revisioned[2].name = "fields";
    revisioned[2].doc = NULL;
    rc = wz_dissect_pcap_fields(pcap, sizeof pcap, 0, &revisioned[2].doc);
    CHECK(rc == WZ_DISSECT_OK, "fields rc=%d", rc);
    revisioned[3].name = "readable_surfaces";
    revisioned[3].doc = NULL;
    rc = wz_dissect_readable_surfaces(&revisioned[3].doc);
    CHECK(rc == WZ_DISSECT_OK, "surfaces rc=%d", rc);

    for (size_t i = 0; i < sizeof revisioned / sizeof revisioned[0]; i++) {
        char want[128];
        snprintf(want, sizeof want,
                 "{\"document\":{\"name\":\"%s\",\"revision\":1}",
                 revisioned[i].name);
        CHECK(strncmp(revisioned[i].doc, want, strlen(want)) == 0,
              "the %s document must OPEN with its own revision so a consumer "
              "reads it before parsing the body: %s",
              revisioned[i].name, revisioned[i].doc);
        wz_dissect_string_free(revisioned[i].doc);
    }

    /* R2102 (ABI 11) -- the LIVE door, which is the one capability in this
     * header that is not a call over a buffer the caller already holds whole. */
    if (check_live_door() != 0) {
        return 1;
    }

    printf("  C1bo: C consumer linked the cdylib and read the tree\n");
    return 0;
}
