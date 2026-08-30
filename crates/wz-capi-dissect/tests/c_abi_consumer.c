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
static size_t tcp_frame_with(unsigned char *out, unsigned long seq,
                             const unsigned char *payload, size_t paylen) {
    unsigned long sum;
    unsigned short ck;
    size_t n = ipv4_head(out, 6, 20 + paylen);

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
    memcpy(out + n + 20, payload, paylen);

    /* The pseudo-header, then the segment, through the same accumulator. */
    sum = ones_complement(out + 26, 8, 0); /* src + dst addresses */
    sum += 6;                              /* protocol */
    sum += 20 + paylen;                    /* TCP length */
    ck = fold(ones_complement(out + n, 20 + paylen, sum));
    out[n + 16] = (unsigned char)(ck >> 8);
    out[n + 17] = (unsigned char)(ck & 0xFF);

    n += 20 + paylen;
    return n < 60 ? 60 : n;
}

/* R2102 -- ONE KeepAlive on a stream link. A zenoh stream frames each unit
 * with a 2-byte little-endian length prefix, so one KeepAlive on the wire is
 * 01 00 04. */
static size_t tcp_keepalive_frame(unsigned char *out, unsigned long seq) {
    static const unsigned char payload[3] = {0x01, 0x00, 0x04};
    return tcp_frame_with(out, seq, payload, sizeof payload);
}

/* R2205 -- TWO KeepAlives in ONE framing unit, which is what a BATCH is on the
 * wire: one length prefix declaring two, and two messages behind it. The byte
 * door's whole contract about where a message's slice ENDS is only visible on
 * a unit that holds more than one. */
static size_t tcp_batch_frame(unsigned char *out, unsigned long seq) {
    static const unsigned char payload[4] = {0x02, 0x00, 0x04, 0x04};
    return tcp_frame_with(out, seq, payload, sizeof payload);
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
    wz_dissect_record records[8];
    size_t written = 999;
    size_t i;
    uint64_t datagram_list = 0;
    int rc;

    /* THE LAYOUT, computed by the C compiler from this header. The Rust side
     * asserts the same numbers from its own definition. Both have to be edited
     * to change the layout, which is the point -- this is the one output of
     * this library that is raw memory, so a field inserted or widened gives a
     * consumer plausible garbage with no error anywhere. */
    CHECK(sizeof(wz_dissect_record) == 56,
          "the record is %zu bytes, expected 56", sizeof(wz_dissect_record));
    CHECK(offsetof(wz_dissect_record, ts_ns) == 0, "ts_ns offset");
    CHECK(offsetof(wz_dissect_record, flow_id) == 8, "flow_id offset");
    CHECK(offsetof(wz_dissect_record, list_id) == 16, "list_id offset");
    CHECK(offsetof(wz_dissect_record, anchor) == 24, "anchor offset");
    CHECK(offsetof(wz_dissect_record, unit_len) == 32, "unit_len offset");
    CHECK(offsetof(wz_dissect_record, batch_index) == 40, "batch_index offset");
    CHECK(offsetof(wz_dissect_record, unit_offset) == 44, "unit_offset offset");
    CHECK(offsetof(wz_dissect_record, direction) == 48, "direction offset");
    CHECK(offsetof(wz_dissect_record, anchor_space) == 49, "anchor_space offset");
    CHECK(offsetof(wz_dissect_record, origin) == 50, "origin offset");
    CHECK(offsetof(wz_dissect_record, kind) == 51, "kind offset");
    CHECK(offsetof(wz_dissect_record, flags) == 52, "flags offset");

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
        CHECK(records[i].list_id == records[0].list_id,
              "and one message LIST must carry one coordinate space");
    }
    /* The two ids come off ONE counter, so they cannot collide by accident --
     * a consumer that read the wrong field would otherwise get a plausible
     * answer for as long as both happened to be small. */
    CHECK(records[0].flow_id != records[0].list_id,
          "flow_id and list_id must never be the same number: %llu",
          (unsigned long long)records[0].flow_id);
    datagram_list = records[0].list_id;

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
    /* A DIFFERENT LIST MUST NOT SHARE A COORDINATE SPACE. This stream's
     * anchors are byte offsets starting at zero and the datagram list's are
     * packet indices starting at zero; a consumer that grouped the two would
     * read two distinct messages as one. `anchor_space` says they are read
     * differently and `list_id` is what says they may not be compared at all. */
    CHECK(records[0].list_id != datagram_list,
          "the stream list took the datagram list's id (%llu)",
          (unsigned long long)datagram_list);
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

/* R2205 (open-debt item 560) -- THE BYTES UNDER THE DESCRIPTION, driven from C.
 *
 * Its own function and not another arm of check_live_door for the reason that
 * one is split out of main: this is a capability, not one more call. What only
 * C can say here is the part that matters to a linking consumer -- the bytes
 * land in an array THIS translation unit declared, at the length this library
 * reported, with nothing to give back afterwards. A Rust test asserting on a
 * `&[u8]` cannot make that statement.
 *
 * The three arms are the three answers, and a test with fewer would pass
 * against a library that returned one of them always:
 *
 *   1. a STREAM record, whose bytes only this reader can produce;
 *   2. a DATAGRAM record, refused BY NAME because the caller is holding the
 *      packet already -- the half of item 560 the consumer cut off itself;
 *   3. a record this handle never issued, refused as a MISS rather than
 *      answered with whatever sits at those coordinates.
 */
static int check_message_bytes_door(void) {
    wz_dissect_live *h = NULL;
    wz_dissect_live *other = NULL;
    unsigned char frame[64];
    unsigned char buf[8];
    size_t frame_len;
    wz_dissect_record records[8];
    wz_dissect_record stream_rec;
    size_t written = 999;
    size_t needed = 999;
    int rc;

    rc = wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &h);
    CHECK(rc == WZ_DISSECT_OK, "bytes live_open rc=%d", rc);

    /* 1 -- A STREAM MESSAGE. Its anchor is a byte offset into a stream this
     * reader reassembled, so no packet the caller pushed contains it at that
     * coordinate: this is the arm with no workaround on the consumer's side. */
    frame_len = tcp_keepalive_frame(frame, 1000);
    rc = wz_dissect_live_push(h, 1 /* ETHERNET */, 1000000u, frame, frame_len);
    CHECK(rc == WZ_DISSECT_OK, "stream push rc=%d", rc);
    rc = wz_dissect_live_drain(h, records, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "stream drain rc=%d", rc);
    CHECK(written == 1, "one framed KeepAlive is one record, got %zu", written);
    CHECK(records[0].anchor_space == WZ_DISSECT_ANCHOR_STREAM_BYTES,
          "this arm is about the stream space, got %u",
          (unsigned)records[0].anchor_space);
    stream_rec = records[0];

    /* SIZE FIRST. A null `out` with a zero `cap` is the documented way to ask
     * for the length alone, and it must not be an argument error. */
    needed = 999;
    rc = wz_dissect_live_message_bytes(h, &stream_rec, NULL, 0, &needed);
    CHECK(rc == WZ_DISSECT_OK, "sizing call rc=%d", rc);
    CHECK(needed == 1, "one KeepAlive is one byte, got %zu", needed);

    /* A SHORT BUFFER WRITES NOTHING. The sentinel is what says so: a door that
     * truncated would leave a prefix here, and a consumer that trusted `needed`
     * would render a fragment as the message. */
    memset(buf, 0xAB, sizeof buf);
    needed = 999;
    rc = wz_dissect_live_message_bytes(h, &stream_rec, buf, 0, &needed);
    CHECK(rc == WZ_DISSECT_OK, "short-buffer rc=%d", rc);
    CHECK(needed == 1, "the length is reported whatever the cap, got %zu", needed);
    CHECK(buf[0] == 0xAB, "a cap below the length must write NOTHING");

    /* AND THEN THE BYTES, into an array this translation unit owns. */
    memset(buf, 0xAB, sizeof buf);
    needed = 999;
    rc = wz_dissect_live_message_bytes(h, &stream_rec, buf, sizeof buf, &needed);
    CHECK(rc == WZ_DISSECT_OK, "byte call rc=%d", rc);
    CHECK(needed == 1, "needed=%zu", needed);
    CHECK(buf[0] == 0x04, "the KeepAlive's own byte, got 0x%02X", buf[0]);
    CHECK(buf[1] == 0xAB, "nothing past the message may be written");

    /* 2 -- A DATAGRAM MESSAGE is refused BY NAME. The caller pushed the packet
     * that carried it and `unit_offset` says where inside it the message is, so
     * copying the bytes back would be handing over what the caller is holding.
     * A `needed` of zero beside the refusal: there is nothing to size for. */
    frame_len = udp_keepalive_frame(frame);
    rc = wz_dissect_live_push(h, 1, 2000000u, frame, frame_len);
    CHECK(rc == WZ_DISSECT_OK, "datagram push rc=%d", rc);
    rc = wz_dissect_live_drain(h, records, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "datagram drain rc=%d", rc);
    CHECK(written == 1, "expected one datagram record, got %zu", written);
    CHECK(records[0].anchor_space == WZ_DISSECT_ANCHOR_PACKET,
          "this arm is about the packet space, got %u",
          (unsigned)records[0].anchor_space);
    needed = 999;
    rc = wz_dissect_live_message_bytes(h, &records[0], buf, sizeof buf, &needed);
    CHECK(rc == WZ_DISSECT_ERR_NO_BYTE_SOURCE,
          "a packet-anchored record must be refused by NAME, rc=%d", rc);
    CHECK(needed == 0, "a refusal must not report a length to size for: %zu",
          needed);

    /* 3 -- A RECORD FROM ANOTHER HANDLE. Its ids are that handle's, and the
     * failure this rules out is the one that costs data rather than time: a
     * lookup that fell through to some list of THIS handle would hand back
     * another message's bytes with no error anywhere. */
    rc = wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &other);
    CHECK(rc == WZ_DISSECT_OK, "second live_open rc=%d", rc);
    needed = 999;
    rc = wz_dissect_live_message_bytes(other, &stream_rec, buf, sizeof buf, &needed);
    CHECK(rc == WZ_DISSECT_ERR_BYTES_RETIRED,
          "a foreign record must MISS, not resolve, rc=%d", rc);
    CHECK(needed == 0, "a miss reports no length, got %zu", needed);
    wz_dissect_live_close(other);

    /* Nulls are refused before anything is dereferenced. */
    rc = wz_dissect_live_message_bytes(NULL, &stream_rec, buf, sizeof buf, &needed);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null handle rc=%d", rc);
    rc = wz_dissect_live_message_bytes(h, NULL, buf, sizeof buf, &needed);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null record rc=%d", rc);
    rc = wz_dissect_live_message_bytes(h, &stream_rec, buf, sizeof buf, NULL);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null needed rc=%d", rc);
    rc = wz_dissect_live_message_bytes(h, &stream_rec, NULL, sizeof buf, &needed);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG,
          "a null buffer with a non-zero cap is a caller bug, rc=%d", rc);
    wz_dissect_live_close(h);

    /* A BATCH, which is where the contract about the slice's END is visible at
     * all. One length prefix declares two messages; the FIRST message's slice
     * runs to the end of the unit and therefore covers both, and the SECOND
     * runs to the end alone. That is not an accident of the implementation --
     * it is the slice the field walker itself was handed, which is what makes a
     * message-relative span out of the `fields` document index it directly. */
    h = NULL;
    rc = wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &h);
    CHECK(rc == WZ_DISSECT_OK, "batch live_open rc=%d", rc);
    frame_len = tcp_batch_frame(frame, 2000);
    rc = wz_dissect_live_push(h, 1, 3000000u, frame, frame_len);
    CHECK(rc == WZ_DISSECT_OK, "batch push rc=%d", rc);
    rc = wz_dissect_live_drain(h, records, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "batch drain rc=%d", rc);
    CHECK(written == 2, "one unit of two KeepAlives is two records, got %zu",
          written);
    CHECK(records[0].anchor == records[1].anchor,
          "two messages of ONE unit share its anchor");
    CHECK(records[0].unit_offset == 0 && records[1].unit_offset == 1,
          "and are told apart by where they stand in it: %u / %u",
          (unsigned)records[0].unit_offset, (unsigned)records[1].unit_offset);

    /* A NON-EMPTY buffer that is still too small. This is the case a zero cap
     * cannot reach: a door that truncated would leave a one-byte prefix here
     * and report a length of two, and a consumer trusting `needed` would render
     * one byte of stale memory as the second. The batch is the only message in
     * this file long enough for the case to exist at all. */
    memset(buf, 0xAB, sizeof buf);
    needed = 999;
    rc = wz_dissect_live_message_bytes(h, &records[0], buf, 1, &needed);
    CHECK(rc == WZ_DISSECT_OK, "batch short-buffer rc=%d", rc);
    CHECK(needed == 2, "the full length is reported whatever the cap: %zu",
          needed);
    CHECK(buf[0] == 0xAB,
          "a cap between zero and the length must still write NOTHING");

    memset(buf, 0xAB, sizeof buf);
    needed = 999;
    rc = wz_dissect_live_message_bytes(h, &records[0], buf, sizeof buf, &needed);
    CHECK(rc == WZ_DISSECT_OK, "batch[0] rc=%d", rc);
    CHECK(needed == 2, "the first message's slice runs to the unit's end: %zu",
          needed);
    CHECK(buf[0] == 0x04 && buf[1] == 0x04, "both KeepAlives, got %02X %02X",
          buf[0], buf[1]);
    CHECK(buf[2] == 0xAB, "and nothing past the unit");

    memset(buf, 0xAB, sizeof buf);
    needed = 999;
    rc = wz_dissect_live_message_bytes(h, &records[1], buf, sizeof buf, &needed);
    CHECK(rc == WZ_DISSECT_OK, "batch[1] rc=%d", rc);
    CHECK(needed == 1, "the second message's slice is what is left: %zu", needed);
    CHECK(buf[0] == 0x04, "the second KeepAlive, got 0x%02X", buf[0]);
    CHECK(buf[1] == 0xAB, "and nothing past it");
    wz_dissect_live_close(h);
    return 0;
}

/* R2171 -- a classic pcap holding `n` copies of `frame`, laid out by hand in
 * the same 24 + 16 form the summary fixture in main uses, little-endian
 * throughout because the magic is written that way.
 *
 * Packet `i` is stamped `(i + 1)` MILLISECONDS, which is what makes the file
 * comparable with the live arm: a live push of the same frames at the same
 * instants must produce the same records, and a fixture whose clock did not
 * line up would leave that comparison untestable. Returns the file length. */
static size_t pcap_of_frames(unsigned char *out, const unsigned char *frame,
                             size_t frame_len, size_t n) {
    static const unsigned char head[24] = {
        0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00};
    size_t at = sizeof head;
    size_t i;
    memcpy(out, head, sizeof head);
    for (i = 0; i < n; i++) {
        unsigned long usec = (unsigned long)(i + 1) * 1000u;
        memset(out + at, 0, 4); /* ts_sec */
        out[at + 4] = (unsigned char)(usec & 0xFF);
        out[at + 5] = (unsigned char)((usec >> 8) & 0xFF);
        out[at + 6] = (unsigned char)((usec >> 16) & 0xFF);
        out[at + 7] = (unsigned char)((usec >> 24) & 0xFF);
        out[at + 8] = (unsigned char)(frame_len & 0xFF);
        out[at + 9] = (unsigned char)((frame_len >> 8) & 0xFF);
        out[at + 10] = 0;
        out[at + 11] = 0;
        out[at + 12] = out[at + 8]; /* origlen == caplen: nothing was snapped */
        out[at + 13] = out[at + 9];
        out[at + 14] = 0;
        out[at + 15] = 0;
        memcpy(out + at + 16, frame, frame_len);
        at += 16 + frame_len;
    }
    return at;
}

/* R2171 (open-debt item 547) -- THE DOOR BETWEEN THE TWO HALVES, driven from C.
 *
 * Every pcap door in this header takes a whole capture and hands back a JSON
 * document; the live family takes packets one at a time and hands back binary
 * records. Nothing joined them, so a FROZEN capture -- the one input a
 * regression test can hold still -- could not reach the record door at all.
 *
 * What this asserts is not that the symbol exists. It is that the file arm and
 * the live arm answer THE SAME RECORDS for the same frames at the same
 * instants, which is the whole claim: a replay that read the container its own
 * way would be a second reader of the same bytes, and the two would drift. */
static int check_replay_door(void) {
    wz_dissect_live *h = NULL;
    wz_dissect_live *live = NULL;
    unsigned char frame[64];
    unsigned char file[24 + 3 * (16 + 64)];
    unsigned char truncated[8] = {0x0A, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0};
    wz_dissect_record from_file[8];
    wz_dissect_record from_live[8];
    size_t frame_len;
    size_t file_len;
    size_t written = 999;
    size_t i;
    int rc;

    frame_len = udp_keepalive_frame(frame);
    file_len = pcap_of_frames(file, frame, frame_len, 3);

    /* An unknown preset is REFUSED here for the same reason it is at
     * wz_dissect_live_open: the handle this hands back is the same handle, and
     * a caller that believes it asked for a ceiling must not be given none. */
    rc = wz_dissect_pcap_replay(file, file_len, 9, &h);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "unknown preset rc=%d", rc);
    CHECK(h == NULL, "a refused replay handed back a handle");

    rc = wz_dissect_pcap_replay(file, file_len, WZ_DISSECT_LIMITS_NONE, &h);
    CHECK(rc == WZ_DISSECT_OK, "pcap_replay rc=%d", rc);
    CHECK(h != NULL, "OK came back with no handle");

    written = 999;
    rc = wz_dissect_live_drain(h, from_file, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "replay drain rc=%d", rc);
    /* THE POPULATION. A replay that parsed the file and pushed nothing would
     * drain zero records and every comparison below would hold vacuously --
     * which is the shape this workspace refuses to call green. */
    CHECK(written == 3, "expected 3 records from a 3-packet capture, got %zu",
          written);

    /* The same three frames, at the same instants, through the door that was
     * already there. */
    rc = wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &live);
    CHECK(rc == WZ_DISSECT_OK, "control live_open rc=%d", rc);
    for (i = 0; i < 3; i++) {
        rc = wz_dissect_live_push(live, 1 /* ETHERNET */,
                                  (uint64_t)(i + 1) * 1000000u, frame, frame_len);
        CHECK(rc == WZ_DISSECT_OK, "control push %zu rc=%d", i, rc);
    }
    written = 999;
    rc = wz_dissect_live_drain(live, from_live, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "control drain rc=%d", rc);
    CHECK(written == 3, "the control arm must decode 3 too, got %zu", written);

    /* FIELD FOR FIELD. `flow_id` and `list_id` are the two a handle assigns
     * from its own counter, so they are compared across the arms rather than
     * to a constant -- two handles that saw the same one conversation must
     * have numbered it the same way. */
    for (i = 0; i < 3; i++) {
        CHECK(from_file[i].kind == WZ_DISSECT_KIND_KEEPALIVE,
              "record %zu kind=%u, expected KEEPALIVE", i,
              (unsigned)from_file[i].kind);
        CHECK(from_file[i].origin == WZ_DISSECT_ORIGIN_DATAGRAM,
              "record %zu origin=%u, expected DATAGRAM", i,
              (unsigned)from_file[i].origin);
        CHECK(from_file[i].anchor_space == WZ_DISSECT_ANCHOR_PACKET,
              "a datagram message anchors to a packet index");
        /* The FILE's packet ordinal is the anchor, exactly as a push ordinal
         * is on a live handle. */
        CHECK(from_file[i].anchor == (uint64_t)i, "record %zu anchor=%llu", i,
              (unsigned long long)from_file[i].anchor);
        CHECK(from_file[i].ts_ns == (uint64_t)(i + 1) * 1000000u,
              "record %zu ts_ns=%llu, the capture's own instant", i,
              (unsigned long long)from_file[i].ts_ns);
        CHECK(from_file[i].ts_ns == from_live[i].ts_ns &&
                  from_file[i].flow_id == from_live[i].flow_id &&
                  from_file[i].list_id == from_live[i].list_id &&
                  from_file[i].anchor == from_live[i].anchor &&
                  from_file[i].unit_len == from_live[i].unit_len &&
                  from_file[i].batch_index == from_live[i].batch_index &&
                  from_file[i].unit_offset == from_live[i].unit_offset &&
                  from_file[i].direction == from_live[i].direction &&
                  from_file[i].anchor_space == from_live[i].anchor_space &&
                  from_file[i].origin == from_live[i].origin &&
                  from_file[i].kind == from_live[i].kind &&
                  from_file[i].flags == from_live[i].flags,
              "record %zu differs between the file arm and the live arm", i);
    }
    wz_dissect_live_close(live);

    /* THE HANDLE IS AN ORDINARY LIVE HANDLE, and its coordinates CONTINUE. A
     * replay that left the packet counter at zero would anchor this push onto
     * the file's own packet 0, and a consumer would read two distinct messages
     * as one -- the exact merge `list_id` exists to prevent, arriving through
     * the other coordinate instead. */
    rc = wz_dissect_live_push(h, 1, 9000000u, frame, frame_len);
    CHECK(rc == WZ_DISSECT_OK, "push onto a replayed handle rc=%d", rc);
    written = 999;
    rc = wz_dissect_live_drain(h, from_file, 8, &written);
    CHECK(rc == WZ_DISSECT_OK, "post-replay drain rc=%d", rc);
    CHECK(written == 1, "one push is one record, got %zu", written);
    CHECK(from_file[0].anchor == 3,
          "a push after a 3-packet replay anchors at 3, got %llu",
          (unsigned long long)from_file[0].anchor);
    CHECK(wz_dissect_live_lost(h) == 0, "nothing was discarded, got %llu",
          (unsigned long long)wz_dissect_live_lost(h));
    wz_dissect_live_close(h);

    /* A DAMAGED capture is a CODE, not a crash and not an empty handle. */
    h = NULL;
    rc = wz_dissect_pcap_replay(truncated, sizeof truncated,
                                WZ_DISSECT_LIMITS_NONE, &h);
    CHECK(rc == WZ_DISSECT_ERR_BAD_CAPTURE, "truncated replay rc=%d", rc);
    CHECK(h == NULL, "a bad capture handed back a handle");

    /* Nulls are refused before anything is dereferenced. */
    rc = wz_dissect_pcap_replay(NULL, 0, WZ_DISSECT_LIMITS_NONE, &h);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null bytes replay rc=%d", rc);
    rc = wz_dissect_pcap_replay(file, file_len, WZ_DISSECT_LIMITS_NONE, NULL);
    CHECK(rc == WZ_DISSECT_ERR_INVALID_ARG, "null out replay rc=%d", rc);
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
     * refuses a library whose memory rules moved has nothing else to ask.
     * R2108 -- 12, for a THIRD reason: the record's LAYOUT changed. `list_id`
     * widened it 48 -> 56 and moved every field after `flow_id`. A consumer
     * reading by offset cannot notice that, which is why the revision is where
     * it is published -- and why the sizeof/offsetof block above is a pin on
     * THIS side of the boundary rather than a restatement of the Rust one.
     * R2171 -- 13 since wz_dissect_pcap_replay joined the set: the door that
     * reads a capture FILE into the LIVE handle, which is what let a frozen
     * capture drive the binary record family at all. A symbol, so the number
     * moves; the memory rule does not, because the handle it returns is the
     * one wz_dissect_live_close already took back.
     * R2205 -- 14 since wz_dissect_live_message_bytes joined it: the door that
     * hands back the BYTES a record was decoded from. One symbol, and the
     * memory rule deliberately left where it stands -- the bytes go into a
     * buffer the caller owns, so there is nothing new to give back. */
    CHECK(wz_dissect_abi_version() == 14, "abi version is %d, expected 14",
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
    /* R2114 (open-debt item 237) -- the expected revision is PER DOCUMENT now,
     * because `readable_surfaces` moved to 2 when it grew
     * `payload_field_types`. A single literal 1 across the table would have
     * had to become "any number" the first time one moved, and "any number" is
     * the assertion that stops noticing -- which is the whole point of a
     * consumer pinning the shape it was written against. */
    struct {
        const char *name;
        unsigned revision;
        char *doc;
    } revisioned[4];
    revisioned[0].name = "census";
    /* R2119 (open-debt item 455) -- 2: the census announced `first_packet`'s
     * retirement beside its successor `first_anchor`.
     * R2123 (open-debt item 453) -- 3: that key is now GONE, and the row gained
     * `anchor_intervals`. A consumer written against revision 1 or 2 that reads
     * `first_packet` gets nothing here, which is exactly what the revision
     * number exists to let it notice before parsing.
     * R2175 (item 552) -- 4, and NO KEY MOVED. This revision declares the five
     * keys on these rows whose VALUE comes from a closed set -- `kind`, `mode`,
     * `offset_space`, `asker`, `declarer` -- so a word joining one of them
     * costs a revision from now on. Ask wz_dissect_readable_surfaces for the
     * words.
     * R2180 (item 554) -- 5, and again NO KEY MOVED for a consumer's purposes:
     * the envelope now carries `planes`, the list of this document's top-level
     * keys that are planes, so `exchanges: null` is readable as "a plane this
     * build cannot feed" instead of by knowing which keys are planes.
     * R2184 (item 556) -- 6, and again no key: this revision says of each of
     * those five families whether the WORD decides which keys arrive beside it.
     * All five are passengers here -- these rows write every key and put `null`
     * where a value does not apply -- which is a promise a consumer can now
     * read rather than infer. */
    revisioned[0].revision = 6;
    revisioned[0].doc = NULL;
    rc = wz_dissect_pcap_census(pcap, sizeof pcap, &revisioned[0].doc);
    CHECK(rc == WZ_DISSECT_OK, "census rc=%d", rc);
    revisioned[1].name = "summary";
    /* R2121 (item 460) -- 2 when the skip census gained `inert_counters`.
     * R2122 (item 238) -- 3 when the health document's `framing` group stopped
     * disagreeing with the capture report's and gained the two counters the
     * report had carried since R311y624.
     *
     * THIS LITERAL IS THE CONSUMER'S OWN, and that is why it is not derived
     * from the Rust table: a check that read the number out of the thing it is
     * checking would agree with any value. The cost is that a revision bump
     * must be written here too, and R2121 did not -- it moved the summary to 2,
     * ran the crate tests, and left this at 1, which only this lane can see. */
    revisioned[1].revision = 3;
    revisioned[1].doc = NULL;
    rc = wz_dissect_pcap_summary(pcap, sizeof pcap, &revisioned[1].doc);
    CHECK(rc == WZ_DISSECT_OK, "summary rc=%d", rc);
    revisioned[2].name = "fields";
    /* R2175 (item 552) -- 2 when the PAYLOAD PLANE joined the pin. Revision 1
     * covered the document as emitted with no mapping declared, so
     * `payload_decode` and its fifteen keys shipped to consumers under no
     * revision at all, and its `state` vocabulary widened at R2170 with nothing
     * to say so.
     * R2182 (item 555) -- 3 when `fields[].kind` gained a declared vocabulary.
     * The tree's own discriminant: eight words, and the surface that reported
     * this had seven, because `opaque` is the arm no capture produces.
     * R2184 (item 556) -- 4 when every family here said whether its word
     * decides the keys beside it. THREE of the six do: `kind`, `state` and
     * `offset_space`, the last through two row emitters rather than two arms
     * of one match. Reading `value` off an `opaque` field is the parse this
     * revision exists to stop. */
    revisioned[2].revision = 4;
    revisioned[2].doc = NULL;
    rc = wz_dissect_pcap_fields(pcap, sizeof pcap, 0, &revisioned[2].doc);
    CHECK(rc == WZ_DISSECT_OK, "fields rc=%d", rc);
    revisioned[3].name = "readable_surfaces";
    /* R2175 (item 552) -- 3 when it gained `value_families`: which keys carry a
     * closed vocabulary and what it is, so a consumer can ASK rather than
     * discover a widened set as a switch fallthrough.
     * R2184 (item 556) -- 4 when those rows gained `carries`, and `word` /
     * `shapes` under it: which keys arrive beside each word, or `null` when the
     * word decides none. */
    revisioned[3].revision = 4;
    revisioned[3].doc = NULL;
    rc = wz_dissect_readable_surfaces(&revisioned[3].doc);
    CHECK(rc == WZ_DISSECT_OK, "surfaces rc=%d", rc);

    /* R2182 -- THE ENVELOPE MAY CARRY MORE AFTER THE REVISION, and this loop
     * used to forbid it by ending the expected prefix with `}`.
     *
     * R2180 added `planes` INSIDE the envelope object, so the census opens
     * `{"document":{"name":"census","revision":5,"planes":[...]}` and this
     * check failed on the comma -- Layer C1bo, and the number beside it was
     * stale too, which is the same miss its own comment above records R2121
     * making. Two defects in one line: a revision that had moved, and a shape
     * that had grown a key.
     *
     * What is asserted instead is exactly the promise the header makes: the
     * document OPENS with its name and its revision, before any body a consumer
     * would have to parse to find them. The delimiter test is what keeps that
     * strict -- without it `revision:5` is a prefix of `revision:50`, so a
     * consumer would read a shape it has never seen as one it was written
     * against. */
    for (size_t i = 0; i < sizeof revisioned / sizeof revisioned[0]; i++) {
        char want[128];
        int n = snprintf(want, sizeof want,
                         "{\"document\":{\"name\":\"%s\",\"revision\":%u",
                         revisioned[i].name, revisioned[i].revision);
        CHECK(n > 0 && (size_t)n < sizeof want, "the expected prefix fits");
        /* The prefix decides FIRST: a document shorter than `want` must not be
         * indexed at its length, which is a read past the terminator. */
        int opens = strncmp(revisioned[i].doc, want, (size_t)n) == 0;
        char after = opens ? revisioned[i].doc[n] : '\0';
        CHECK(opens && (after == ',' || after == '}'),
              "the %s document must OPEN with its own revision so a consumer "
              "reads it before parsing the body: %s",
              revisioned[i].name, revisioned[i].doc);
        wz_dissect_string_free(revisioned[i].doc);
    }

    /* R2114 (open-debt item 237) -- A FORMAT THIS LIBRARY DOES NOT SHIP,
     * SUPPLIED FROM C AS TEXT.
     *
     * The division of labour is the one this file already keeps for the
     * payload seam above: the Rust side owns the claim that a described layout
     * decodes real bytes, because that needs a capture with a payload in it,
     * and this file owns that a LINKING consumer can get the description
     * across at all -- accepted here, refused by line when it is unreadable,
     * and diagnosed with no capture. No new symbol appears for any of it,
     * which is the point: the record crossed as data through a door that was
     * already there, so the header's "no callbacks run" is untouched. */
    {
        char *described = NULL;
        rc = wz_dissect_pcap_fields_with_payloads(
            pcap, sizeof pcap, 0,
            "#profile=tag:u8,rest_of_it:rest\ndemo/temp=profile", &described);
        CHECK(rc == WZ_DISSECT_OK, "described fields rc=%d", rc);
        CHECK(described != NULL, "OK came back with no string");
        wz_dissect_string_free(described);

        /* An unreadable layout is a DECLARATION refusal, not a bad capture --
         * the same code an unknown format name gets, because both are the
         * caller's text rather than the traffic. */
        described = NULL;
        rc = wz_dissect_pcap_fields_with_payloads(pcap, sizeof pcap, 0,
                                                  "#profile=tag:u24le",
                                                  &described);
        CHECK(rc == WZ_DISSECT_ERR_DECLARATION,
              "an unreadable layout must be its own refusal, got rc=%d", rc);
        CHECK(described == NULL, "a refused declaration handed back a string");

        /* And the diagnostic names WHICH line and WHY, sight unseen, which is
         * what a UI needs while an operator is still typing a layout. */
        char *verdict = NULL;
        rc = wz_dissect_declarations_diagnose("#profile=tag:u24le", &verdict);
        CHECK(rc == WZ_DISSECT_OK, "diagnose rc=%d", rc);
        CHECK(strstr(verdict, "\"ok\":false") != NULL &&
                  strstr(verdict, "u24le") != NULL,
              "a bad layout must be refused and named: %s", verdict);
        wz_dissect_string_free(verdict);
    }

    /* R2102 (ABI 11) -- the LIVE door, which is the one capability in this
     * header that is not a call over a buffer the caller already holds whole. */
    if (check_live_door() != 0) {
        return 1;
    }

    /* R2171 (ABI 13) -- and the door that joins the two halves, so a FROZEN
     * capture can drive the record door a live tap uses. */
    if (check_replay_door() != 0) {
        return 1;
    }

    /* R2205 (ABI 14) -- and the BYTES under the description, which is the one
     * output of this library that is neither a document nor a scalar. */
    if (check_message_bytes_door() != 0) {
        return 1;
    }

    /* R2174 (open-debt item 551) -- A SELECTOR CARRYING NON-ASCII IS
     * DIAGNOSED, NOT FATAL.
     *
     * Here rather than only in the Rust tests because THE DIFFERENCE IS THE
     * WHOLE DEFECT. Inside the library the fault was a panic, which
     * `cargo test` catches and reports as a failure. Across this boundary it
     * could not even unwind -- a downstream consumer measured `fatal runtime
     * error: failed to initiate panic, error 5, aborting`, process exit 134,
     * with no return code to read and nothing to catch. The claim "it answers"
     * is only witnessed where a C caller stands.
     *
     * `wz_dissect_selector_diagnose` is the sharpest of the four doors that
     * reach the lexer: its own doc names its purpose as answering WHILE AN
     * OPERATOR IS TYPING, so in a GUI this was one keystroke killing the
     * application. If it regresses, THIS PROGRAM DIES rather than printing a
     * CHECK failure -- the correct shape for the fault, and why the lane reads
     * an exit status rather than only stdout. */
    {
        /* An unquoted Korean word, spelled in escapes so the fixture does not
         * depend on this file's own encoding surviving a tool: 로봇. */
        char *verdict = NULL;
        rc = wz_dissect_selector_diagnose("key == \xeb\xa1\x9c\xeb\xb4\x87", &verdict);
        CHECK(rc == WZ_DISSECT_OK, "a non-ASCII selector must be diagnosed, rc=%d", rc);
        CHECK(verdict != NULL, "OK came back with no verdict");
        CHECK(strstr(verdict, "\"ok\":true") != NULL,
              "an unquoted non-ASCII word is a word: %s", verdict);
        wz_dissect_string_free(verdict);

        /* A non-ASCII character that is NOT a word character (the euro sign).
         * It died by a DIFFERENT route than the one above: its lead byte 0xE2
         * reads as an accented 'a', which is alphanumeric, so the word scan
         * started on a character that is not a word character at all. A fix
         * that only rejected high bytes would have passed the case above and
         * still mis-lexed this one, which is why both are here. */
        verdict = NULL;
        rc = wz_dissect_selector_diagnose("key == \xe2\x82\xac", &verdict);
        CHECK(rc == WZ_DISSECT_OK, "a refusal is still a diagnosis, rc=%d", rc);
        CHECK(verdict != NULL, "OK came back with no verdict");
        CHECK(strstr(verdict, "\"ok\":false") != NULL,
              "the euro sign is not a word character: %s", verdict);
        wz_dissect_string_free(verdict);
    }

    printf("  C1bo: C consumer linked the cdylib and read the tree\n");
    return 0;
}
