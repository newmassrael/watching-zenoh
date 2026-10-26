#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3716 (no register item) — read and rewrite QUIC Initial packets with the
standard library only, for `capture_anonymise.py`.

## Why this exists

A QUIC Initial packet is encrypted, but under keys anyone derives from the
Destination Connection ID of the client's first Initial (RFC 9001 §5.2), and
the client's Initials carry its TLS ClientHello, whose `server_name` names the
host it connects to. A capture that keeps the Initial as it is keeps that name
readable to anyone, while a search of the file's bytes for it finds nothing.
The anonymiser reads the Initials through this module, replaces the name, and
protects the packet again, so the packet keeps its length, its packet number
and a valid authentication tag; the leak check searches the plaintexts this
module recovers from the output.

Versions 1 (RFC 9001) and 2 (RFC 9369) are read. The cipher of Initial packets
is AEAD_AES_128_GCM with AES header protection for both, so AES-128 (FIPS 197,
the encryption direction only), GCM (NIST SP 800-38D) and HKDF (RFC 5869) are
written here: the hooks and hosted CI run this with no package beyond Python.
The selftest checks all of it against the sample packets of RFC 9001 and
RFC 9369 Appendix A.
"""

import hashlib
import hmac
import struct

# ── AES-128, encryption only ─────────────────────────────────────────────────


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _make_sbox():
    """The S-box from its definition (the inverse in GF(2^8), then the affine
    map), walking the field with the generator 3 and its inverse."""
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return bytes(sbox)


SBOX = _make_sbox()
XTIME = bytes(((b << 1) ^ (0x1B if b & 0x80 else 0)) & 0xFF for b in range(256))
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def aes128_key_schedule(key):
    w = list(key)
    for i in range(4, 44):
        t = w[4 * (i - 1) : 4 * i]
        if i % 4 == 0:
            t = [SBOX[t[1]] ^ RCON[i // 4 - 1], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
        w.extend(w[4 * (i - 4) + j] ^ t[j] for j in range(4))
    return [w[16 * r : 16 * r + 16] for r in range(11)]


def aes128_encrypt(rounds, block):
    s = [b ^ k for b, k in zip(block, rounds[0])]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        # ShiftRows: the state is column-major, row i rotates left by i.
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if r != 10:
            m = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c : c + 4]
                t = a0 ^ a1 ^ a2 ^ a3
                m += [
                    a0 ^ t ^ XTIME[a0 ^ a1],
                    a1 ^ t ^ XTIME[a1 ^ a2],
                    a2 ^ t ^ XTIME[a2 ^ a3],
                    a3 ^ t ^ XTIME[a3 ^ a0],
                ]
            s = m
        s = [b ^ k for b, k in zip(s, rounds[r])]
    return bytes(s)


# ── AES-128-GCM ──────────────────────────────────────────────────────────────

_GCM_R = 0xE1 << 120


def _gf_mul(x, y):
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
    return z


def _ghash(h, aad, ct):
    x = 0
    for data in (aad, ct):
        for i in range(0, len(data), 16):
            block = data[i : i + 16].ljust(16, b"\0")
            x = _gf_mul(x ^ int.from_bytes(block, "big"), h)
    lengths = struct.pack("!QQ", 8 * len(aad), 8 * len(ct))
    return _gf_mul(x ^ int.from_bytes(lengths, "big"), h)


def _ctr(rounds, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 16):
        counter = nonce + struct.pack("!I", 2 + i // 16)
        stream = aes128_encrypt(rounds, counter)
        chunk = data[i : i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, stream))
    return bytes(out)


def _tag(rounds, nonce, aad, ct):
    h = int.from_bytes(aes128_encrypt(rounds, b"\0" * 16), "big")
    s = _ghash(h, aad, ct) ^ int.from_bytes(aes128_encrypt(rounds, nonce + b"\0\0\0\1"), "big")
    return s.to_bytes(16, "big")


def gcm_seal(key, nonce, aad, plaintext):
    rounds = aes128_key_schedule(key)
    ct = _ctr(rounds, nonce, plaintext)
    return ct + _tag(rounds, nonce, aad, ct)


def gcm_open(key, nonce, aad, sealed):
    """The plaintext, or None when the tag does not verify."""
    if len(sealed) < 16:
        return None
    rounds = aes128_key_schedule(key)
    ct, tag = sealed[:-16], sealed[-16:]
    if not hmac.compare_digest(_tag(rounds, nonce, aad, ct), tag):
        return None
    return _ctr(rounds, nonce, ct)


# ── HKDF and the Initial keys ────────────────────────────────────────────────


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\0"
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


VERSION_1 = 0x00000001
VERSION_2 = 0x6B3343CF

# Per version: the Initial salt, the prefix of the packet protection labels,
# and the long header type of an Initial packet.
VERSIONS = {
    VERSION_1: (bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), b"quic ", 0),
    VERSION_2: (bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), b"quicv2 ", 1),
}
# The other long header types of each version that carry a Length field
# (0-RTT and Handshake); Retry runs to the end of the datagram.
LENGTHED = {VERSION_1: (1, 2), VERSION_2: (2, 3)}

CLIENT = "client"
SERVER = "server"


class Keys:
    def __init__(self, version, odcid, side):
        salt, prefix, _ = VERSIONS[version]
        initial = hkdf_extract(salt, odcid)
        secret = hkdf_expand_label(initial, b"client in" if side == CLIENT else b"server in", 32)
        self.key = hkdf_expand_label(secret, prefix + b"key", 16)
        self.iv = hkdf_expand_label(secret, prefix + b"iv", 12)
        self.hp = aes128_key_schedule(hkdf_expand_label(secret, prefix + b"hp", 16))

    def mask(self, sample):
        return aes128_encrypt(self.hp, sample)

    def nonce(self, pn):
        return bytes(a ^ b for a, b in zip(self.iv, pn.to_bytes(12, "big")))


# ── packets ──────────────────────────────────────────────────────────────────


class Malformed(Exception):
    pass


def varint(buf, pos):
    if pos >= len(buf):
        raise Malformed("varint past the end")
    n = 1 << (buf[pos] >> 6)
    if pos + n > len(buf):
        raise Malformed("varint past the end")
    v = buf[pos] & 0x3F
    for b in buf[pos + 1 : pos + n]:
        v = (v << 8) | b
    return v, pos + n


class Initial:
    """One Initial packet whose protection verified, at `start..end` of its
    datagram."""

    def __init__(self, start, end, version, dcid, scid, odcid, side, opened):
        self.start = start
        self.end = end
        self.version = version
        self.dcid = dcid
        self.scid = scid
        self.odcid = odcid
        self.side = side
        self.keys, self.aad, self.pn_len, self.pn, self.plaintext = opened
        # The unprotected header ends with the packet number.
        self.pn_offset = len(self.aad) - self.pn_len

    def crypto_frames(self):
        """(stream offset, offset in the plaintext, length) of each CRYPTO frame."""
        return crypto_frames(self.plaintext)


def crypto_frames(plain):
    out = []
    pos = 0
    while pos < len(plain):
        kind, pos = varint(plain, pos)
        if kind in (0x00, 0x01):  # PADDING, PING
            continue
        if kind in (0x02, 0x03):  # ACK, ACK with ECN counts
            _, pos = varint(plain, pos)
            _, pos = varint(plain, pos)
            count, pos = varint(plain, pos)
            _, pos = varint(plain, pos)
            for _ in range(2 * count + (3 if kind == 0x03 else 0)):
                _, pos = varint(plain, pos)
            continue
        if kind == 0x06:  # CRYPTO
            off, pos = varint(plain, pos)
            n, pos = varint(plain, pos)
            if pos + n > len(plain):
                raise Malformed("CRYPTO frame past the end")
            out.append((off, pos, n))
            pos += n
            continue
        if kind == 0x1C:  # CONNECTION_CLOSE
            _, pos = varint(plain, pos)
            _, pos = varint(plain, pos)
            n, pos = varint(plain, pos)
            pos += n
            continue
        raise Malformed("frame type 0x%x in an Initial" % kind)
    return out


def _unprotect(data, start, end, pn_offset, version, odcid, side):
    keys = Keys(version, odcid, side)
    pkt = data[start:end]
    sample = pkt[pn_offset + 4 : pn_offset + 20]
    if len(sample) != 16:
        return None
    mask = keys.mask(sample)
    first = pkt[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(a ^ b for a, b in zip(pkt[pn_offset : pn_offset + pn_len], mask[1 : 1 + pn_len]))
    aad = bytes([first]) + pkt[1:pn_offset] + pn_bytes
    pn = int.from_bytes(pn_bytes, "big")
    plain = gcm_open(keys.key, keys.nonce(pn), aad, pkt[pn_offset + pn_len :])
    if plain is None:
        return None
    return keys, aad, pn_len, pn, plain


class Reader:
    """The Initials of one capture, read in the order its datagrams were
    sent. It keeps the connection IDs it has seen, mapped to the client's
    original Destination Connection ID, because only the client's first
    Initials carry the ID their keys come from."""

    def __init__(self):
        self.odcid = {}

    def _candidates(self, version, dcid, scid):
        # A client's first Initials: the keys come from their own DCID.
        yield dcid, CLIENT
        for cid in (scid, dcid):
            odcid = self.odcid.get((version, cid))
            if odcid is not None:
                yield odcid, CLIENT
                yield odcid, SERVER

    def datagram(self, data):
        """The Initials of one UDP payload whose protection verifies.

        A datagram holds long header packets one after another, each with its
        Length, then at most one short header packet running to the end. A
        packet this reader cannot delimit (a Retry, a version it does not
        know, bytes that are not QUIC at all) ends the walk: what follows it
        is kept as it is, and only a packet whose authentication tag verified
        is reported, which is what tells a QUIC Initial from bytes that only
        look like one."""
        found = []
        pos = 0
        while pos + 7 <= len(data):
            first = data[pos]
            if not first & 0x80:
                break  # a short header runs to the end
            version = struct.unpack("!I", data[pos + 1 : pos + 5])[0]
            if version not in VERSIONS:
                break
            p = pos + 5
            dlen = data[p]
            dcid = bytes(data[p + 1 : p + 1 + dlen])
            p += 1 + dlen
            if p >= len(data) or dlen > 20:
                break
            slen = data[p]
            scid = bytes(data[p + 1 : p + 1 + slen])
            p += 1 + slen
            if slen > 20:
                break
            kind = (first >> 4) & 0x03
            try:
                if kind == VERSIONS[version][2]:
                    tlen, p = varint(data, p)
                    p += tlen
                elif kind not in LENGTHED[version]:
                    break  # a Retry runs to the end
                length, p = varint(data, p)
            except Malformed:
                break
            end = p + length
            if end > len(data):
                break
            if kind == VERSIONS[version][2]:
                for odcid, side in self._candidates(version, dcid, scid):
                    opened = _unprotect(data, pos, end, p - pos, version, odcid, side)
                    if opened is None:
                        continue
                    found.append(Initial(pos, end, version, dcid, scid, odcid, side, opened))
                    self.odcid[(version, scid)] = odcid
                    self.odcid[(version, dcid)] = odcid
                    break
            pos = end
        return found


# ── the ClientHello's server names ───────────────────────────────────────────

EXT_SERVER_NAME = 0x0000


class Incomplete(Exception):
    """The stream does not hold a whole ClientHello."""


def client_hello_server_names(stream):
    """(offset, length) in `stream` of every host name in the `server_name`
    extension of the ClientHello the client's Initial CRYPTO stream begins
    with (RFC 8446 §4.1.2, RFC 6066 §3)."""
    if len(stream) < 4:
        raise Incomplete()
    if stream[0] != 0x01:
        raise Malformed("the Initial CRYPTO stream does not begin with a ClientHello")
    body_len = int.from_bytes(stream[1:4], "big")
    end = 4 + body_len
    if len(stream) < end:
        raise Incomplete()
    p = 4 + 2 + 32  # legacy_version, random
    p += 1 + stream[p]  # legacy_session_id
    p += 2 + int.from_bytes(stream[p : p + 2], "big")  # cipher_suites
    p += 1 + stream[p]  # legacy_compression_methods
    ext_end = p + 2 + int.from_bytes(stream[p : p + 2], "big")
    p += 2
    if ext_end > end:
        raise Malformed("extensions past the ClientHello")
    names = []
    while p + 4 <= ext_end:
        etype, elen = struct.unpack("!HH", stream[p : p + 4])
        data = p + 4
        if data + elen > ext_end:
            raise Malformed("an extension past the ClientHello")
        if etype == EXT_SERVER_NAME and elen:
            q = data + 2
            list_end = q + int.from_bytes(stream[data:q], "big")
            while q + 3 <= list_end:
                kind = stream[q]
                n = int.from_bytes(stream[q + 1 : q + 3], "big")
                if kind == 0:  # host_name
                    names.append((q + 3, n))
                q += 3 + n
        p = data + elen
    return names


def protect(initial, plaintext):
    """The packet `initial` with `plaintext` in place of its own (of the same
    length), sealed and header-protected again under the same keys and packet
    number. The same plaintext gives back the bytes the packet had."""
    if len(plaintext) != len(initial.plaintext):
        raise ValueError("a rewritten Initial keeps its length")
    return seal(initial.keys, initial.aad, initial.pn_len, initial.pn, plaintext)


def seal(keys, aad, pn_len, pn, plaintext):
    """A protected packet from its unprotected header `aad` (which ends with
    the `pn_len`-byte packet number `pn`) and its plaintext (RFC 9001 §5.3,
    §5.4)."""
    pn_offset = len(aad) - pn_len
    sealed = gcm_seal(keys.key, keys.nonce(pn), aad, plaintext)
    mask = keys.mask(sealed[4 - pn_len : 20 - pn_len])
    out = bytearray(aad)
    out[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        out[pn_offset + i] ^= mask[1 + i]
    return bytes(out) + sealed


# ── selftest: the sample packets of RFC 9001 and RFC 9369, Appendix A ────────

# The client's CRYPTO frame, a ClientHello naming `example.com`, the same in
# both RFCs; PADDING frames fill the payload to 1162 bytes.
SAMPLE_CLIENT_CRYPTO = bytes.fromhex(
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
    "75300901100f088394c8f03e51570806048000ffff"
)
SAMPLE_ODCID = bytes.fromhex("8394c8f03e515708")
# The server's answer: an ACK and a CRYPTO frame holding its ServerHello.
SAMPLE_SERVER_PAYLOAD = bytes.fromhex(
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
    "020304"
)
# Per version: the client's unprotected header, the sha256 of the 1200-byte
# protected client packet the RFC prints, and the server's protected packet.
SAMPLES = {
    VERSION_1: (
        bytes.fromhex("c300000001088394c8f03e5157080000449e00000002"),
        "73fa0210cb4a5a17dc10b9dc98e5cc359ba1c20fe7c0e93a9e1dcb473c37e097",
        bytes.fromhex(
            "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
            "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
            "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
            "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
            "2158407dd074ee"
        ),
    ),
    VERSION_2: (
        bytes.fromhex("d36b3343cf088394c8f03e5157080000449e00000002"),
        "b0b766fe7e762577072d3365cc4f9635809210cba301a67f8457f5e6fdac5c68",
        bytes.fromhex(
            "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698"
            "baeea26b91eb761d9b89237bbf87263017915358230035f7fd3945d88965cf17"
            "f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e42757507698075b2"
            "c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca8"
            "4bed8521e2e140"
        ),
    ),
}


def sample_client_packet(version):
    header, _, _ = SAMPLES[version]
    plaintext = SAMPLE_CLIENT_CRYPTO.ljust(1162, b"\0")
    return seal(Keys(version, SAMPLE_ODCID, CLIENT), header, 4, 2, plaintext)


def selftest(check):
    """Check this module against the RFC samples; `check(cond, what)` records
    each check."""
    k = Keys(VERSION_1, SAMPLE_ODCID, CLIENT)
    check(k.key.hex() == "1f369613dd76d5467730efcbe3b1a22d", "RFC 9001 A.1: the client key")
    check(k.iv.hex() == "fa044b2f42a3fd3b46fb255c", "RFC 9001 A.1: the client IV")
    s = Keys(VERSION_1, SAMPLE_ODCID, SERVER)
    check(s.key.hex() == "cf3a5331653c364c88f0f379b6067e37", "RFC 9001 A.1: the server key")
    for version, (_, digest, server_packet) in SAMPLES.items():
        name = "v%x" % version
        client_packet = sample_client_packet(version)
        check(
            hashlib.sha256(client_packet).hexdigest() == digest,
            "%s A.2: the protected client Initial is the RFC's, byte for byte" % name,
        )
        reader = Reader()
        found = reader.datagram(client_packet)
        check(len(found) == 1 and found[0].side == CLIENT, "%s: the client Initial is read" % name)
        if not found:
            continue
        initial = found[0]
        check(initial.plaintext[: len(SAMPLE_CLIENT_CRYPTO)] == SAMPLE_CLIENT_CRYPTO, "%s: it opens" % name)
        check(protect(initial, initial.plaintext) == client_packet, "%s: sealing it again gives its bytes" % name)
        frames = initial.crypto_frames()
        check(len(frames) == 1 and frames[0][0] == 0, "%s: one CRYPTO frame at stream offset 0" % name)
        _, at, n = frames[0]
        stream = initial.plaintext[at : at + n]
        names = client_hello_server_names(stream)
        check(
            [stream[o : o + m] for o, m in names] == [b"example.com"],
            "%s: the ClientHello names example.com" % name,
        )
        found = reader.datagram(server_packet)
        check(
            len(found) == 1 and found[0].side == SERVER and found[0].plaintext == SAMPLE_SERVER_PAYLOAD,
            "%s A.3: the server Initial opens under the client's original DCID" % name,
        )
        if found:
            check(protect(found[0], found[0].plaintext) == server_packet, "%s A.3: and seals back" % name)
        # A tampered packet does not verify, and is not reported.
        bad = bytearray(client_packet)
        bad[-1] ^= 1
        check(Reader().datagram(bytes(bad)) == [], "%s: a packet whose tag fails is not read" % name)
