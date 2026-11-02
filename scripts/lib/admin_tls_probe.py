#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4097 (no register item) -- a stock TLS 1.3 client against the fixed-memory admin node over Zephyr's
sockets (Layer Qz).

The node (deploy/zephyr-admin-node built with overlays/qemu_admin_fixed_tls.conf) takes a session only
through the secure channel of decision D9 (docs/session-lifecycle-intent.md), and its zid is the one
its key names (decision D1: the first sixteen bytes of SHA-256 over the DER SubjectPublicKeyInfo of
its certificate). This probe is the other end of that channel, written with nothing of wz's in it
(OpenSSL through Python's `ssl`): it presents a self-signed certificate of its own, completes the
mutual TLS 1.3 handshake with the node, and checks that

  1. the node accepted a client it had never heard of (the node pins nobody by a chain; it knows its
     peer by the key's zid, and the handshake proves the client holds the key it presented), and
  2. the certificate the node presented is the key whose zid the node's READY line claims, derived
     here from the certificate the handshake delivered, not from anything the node printed about it.

It does not speak zenoh: the verbs and the commander lists are held by the witness image
(deploy/zephyr-admin-loopback) and the host tests. What it adds to them is the product image, as built
for the board, on a socket, against a TLS stack that is not wz's.

    admin_tls_probe.py --port PORT --ready-line TEXT     run the probe against 127.0.0.1:PORT
    admin_tls_probe.py --selftest                        drive the zid derivation on known values
"""

import argparse
import hashlib
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile

# The line the node prints once it listens: `ZEPHYR-WZ-ADMIN READY <zid hex> <locator>`.
READY = re.compile(r"^ZEPHYR-WZ-ADMIN READY ([0-9a-f]+) (tls/\S+)\s*$")


def zenoh_hex(zid: bytes) -> str:
    """A zid as zenoh writes it: the little-endian number its bytes spell, in lowercase hex with the
    leading zeros dropped (wz_session_core::zid_hex::write_zenoh_hex)."""
    return format(int.from_bytes(zid, "little"), "x")


def zid_of_spki(spki_der: bytes) -> bytes:
    """Decision D1: the first sixteen bytes of SHA-256 over the key's DER SubjectPublicKeyInfo."""
    return hashlib.sha256(spki_der).digest()[:16]


def spki_of_certificate(cert_der: bytes) -> bytes:
    """The DER SubjectPublicKeyInfo of a certificate, read by `openssl` (the stock tool, not wz's)."""
    pem = ssl.DER_cert_to_PEM_cert(cert_der).encode()
    pub = subprocess.run(
        ["openssl", "x509", "-pubkey", "-noout"], input=pem, capture_output=True, check=True
    ).stdout
    return subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input=pub, capture_output=True, check=True
    ).stdout


def make_identity(directory: str) -> tuple[str, str]:
    """A fresh P-256 key and a self-signed certificate over it, as a device's operator makes one."""
    key, cert = os.path.join(directory, "key.pem"), os.path.join(directory, "cert.pem")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=wz-admin-tls-probe", "-days", "1",
        ],
        capture_output=True,
        check=True,
    )
    return cert, key


def probe(port: int, ready_line: str, timeout_s: float) -> list[str]:
    """Run the probe; the returned list is the problems found, empty for a pass."""
    ready = READY.match(ready_line)
    if not ready:
        return [f"the node's READY line is not one: {ready_line!r}"]
    claimed = ready.group(1)
    with tempfile.TemporaryDirectory() as directory:
        cert, key = make_identity(directory)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        # The node is no certificate authority's: it is known by the zid of its key, checked below.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(cert, key)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout_s) as raw:
                with context.wrap_socket(raw) as tls:
                    tls.settimeout(timeout_s)
                    tls.do_handshake()
                    version = tls.version()
                    der = tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError) as why:
            return [f"the handshake with the node did not complete: {why}"]
    problems = []
    if version != "TLSv1.3":
        problems.append(f"the channel is {version}, not TLSv1.3")
    if not der:
        return problems + ["the node presented no certificate"]
    derived = zenoh_hex(zid_of_spki(spki_of_certificate(der)))
    if derived != claimed:
        problems.append(
            f"the node claims zid {claimed} and the key of the certificate it presented names {derived}"
        )
    return problems


def selftest() -> int:
    ok = True

    def expect(what: str, got: object, want: object) -> None:
        nonlocal ok
        if got != want:
            ok = False
            print(f"  FAIL {what}: got {got!r}, want {want!r}")
        else:
            print(f"  ok   {what}")

    expect("the zid of 'abc' (FIPS 180-2's vector, first sixteen bytes)", zid_of_spki(b"abc").hex(),
           "ba7816bf8f01cfea414140de5dae2223")
    expect("a zid is its little-endian number in hex", zenoh_hex(bytes([0x1f]) + bytes(15)), "1f")
    expect("leading zeros are dropped", zenoh_hex(bytes([1, 2]) + bytes(14)), "201")
    expect("the kit's zid reads as zenoh writes it",
           zenoh_hex(bytes([0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC]) + bytes(10)), "ccbbaa005452")
    expect("the READY line is read", bool(READY.match("ZEPHYR-WZ-ADMIN READY ab12 tls/10.0.2.15:7448\r")), True)
    expect("a READY line of the lwIP node is not this node's",
           READY.match("ZEPHYR-WZ-ADMIN READY ab12 udp/10.0.0.1:7447 udp/10.0.0.2:7447"), None)
    print("admin-tls-probe selftest: " + ("ok" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--port", type=int)
    parser.add_argument("--ready-line")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.port is None or args.ready_line is None:
        parser.error("--port and --ready-line are required")
    problems = probe(args.port, args.ready_line, args.timeout)
    for problem in problems:
        print(f"admin-tls-probe: FAIL - {problem}")
    if not problems:
        print("admin-tls-probe: ok - a stock TLS 1.3 client completed the mutual handshake with the node, "
              "and the certificate it presented is the key its READY line names")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
