#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""The GET round trip of a kit image that ANSWERS, as the bench host sees it (kit lane, scripts/kit-lane.sh).

    kit_rest_probe.py <rest port> <node key id> <out.json> <gets>

A router the lane started (zenohd with its REST plugin on 127.0.0.1:<rest port>) holds the kit's session. This
asks it, over HTTP, for the two documents the answering client declares, `<root>/status/connect` and
`<root>/config` with `<root>` = `@/<node key id>/peer`, once to warm up and `<gets>` times each for the
record, and writes every sample to the JSON file in the shape `scripts/lib/resource_budget_gate.py
--measure` reads (`get_status_ms`, `get_config_ms`, `get_status_bad`, `get_config_bad`, and the answer
sizes).

It measures nothing it was not asked and judges nothing: the verdict is the resource gate's. A node whose
session never comes up in the wait is exit 3 and a file with `session_up: false`, which that gate cannot
read as a latency, so a run with no answers is a failed run and not a fast one.
"""

from __future__ import annotations

import http.client
import json
import sys
import time

HOST = "127.0.0.1"
SESSION_WAIT_S = 150
WARMUP_GETS = 50


def get(conn: http.client.HTTPConnection, path: str) -> tuple[bool, int]:
    """One GET: whether it was answered with a body, and how long the body was."""
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read()
        return response.status == 200 and len(body) > 2, len(body)
    except (OSError, http.client.HTTPException):
        return False, 0


def timed_gets(port: int, path: str, count: int) -> tuple[list[float], int, int]:
    """`count` GETs of `path` on one connection (reopened after a failure): the milliseconds of the
    answered ones, how many were not answered, and the length of the last answer."""
    conn = http.client.HTTPConnection(HOST, port, timeout=5)
    times: list[float] = []
    bad = 0
    length = 0
    for _ in range(count):
        started = time.perf_counter()
        ok, size = get(conn, path)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if ok:
            times.append(elapsed_ms)
            length = size
        else:
            bad += 1
            conn.close()
            conn = http.client.HTTPConnection(HOST, port, timeout=5)
    conn.close()
    return times, bad, length


def session_up(port: int, base: str) -> bool:
    """Whether the kit's session answers through the router, tried once a second until the wait ends."""
    deadline = time.monotonic() + SESSION_WAIT_S
    while time.monotonic() < deadline:
        conn = http.client.HTTPConnection(HOST, port, timeout=3)
        ok, _ = get(conn, base + "/status/connect")
        conn.close()
        if ok:
            return True
        time.sleep(1)
    return False


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 64
    port_text, key_id, out_path, gets_text = argv
    port, gets = int(port_text), int(gets_text)
    base = f"/@/{key_id}/peer"
    result: dict = {"node_id": key_id, "session_up": False}
    if session_up(port, base):
        result["session_up"] = True
        timed_gets(port, base + "/status/connect", WARMUP_GETS)  # warm-up, not kept
        result["get_status_ms"], result["get_status_bad"], result["get_status_bytes"] = timed_gets(
            port, base + "/status/connect", gets
        )
        result["get_config_ms"], result["get_config_bad"], result["get_config_bytes"] = timed_gets(
            port, base + "/config", gets
        )
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle)
    print({key: (len(value) if isinstance(value, list) else value) for key, value in result.items()})
    return 0 if result["session_up"] else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
