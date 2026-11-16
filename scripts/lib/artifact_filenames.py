#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y736 (N28, N31) — READ THE ARTEFACT PATHS CARGO ITSELF DECLARES.

Reads `cargo --message-format=json` on stdin and writes one absolute artefact
path per line. That is the whole job: cargo names every file it considers an
output of the build, and it does so for CACHED units too -- a `compiler-artifact`
message carries `filenames` whether `fresh` is true or false, which is the
property the reaper needs and the one an mtime comparison can only approximate.

WHY THIS EXISTS RATHER THAN A `find` OVER `target/`. The reaper's question is
"which of these files does the current gate still use", and only cargo can
answer it: the hash in `deps/wz_capture-1538b00b5385bd2c` is cargo's internal
computation and is exposed nowhere else -- not in `--unit-graph`, which names
units logically and carries no filename, and not to a `rustc-wrapper`, which a
fresh unit never invokes at all. Both were checked at R311y734.

IT REFUSES AN EMPTY READ. A run that produced no artefact message means the
command did not build anything this tool understands, and a collector that
silently contributes nothing to the keep-set is how a reaper deletes a live
lane's output.

A BUILD SCRIPT'S RUN IS A UNIT TOO. Its output directory
(`<profile>/build/<pkg>-<hash>/out`) is named by no `compiler-artifact`
message, only by the `build-script-executed` one, and without it the reaper
(`artifact_reap.py`) would condemn every build script's output and the
fingerprint that says it is current. So that directory is declared as well.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable


def collect(lines: Iterable[str]) -> tuple[set[str], int]:
    """The paths the messages declare, and how many `compiler-artifact`
    messages were read."""
    seen: set[str] = set()
    messages = 0
    for line in lines:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        reason = msg.get("reason")
        if reason == "build-script-executed":
            out_dir = msg.get("out_dir")
            if out_dir:
                seen.add(out_dir)
            continue
        if reason != "compiler-artifact":
            continue
        messages += 1
        for path in msg.get("filenames") or []:
            seen.add(path)
        # `executable` is the test/bin binary and is NOT always repeated in
        # `filenames` -- for a test target it is the thing the reaper most
        # needs to keep, so it is taken separately rather than assumed.
        binary = msg.get("executable")
        if binary:
            seen.add(binary)
    return seen, messages


def selftest() -> int:
    stream = [
        "   Compiling foo v0.1.0",
        json.dumps(
            {
                "reason": "compiler-artifact",
                "filenames": ["/t/debug/deps/libfoo-0123456789abcdef.rlib"],
                "executable": None,
                "fresh": True,
            }
        ),
        json.dumps(
            {
                "reason": "compiler-artifact",
                "filenames": [],
                "executable": "/t/debug/deps/it-fedcba9876543210",
                "fresh": False,
            }
        ),
        json.dumps(
            {
                "reason": "build-script-executed",
                "out_dir": "/t/debug/build/foo-1111111111111111/out",
            }
        ),
        json.dumps({"reason": "compiler-message", "message": {}}),
        "{not json",
    ]
    failures = 0
    seen, messages = collect(stream)
    want = {
        "/t/debug/deps/libfoo-0123456789abcdef.rlib",
        "/t/debug/deps/it-fedcba9876543210",
        "/t/debug/build/foo-1111111111111111/out",
    }
    if seen != want:
        failures += 1
        print(f"artifact-filenames selftest FAIL: declared {sorted(seen)}, want {sorted(want)}")
    if messages != 2:
        failures += 1
        print(f"artifact-filenames selftest FAIL: {messages} artifact message(s), want 2")
    _, none = collect(stream[3:])
    if none != 0:
        failures += 1
        print("artifact-filenames selftest FAIL: a stream without an artifact message counted one")
    if failures:
        return 1
    print("artifact-filenames selftest: ok")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    if sys.argv[1:]:
        print("usage: artifact_filenames.py [--selftest] < cargo-json", file=sys.stderr)
        return 2
    seen, messages = collect(sys.stdin)
    if not messages:
        print(
            "artifact-filenames: no compiler-artifact message on stdin",
            file=sys.stderr,
        )
        return 1
    for path in sorted(seen):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
