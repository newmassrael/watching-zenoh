#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y736 (N28) — READ THE ARTEFACT PATHS CARGO ITSELF DECLARES.

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
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    seen: set[str] = set()
    messages = 0
    for line in sys.stdin:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
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
