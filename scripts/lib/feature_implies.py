#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311n — wz facade → wz-runtime-tokio feature transitive-puller resolver.

Reads `cargo metadata --format-version=1 --no-deps` JSON from stdin and
emits shell-sourceable assignments naming, for every wz-runtime-tokio
feature starting with `codec-`, the set of wz facade features that
transitively activate it through forwards (`wz-runtime-tokio?/X`) or
local recursion. The minus-<codec> measurement lane in
`scripts/measure-codec-footprint.sh` consumes these to exclude the full
puller set so cargo's resolver cannot silently re-enable the codec via
a high-level consumer feature.

Output shape:

    PULLERS_codec_push="codec-push domain-codec preset-ap-client ..."
    PULLERS_codec_declare="codec-declare declare-final declare-interest ..."
    PULLERS_codec_frame="codec-frame codec-declare codec-push ..."

Variable names are `PULLERS_<codec_with_dashes_to_underscores>`.

Why a separate file instead of an inline heredoc in the bash script:
`cmd | python3 - <<EOF` is ambiguous in bash — the heredoc and the
pipe both redirect into python's stdin and the later redirection wins
(typically the heredoc), discarding the cargo metadata JSON. A
standalone module called with `python3 path/feature_implies.py` (stdin
= cargo metadata pipe) avoids the ambiguity entirely.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    md = json.load(sys.stdin)
    pkgs = {p["name"]: p for p in md["packages"]}
    wz = pkgs.get("wz", {}).get("features", {})
    rt = pkgs.get("wz-runtime-tokio", {}).get("features", {})

    rt_closure: dict[str, set[str]] = {}

    def resolve_rt(feat: str, seen: set[str]) -> set[str]:
        if feat in seen:
            return set()
        if feat in rt_closure:
            return rt_closure[feat]
        if feat not in rt:
            return {feat}
        seen = seen | {feat}
        result: set[str] = {feat}
        for target in rt[feat]:
            if target.startswith("dep:") or "/" in target:
                continue
            result |= resolve_rt(target, seen)
        rt_closure[feat] = result
        return result

    for feat in list(rt.keys()):
        resolve_rt(feat, set())

    wz_to_rt: dict[str, set[str]] = {}

    def resolve_wz(feat: str, seen: set[str]) -> set[str]:
        if feat in seen:
            return set()
        if feat in wz_to_rt:
            return wz_to_rt[feat]
        seen = seen | {feat}
        result: set[str] = set()
        for target in wz.get(feat, []):
            if target.startswith("dep:"):
                continue
            if "/" in target:
                sep = "?/" if "?/" in target else "/"
                dep, foreign = target.split(sep, 1)
                if dep == "wz-runtime-tokio":
                    result |= resolve_rt(foreign, set())
            else:
                result |= resolve_wz(target, seen)
        wz_to_rt[feat] = result
        return result

    for feat in list(wz.keys()):
        resolve_wz(feat, set())

    rt_to_wz: dict[str, set[str]] = {}
    for wz_feat, rt_set in wz_to_rt.items():
        for rt_feat in rt_set:
            rt_to_wz.setdefault(rt_feat, set()).add(wz_feat)

    codec_feats = sorted([f for f in rt if f.startswith("codec-")])
    for codec in codec_feats:
        pullers = sorted(rt_to_wz.get(codec, set()))
        if codec not in pullers:
            pullers.append(codec)
            pullers.sort()
        var = "PULLERS_" + codec.replace("-", "_")
        print('{}="{}"'.format(var, " ".join(pullers)))

    return 0


if __name__ == "__main__":
    sys.exit(main())
