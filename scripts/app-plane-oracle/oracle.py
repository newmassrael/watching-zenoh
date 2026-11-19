#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The checks of the application-plane oracle lane (scripts/app-plane-oracle.sh).

The lane exchanges protected frames and replay answers between wz's party and a deployment's
party, both ways, and this file is the part of it that holds no process: it reads the lane
file a deployment hands over, writes one check directory per check for the two parties, and
judges the transcripts the parties printed. The contract the two parties share is
docs/app-plane-oracle.md's; nothing here knows any deployment's layout, constants or values.

    oracle.py prepare <lane-file> <scratch>   the check directories and the lane's own lists
    oracle.py judge <scratch>                 one line per check aspect, then the verdict
    oracle.py --selftest                      the plans, the refusals and the judge, on
                                              synthetic transcripts

Exit status: 0 PASS (or prepared), 1 FAIL, 2 a lane file refused.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

KINDS = ("e2e", "replay")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
BUILD_ENV = re.compile(r"^WZ_(POLICY|LIMIT)_[A-Z0-9_]+$")
MAX_FRAMES = 256
DIRECTIONS = ("wz-sends", "peer-sends")
# The policy a replay check's shape is: the lane states it per build, never the lane file.
SHAPE_POLICY = "WZ_POLICY_REPLAY_REPLY_SHAPE"


class Refused(Exception):
    """A lane file the lane cannot run, said by name."""


# ── the plan ────────────────────────────────────────────────────────────────


def payload(index: int, length: int) -> bytes:
    """Frame `index`'s payload: synthetic bytes, different for every frame."""
    return bytes((0xA5 ^ (index * 31 + j * 7)) & 0xFF for j in range(length))


def e2e_plan(length: int, beyond: int) -> list[tuple[str, bytes]]:
    """The frames a sender builds, in order, and what it does with each.

    send: put once. twice: put twice (the second is a repeated counter). hold: build it,
    which spends its counter, and put nothing (a gap). corrupt: put a copy with its last
    byte XOR 0x01, then the frame. `beyond` frames are held in one run, which the lane file
    states is past the deployment's allowance for a gap.
    """
    actions = ["send", "send", "twice", "hold", "send"]
    actions += ["hold"] * beyond
    actions += ["send", "send", "send", "corrupt", "send"]
    return [(action, payload(i, length)) for i, action in enumerate(actions)]


def arrivals(plan: list[tuple[str, bytes]]) -> list[tuple[int, str]]:
    """What a receiver is handed, in order: (plan index, what it is)."""
    out: list[tuple[int, str]] = []
    for i, (action, _) in enumerate(plan):
        if action == "send":
            out.append((i, "frame"))
        elif action == "twice":
            out += [(i, "frame"), (i, "repeat")]
        elif action == "corrupt":
            out += [(i, "corrupt"), (i, "frame")]
    return out


def e2e_anchors(plan: list[tuple[str, bytes]]) -> dict[int, str]:
    """Arrival -> the class every implementation owes it; the others are compared only.

    The first two frames are intact (the first is a stream's baseline), the repeat breaks
    the counter rule, the first frame after the held run does too (the lane file says the
    run is past the allowance), and the corrupted copy fails its integrity.
    """
    got = arrivals(plan)
    anchors = {0: "intact", 1: "intact", 2: "intact"}
    for n, (_, what) in enumerate(got):
        if what == "repeat":
            anchors[n] = "counter"
        if what == "corrupt":
            anchors[n] = "integrity"
    first_hold = next(i for i, (a, _) in enumerate(plan) if a == "hold")
    run_end = max(i for i, (a, _) in enumerate(plan) if a == "hold")
    if run_end > first_hold:
        after_run = next(n for n, (i, _) in enumerate(got) if i > run_end)
        anchors[after_run] = "counter"
    return anchors


# ── prepare ─────────────────────────────────────────────────────────────────


def _text(check: dict, field: str, base: Path, required: bool = True) -> str | None:
    """A profile or values document: inline JSON, or a path relative to the lane file."""
    value = check.get(field)
    if value is None:
        if required:
            raise Refused(f"check {check.get('name')!r}: no {field}")
        return None
    if isinstance(value, str):
        path = base / value
        if not path.is_file():
            raise Refused(f"check {check.get('name')!r}: {field} names {value}, which is not a file")
        return path.read_text(encoding="utf-8")
    if isinstance(value, dict):
        return json.dumps(value)
    raise Refused(f"check {check.get('name')!r}: {field} is neither a document nor a path")


def _positive(check: dict, field: str, default: int | None = None) -> int:
    value = check.get(field, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise Refused(f"check {check.get('name')!r}: {field} must be a positive integer, not {value!r}")
    return value


def _count(check: dict, field: str, default: int) -> int:
    value = check.get(field, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise Refused(f"check {check.get('name')!r}: {field} must be an integer >= 0, not {value!r}")
    return value


def read_lane(text: str) -> dict:
    """The lane file, checked for the lane's own shape; the documents it carries are the
    parties' to read."""
    try:
        lane = json.loads(text)
    except json.JSONDecodeError as err:
        raise Refused(f"the lane file is not JSON: {err}") from err
    if not isinstance(lane, dict):
        raise Refused("the lane file is not a JSON object")
    checks = lane.get("checks")
    if not isinstance(checks, list) or not checks:
        raise Refused("the lane file names no check")
    seen: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            raise Refused("a check is not a JSON object")
        name = check.get("name")
        if not isinstance(name, str) or not NAME.match(name):
            raise Refused(f"check name {name!r} is not lower-case letters, digits and dashes")
        if name in seen:
            raise Refused(f"check {name!r} is named twice")
        seen.add(name)
        if check.get("kind") not in KINDS:
            raise Refused(f"check {name!r}: kind {check.get('kind')!r} is not one of {', '.join(KINDS)}")
        if not isinstance(check.get("key"), str) or not check["key"]:
            raise Refused(f"check {name!r}: no key")
    wz = lane.get("wz", {})
    if not isinstance(wz, dict):
        raise Refused("wz is not a JSON object")
    features = wz.get("features", "")
    if not isinstance(features, str) or not re.match(r"^[a-z0-9,-]*$", features):
        raise Refused(f"wz.features {features!r} is not a comma list of feature names")
    env = wz.get("build_env", {})
    if not isinstance(env, dict):
        raise Refused("wz.build_env is not a JSON object")
    for key, value in env.items():
        if not BUILD_ENV.match(key):
            raise Refused(f"wz.build_env names {key}: only WZ_POLICY_* and WZ_LIMIT_* are a build's to state")
        if key == SHAPE_POLICY:
            raise Refused(f"wz.build_env names {key}: the lane builds it from each check's segment")
        if not isinstance(value, str) or not re.match(r"^[A-Za-z0-9_.-]+$", value):
            raise Refused(f"wz.build_env {key} = {value!r} is not a plain value")
    session = lane.get("session", {})
    if not isinstance(session, dict):
        raise Refused("session is not a JSON object")
    mode = session.get("connect_mode", "client")
    if mode not in ("client", "peer"):
        raise Refused(f"session.connect_mode {mode!r} is neither client nor peer")
    if "key_ids" in lane:
        read_key_ids(lane["key_ids"], features)
    return lane


def key_problem(key: str) -> str | None:
    """Why `key` is not a canonical key expression; None when it is.

    The rules of zenoh's canon: no empty chunk (so no leading, trailing or doubled slash),
    no `#` or `?`, `$` only as `$*` inside a longer chunk, `*` alone or as `**` alone, never
    `**/**` and never `**/*` (whose canon is `*/**`). The session's own door judges the same
    rules again at open; this answers before anything is built.
    """
    if not key:
        return "it is empty"
    chunks = key.split("/")
    for n, chunk in enumerate(chunks):
        if not chunk:
            return "it has an empty chunk"
        if any(c in chunk for c in "#? \t\r\n"):
            return f"chunk {chunk!r} holds a character no key expression holds"
        if chunk in ("*", "**"):
            if chunk == "**" and n + 1 < len(chunks) and chunks[n + 1] in ("*", "**"):
                return f"'**/{chunks[n + 1]}' is not canonical"
            continue
        if chunk == "$*":
            return "chunk '$*' is not canonical: it is '*'"
        bare = chunk.replace("$*", "")
        if "*" in bare or "$" in bare:
            return f"chunk {chunk!r} holds '*' or '$' outside a '$*'"
        if "$*$*" in chunk:
            return f"chunk {chunk!r} repeats '$*'"
    return None


KEY_FORMS = ("declared", "shared", "literal")


def read_key_ids(key_ids: object, features: str) -> tuple[list[tuple[int, str]], dict[str, str]]:
    """The shared key-id dictionary and the per-endpoint forms, checked; refused by name."""
    if "shared-key-ids" not in features.split(","):
        raise Refused("key_ids is given but wz.features does not name shared-key-ids, "
                      "so wz's build would have no dictionary to hand it")
    if not isinstance(key_ids, dict):
        raise Refused("key_ids is not a JSON object")
    entries = key_ids.get("dictionary")
    if not isinstance(entries, list) or not entries:
        raise Refused("key_ids.dictionary is not a non-empty list")
    out: list[tuple[int, str]] = []
    ids: set[int] = set()
    keys: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise Refused("a key_ids.dictionary entry is not a JSON object")
        ident, key = entry.get("id"), entry.get("key")
        if not isinstance(ident, int) or isinstance(ident, bool) or not 1 <= ident <= 0xFFFF:
            raise Refused(f"key_ids: id {ident!r} is not 1 to 65535 (0 names no key)")
        if not isinstance(key, str):
            raise Refused(f"key_ids: id {ident} has no key")
        problem = key_problem(key)
        if problem is not None:
            raise Refused(f"key_ids: key {key!r} is not a canonical key expression: {problem}")
        if ident in ids:
            raise Refused(f"key_ids: id {ident} is named twice")
        if key in keys:
            raise Refused(f"key_ids: key {key!r} is named twice")
        ids.add(ident)
        keys.add(key)
        out.append((ident, key))
    forms = key_ids.get("forms", {})
    if not isinstance(forms, dict):
        raise Refused("key_ids.forms is not a JSON object")
    for side, form in forms.items():
        if side not in ("listen", "connect"):
            raise Refused(f"key_ids.forms names {side!r}: a form is stated for listen or connect")
        if form not in KEY_FORMS:
            raise Refused(f"key_ids.forms.{side} {form!r} is not one of {', '.join(KEY_FORMS)}")
    return out, dict(forms)


def _segment(check: dict, base: Path, out: Path, params: dict) -> None:
    """A check's optional segment profile: written beside the check, and its params set."""
    segment = check.get("segment")
    params["segmented"] = 0
    if segment is None:
        return
    name = check["name"]
    if not isinstance(segment, dict):
        raise Refused(f"check {name!r}: segment is not a JSON object")
    segment = dict(segment, name=name)
    (out / "segment-profile.json").write_text(_text(segment, "profile", base) or "", encoding="utf-8")
    (out / "segment-values.json").write_text(_text(segment, "values", base) or "", encoding="utf-8")
    params["segmented"] = 1
    params["first_transfer"] = _count(segment, "first_transfer", 0)
    params["chunk_bytes"] = _positive(segment, "chunk_bytes")


def prepare(lane_path: Path, scratch: Path) -> list[str]:
    """Write the check directories and the lane's lists; the lines of checks.tsv."""
    lane = read_lane(lane_path.read_text(encoding="utf-8"))
    base = lane_path.parent
    rows: list[str] = []
    checks_dir = scratch / "checks"
    if checks_dir.exists():
        shutil.rmtree(checks_dir)
    dictionary: list[tuple[int, str]] = []
    forms: dict[str, str] = {}
    if "key_ids" in lane:
        dictionary, forms = read_key_ids(lane["key_ids"], lane.get("wz", {}).get("features", ""))
    for check in lane["checks"]:
        name = check["name"]
        out = checks_dir / name
        out.mkdir(parents=True)
        length = _positive(check, "payload_len")
        params = {"kind": check["kind"], "key": check["key"],
                  "first_counter": _count(check, "first_counter", 0),
                  "frame_max": length + 256}
        for side, form in sorted(forms.items()):
            params[f"key_form_{side}"] = form
        if dictionary:
            (out / "key-ids").write_text("".join(f"{i} {k}\n" for i, k in dictionary), encoding="utf-8")
        (out / "profile.json").write_text(_text(check, "profile", base) or "", encoding="utf-8")
        (out / "values.json").write_text(_text(check, "values", base) or "", encoding="utf-8")
        variant = "frame"
        if check["kind"] == "e2e":
            beyond = _positive(check, "skip_beyond_gap")
            plan = e2e_plan(length, beyond)
            if len(plan) > MAX_FRAMES:
                raise Refused(f"check {name!r}: skip_beyond_gap {beyond} makes more than {MAX_FRAMES} frames")
            params["expect"] = len(arrivals(plan))
            # Live frames cut into pieces: the receiving side joins them before it judges, which
            # wz does in the replay subscriber under the segmented reply shape, on a suffix no
            # cache serves.
            _segment(check, base, out, params)
            if params["segmented"]:
                params["suffix"] = check.get("suffix") or "/lane-no-cache"
                params["depth"] = 1
                variant = "segmented"
                held = lane.get("wz", {}).get("build_env", {}).get("WZ_POLICY_REPLAY_LIVE_BEFORE_ANSWER")
                if held == "hold-back":
                    raise Refused(f"check {name!r}: live pieces are joined by a subscriber that no "
                                  "round ever releases, so WZ_POLICY_REPLAY_LIVE_BEFORE_ANSWER "
                                  "hold-back would keep every frame")
        else:
            frames = _positive(check, "frames")
            if frames > MAX_FRAMES:
                raise Refused(f"check {name!r}: more than {MAX_FRAMES} frames")
            plan = [("record", payload(i, length)) for i in range(frames)]
            params["expect"] = frames
            if not isinstance(check.get("suffix"), str) or not check["suffix"]:
                raise Refused(f"check {name!r}: a replay check states its suffix")
            params["suffix"] = check["suffix"]
            params["depth"] = _positive(check, "depth", frames)
            if params["depth"] < frames:
                raise Refused(f"check {name!r}: depth {params['depth']} keeps fewer than its {frames} frames")
            _segment(check, base, out, params)
            if params["segmented"]:
                variant = "segmented"
        (out / "params").write_text("".join(f"{k} {v}\n" for k, v in params.items()), encoding="utf-8")
        (out / "plan").write_text("".join(f"{a} {p.hex()}\n" for a, p in plan), encoding="utf-8")
        (out / "peer.json").write_text(json.dumps(check.get("peer", {})), encoding="utf-8")
        rows.append(f"{name}\t{check['kind']}\t{variant}")
    (scratch / "checks.tsv").write_text("".join(r + "\n" for r in rows), encoding="utf-8")
    wz = lane.get("wz", {})
    (scratch / "wz-features").write_text(wz.get("features", "") + "\n", encoding="utf-8")
    env = wz.get("build_env", {})
    (scratch / "wz-build-env").write_text("".join(f"{k}={v}\n" for k, v in sorted(env.items())),
                                          encoding="utf-8")
    mode = lane.get("session", {}).get("connect_mode", "client")
    (scratch / "connect-mode").write_text(mode + "\n", encoding="utf-8")
    return rows


# ── judge ───────────────────────────────────────────────────────────────────


def transcript(path: Path) -> dict:
    """A party's transcript: its frames, pieces and arrivals, the last word it said and its
    exit status (None when the lane recorded none)."""
    t: dict = {"frames": {}, "pieces": {}, "got": [], "words": set(), "round": None, "rc": None,
               "refused": []}
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(" ")
            if parts[0] == "frame" and len(parts) == 3:
                t["frames"][int(parts[1])] = parts[2].lower()
            elif parts[0] == "piece" and len(parts) == 4:
                t["pieces"][(int(parts[1]), int(parts[2]))] = parts[3].lower()
            elif parts[0] == "got" and len(parts) in (3, 4):
                t["got"].append((parts[2], parts[3].lower() if len(parts) == 4 else ""))
            elif parts[0] == "round" and len(parts) == 2:
                t["round"] = parts[1]
            elif parts[0] == "refused":
                t["refused"].append(line)
            elif parts[0]:
                t["words"].add(parts[0])
    rc_path = path.with_suffix(".rc")
    if rc_path.is_file():
        try:
            t["rc"] = int(rc_path.read_text(encoding="utf-8").strip())
        except ValueError:
            t["rc"] = None
    return t


def _plan(check_dir: Path) -> list[tuple[str, bytes]]:
    plan = []
    for line in (check_dir / "plan").read_text(encoding="utf-8").splitlines():
        action, hexed = line.split(" ")
        plan.append((action, bytes.fromhex(hexed)))
    return plan


def _params(check_dir: Path) -> dict[str, str]:
    return dict(line.split(" ", 1) for line in (check_dir / "params").read_text(encoding="utf-8").splitlines())


def _ran(t: dict, who: str) -> list[str]:
    bad = []
    if t["refused"]:
        bad.append(f"{who} refused: {t['refused'][0]}")
    if t["rc"] is None:
        bad.append(f"{who} left no exit status")
    elif t["rc"] != 0:
        bad.append(f"{who} exited {t['rc']}")
    if "done" not in t["words"]:
        bad.append(f"{who} never said done")
    return bad


def judge_check(name: str, scratch: Path) -> list[tuple[str, list[str]]]:
    """(aspect, findings) for one check; an aspect with no finding passed."""
    check_dir = scratch / "checks" / name
    params = _params(check_dir)
    plan = _plan(check_dir)
    runs = scratch / "runs" / name
    t = {d: {r: transcript(runs / d / f"{r}.out") for r in ("send", "receive")} for d in DIRECTIONS}
    out: list[tuple[str, list[str]]] = []

    ran: list[str] = []
    for d in DIRECTIONS:
        for r in ("send", "receive"):
            ran += _ran(t[d][r], f"{d} {r}")
    out.append(("ran", ran))

    frames: list[str] = []
    wz_frames = t["wz-sends"]["send"]["frames"]
    peer_frames = t["peer-sends"]["send"]["frames"]
    for who, got in (("wz", wz_frames), ("peer", peer_frames)):
        if sorted(got) != list(range(len(plan))):
            frames.append(f"{who} printed frames {sorted(got)}, the plan has {len(plan)}")
    for i in range(len(plan)):
        if i in wz_frames and i in peer_frames and wz_frames[i] != peer_frames[i]:
            frames.append(f"frame {i}: wz {wz_frames[i]} peer {peer_frames[i]}")
    out.append(("frames byte for byte", frames))

    if params["kind"] == "e2e":
        expect = arrivals(plan)
        anchors = e2e_anchors(plan)
        recv = {d: t[d]["receive"]["got"] for d in DIRECTIONS}
        count: list[str] = []
        for d in DIRECTIONS:
            if len(recv[d]) != len(expect):
                count.append(f"{d}: {len(recv[d])} arrivals, {len(expect)} published")
        out.append(("arrivals", count))
        anchor: list[str] = []
        for d in DIRECTIONS:
            for n, cls in sorted(anchors.items()):
                if n < len(recv[d]) and recv[d][n][0] != cls:
                    anchor.append(f"{d} arrival {n}: {recv[d][n][0]}, owed {cls}")
        out.append(("verdicts owed", anchor))
        cross: list[str] = []
        for n in range(min(len(recv["wz-sends"]), len(recv["peer-sends"]))):
            a, b = recv["wz-sends"][n][0], recv["peer-sends"][n][0]
            if a != b:
                cross.append(f"arrival {n}: the peer judged wz's frame {a}, wz judged the peer's {b}")
        out.append(("same verdicts both ways", cross))
        pay: list[str] = []
        for d in DIRECTIONS:
            for n, (cls, hexed) in enumerate(recv[d]):
                if n < len(expect) and expect[n][1] != "corrupt" and cls != "integrity":
                    want = plan[expect[n][0]][1].hex()
                    if hexed != want:
                        pay.append(f"{d} arrival {n}: payload {hexed}, sent {want}")
        out.append(("payloads", pay))
    else:
        answers: list[str] = []
        for d in DIRECTIONS:
            got = t[d]["receive"]["got"]
            want = [p.hex() for _, p in plan]
            if [h for _, h in got] != want:
                answers.append(f"{d}: answered {len(got)} payload(s) out of order or changed, "
                               f"{len(want)} recorded")
            for n, (cls, _) in enumerate(got):
                if cls != "intact":
                    answers.append(f"{d} answer {n}: {cls}")
            if t[d]["receive"]["round"] != "live":
                answers.append(f"{d}: the round ended {t[d]['receive']['round']}, not live")
        out.append(("answers in order", answers))
    if params.get("segmented") == "1":
        # A replay cache cuts every recorded frame (`piece <frame> <j>`); an e2e sender cuts
        # every frame it puts, in the order put (`piece <put> <j>`), a repeat or a corrupted
        # copy under a transfer number of its own.
        units = len(plan) if params["kind"] == "replay" else len(arrivals(plan))
        pieces: list[str] = []
        wz_p = t["wz-sends"]["send"]["pieces"]
        peer_p = t["peer-sends"]["send"]["pieces"]
        for who, got in (("wz", wz_p), ("peer", peer_p)):
            if {i for i, _ in got} != set(range(units)):
                pieces.append(f"{who} printed pieces of {sorted({i for i, _ in got})}, owed 0 to {units - 1}")
        for place in sorted(set(wz_p) | set(peer_p)):
            if wz_p.get(place) != peer_p.get(place):
                pieces.append(f"piece {place[0]}.{place[1]}: wz {wz_p.get(place)} peer {peer_p.get(place)}")
        out.append(("pieces byte for byte", pieces))
    return out


def judge(scratch: Path) -> int:
    rows = [r.split("\t") for r in (scratch / "checks.tsv").read_text(encoding="utf-8").splitlines() if r]
    if not rows:
        print("app-plane-oracle: no check was prepared, so nothing was judged: FAIL")
        return 1
    failed = 0
    aspects = 0
    for name, _kind, _variant in rows:
        for aspect, findings in judge_check(name, scratch):
            aspects += 1
            if findings:
                failed += 1
                print(f"check {name} {aspect}: FAIL")
                for f in findings[:12]:
                    print(f"    {f}")
                if len(findings) > 12:
                    print(f"    ... {len(findings) - 12} more")
            else:
                print(f"check {name} {aspect}: PASS")
    verdict = "PASS" if failed == 0 else "FAIL"
    print(f"app-plane-oracle: {len(rows)} check(s), {aspects} aspect(s), {failed} failed: {verdict}")
    return 0 if failed == 0 else 1


# ── selftest ────────────────────────────────────────────────────────────────

PROFILE = {"name": "selftest-frame", "fields": [{"name": "counter", "bytes": 1}]}


def _lane(**over) -> dict:
    lane = {
        "checks": [
            {"name": "small", "kind": "e2e", "key": "lane/small", "profile": PROFILE, "values": {},
             "payload_len": 3, "skip_beyond_gap": 2},
            {"name": "answers", "kind": "replay", "key": "lane/answers", "suffix": "/ask",
             "profile": PROFILE, "values": {}, "payload_len": 5, "frames": 3,
             "segment": {"profile": {"name": "selftest-pieces"}, "values": {}, "chunk_bytes": 2}},
            {"name": "pieced", "kind": "e2e", "key": "lane/pieced", "profile": PROFILE, "values": {},
             "payload_len": 9, "skip_beyond_gap": 1,
             "segment": {"profile": {"name": "selftest-pieces"}, "values": {}, "chunk_bytes": 4}},
        ]
    }
    lane.update(over)
    return lane


KEY_IDS = {"dictionary": [{"id": 7, "key": "lane/small"}, {"id": 9, "key": "lane/pieced"}],
           "forms": {"connect": "shared"}}


def _keyed(key_ids: object) -> dict:
    """The selftest lane with a dictionary, in a build that has one."""
    return _lane(wz={"features": "shared-key-ids"}, key_ids=key_ids)


def _fake_frame(i: int, p: bytes) -> str:
    return (bytes([i & 0xFF]) + p).hex()


def _perfect(scratch: Path) -> None:
    """The transcripts of a pair of implementations that agree in everything."""
    for name, kind, _ in (r.split("\t") for r in (scratch / "checks.tsv").read_text().splitlines()):
        plan = _plan(scratch / "checks" / name)
        segmented = _params(scratch / "checks" / name).get("segmented") == "1"
        for d in DIRECTIONS:
            run = scratch / "runs" / name / d
            run.mkdir(parents=True, exist_ok=True)
            send = [f"frame {i} {_fake_frame(i, p)}" for i, (_, p) in enumerate(plan)]
            if segmented and kind == "e2e":
                send += [f"piece {u} {j} {u:02x}{j:02x}" for u in range(len(arrivals(plan))) for j in range(2)]
            if kind == "replay":
                if segmented:
                    send += [f"piece {i} 0 {_fake_frame(i, p)[:4]}" for i, (_, p) in enumerate(plan)]
                recv = [f"got {n} intact {p.hex()}" for n, (_, p) in enumerate(plan)] + ["round live"]
            else:
                anchors = e2e_anchors(plan)
                recv = []
                for n, (i, what) in enumerate(arrivals(plan)):
                    cls = anchors.get(n, "intact")
                    shown = plan[i][1].hex() if what != "corrupt" else "00"
                    recv.append(f"got {n} {cls} {shown}")
            (run / "send.out").write_text("\n".join(send + ["ready", "done"]) + "\n")
            (run / "receive.out").write_text("\n".join(["ready"] + recv + ["done"]) + "\n")
            (run / "send.rc").write_text("0\n")
            (run / "receive.rc").write_text("0\n")


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text, (path, old)
    path.write_text(text.replace(old, new, 1))


def selftest() -> int:
    failures = []

    def expect(label: str, cond: bool) -> None:
        if not cond:
            failures.append(label)

    plan = e2e_plan(2, 3)
    expect("the plan holds the declared run", [a for a, _ in plan].count("hold") == 4)
    expect("eleven arrivals", len(arrivals(plan)) == 11)
    anchors = e2e_anchors(plan)
    expect("the repeat is owed counter", anchors.get(3) == "counter")
    expect("the frame after the run is owed counter", anchors.get(5) == "counter")
    expect("the corrupted copy is owed integrity", anchors.get(8) == "integrity")
    expect("the single gap is compared only", 4 not in anchors)
    expect("payloads differ frame to frame", payload(0, 4) != payload(1, 4))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        lane_file = root / "lane.json"

        def refused(lane: object, why: str) -> None:
            lane_file.write_text(json.dumps(lane))
            try:
                prepare(lane_file, root / "s")
            except Refused:
                return
            failures.append(f"not refused: {why}")

        refused({"checks": []}, "no check")
        refused({"checks": [{"name": "x", "kind": "pubsub", "key": "k"}]}, "an unknown kind")
        refused(_lane(checks=[_lane()["checks"][0], _lane()["checks"][0]]), "a name twice")
        refused(_lane(checks=[dict(_lane()["checks"][0], name="Bad Name")]), "a name not a word")
        refused(_lane(checks=[dict(_lane()["checks"][0], key="")]), "no key")
        refused(_lane(checks=[dict(_lane()["checks"][0], payload_len=0)]), "an empty payload")
        refused(_lane(checks=[dict(_lane()["checks"][0], skip_beyond_gap=0)]), "no run past the gap")
        refused(_lane(checks=[dict(_lane()["checks"][0], skip_beyond_gap=400)]), "too many frames")
        refused(_lane(checks=[dict(_lane()["checks"][0], profile="missing.json")]), "a profile path missing")
        refused(_lane(checks=[{k: v for k, v in _lane()["checks"][1].items() if k != "suffix"}]), "no suffix")
        refused(_lane(checks=[dict(_lane()["checks"][1], depth=2)]), "a depth below the frames")
        refused(_lane(checks=[dict(_lane()["checks"][1], segment={"profile": {}, "values": {}})]),
                "a segment without chunk_bytes")
        refused(_lane(wz={"build_env": {"PATH": "/x"}}), "a build_env outside the policies and limits")
        refused(_lane(wz={"build_env": {SHAPE_POLICY: "segmented"}}), "the reply shape in build_env")
        refused(_lane(session="peer"), "a session that is not an object")
        refused(_lane(checks=[dict(_lane()["checks"][2], segment={"profile": {}, "values": {}})]),
                "an e2e segment without chunk_bytes")
        refused(_lane(wz={"build_env": {"WZ_POLICY_REPLAY_LIVE_BEFORE_ANSWER": "hold-back"}}),
                "an e2e segment under hold-back")
        refused(_lane(key_ids=KEY_IDS), "a dictionary for a build without shared-key-ids")
        refused(_keyed([]), "key_ids that is not an object")
        refused(_keyed({"dictionary": []}), "an empty dictionary")
        refused(_keyed({"dictionary": [{"id": 0, "key": "a/b"}]}), "id 0")
        refused(_keyed({"dictionary": [{"id": 65536, "key": "a/b"}]}), "an id past 16 bits")
        refused(_keyed({"dictionary": [{"id": True, "key": "a/b"}]}), "an id that is a boolean")
        refused(_keyed({"dictionary": [{"id": 3}]}), "an entry with no key")
        refused(_keyed({"dictionary": [{"id": 3, "key": "a/b"}, {"id": 3, "key": "a/c"}]}), "an id twice")
        refused(_keyed({"dictionary": [{"id": 3, "key": "a/b"}, {"id": 4, "key": "a/b"}]}), "a key twice")
        for bad in ("", "/a", "a/", "a//b", "a/**/**", "a/**/*", "$*", "a/b*", "a/$b", "a#b", "a?b",
                    "a b", "a/$*$*"):
            refused(_keyed({"dictionary": [{"id": 3, "key": bad}]}), f"the key {bad!r}")
        refused(_keyed(dict(KEY_IDS, forms={"router": "shared"})), "a form for no side")
        refused(_keyed(dict(KEY_IDS, forms={"listen": "compact"})), "a form the policy has no value of")
        refused(_keyed(dict(KEY_IDS, forms="shared")), "forms that is not an object")
        for good in ("a/b", "a/*/c", "a/**", "*/**", "a$*b/c", "**"):
            expect(f"the canonical key {good!r} is read", key_problem(good) is None)
        refused(_lane(wz={"features": "a b"}), "features not a comma list")
        refused(_lane(session={"connect_mode": "router"}), "an unknown connect mode")

        lane_file.write_text(json.dumps(_lane(wz={"features": "message-catalog,shared-key-ids",
                                                    "build_env": {"WZ_POLICY_X": "on"}},
                                              key_ids=KEY_IDS)))
        scratch = root / "s"
        rows = prepare(lane_file, scratch)
        expect("three checks prepared", rows == ["small\te2e\tframe", "answers\treplay\tsegmented",
                                                 "pieced\te2e\tsegmented"])
        expect("the build env is written", (scratch / "wz-build-env").read_text() == "WZ_POLICY_X=on\n")
        params = _params(scratch / "checks" / "answers")
        expect("the replay params", params.get("segmented") == "1" and params.get("chunk_bytes") == "2"
               and params.get("suffix") == "/ask" and params.get("expect") == "3")
        small_params = _params(scratch / "checks" / "small")
        expect("the e2e expect", small_params.get("expect") == "11")
        expect("an e2e check without a segment is not segmented", small_params.get("segmented") == "0")
        pieced = _params(scratch / "checks" / "pieced")
        expect("an e2e segment's params", pieced.get("segmented") == "1" and pieced.get("chunk_bytes") == "4"
               and pieced.get("suffix") == "/lane-no-cache" and pieced.get("depth") == "1"
               and (scratch / "checks" / "pieced" / "segment-profile.json").is_file())
        expect("the dictionary is in every check", all(
            (scratch / "checks" / n / "key-ids").read_text() == "7 lane/small\n9 lane/pieced\n"
            for n in ("small", "answers", "pieced")))
        expect("the stated form reaches the params", small_params.get("key_form_connect") == "shared"
               and "key_form_listen" not in small_params)
        lane_file.write_text(json.dumps(_lane()))
        prepare(lane_file, root / "plain")
        expect("no dictionary, no key-ids file", not (root / "plain" / "checks" / "small" / "key-ids").exists())

        _perfect(scratch)
        expect("a pair that agrees passes", judge(scratch) == 0)

        def red(label: str, path: Path, old: str, new: str) -> None:
            _edit(path, old, new)
            if judge(scratch) == 0:
                failures.append(f"not red: {label}")
            _edit(path, new, old)

        small = scratch / "runs" / "small"
        answers = scratch / "runs" / "answers"
        first = _fake_frame(0, _plan(scratch / "checks" / "small")[0][1])
        red("one frame byte differs", small / "peer-sends" / "send.out", f"frame 0 {first}",
            f"frame 0 ff{first[2:]}")
        red("a party exits non-zero", small / "wz-sends" / "send.rc", "0", "1")
        red("a party never says done", small / "peer-sends" / "receive.out", "done", "sent")
        red("one side judges differently", small / "peer-sends" / "receive.out", "got 4 intact",
            "got 4 counter")
        red("both sides miss the repeat", small / "wz-sends" / "receive.out", "got 3 counter", "got 3 intact")
        red("an arrival is missing", small / "wz-sends" / "receive.out", "got 10 intact", "late 10 intact")
        red("a payload is changed", small / "wz-sends" / "receive.out",
            f"got 0 intact {_plan(scratch / 'checks' / 'small')[0][1].hex()}", "got 0 intact 0000")
        red("an answer is not intact", answers / "wz-sends" / "receive.out", "got 1 intact", "got 1 counter")
        red("the round was abandoned", answers / "peer-sends" / "receive.out", "round live", "round abandoned")
        a0 = _plan(scratch / "checks" / "answers")[0][1].hex()
        a1 = _plan(scratch / "checks" / "answers")[1][1].hex()
        path = answers / "peer-sends" / "receive.out"
        text = path.read_text()
        path.write_text(text.replace(f"got 0 intact {a0}", "SWAP").replace(f"got 1 intact {a1}", f"got 0 intact {a0}")
                        .replace("SWAP", f"got 1 intact {a1}"))
        if judge(scratch) == 0:
            failures.append("not red: answers out of order")
        path.write_text(text)
        piece = _fake_frame(1, _plan(scratch / "checks" / "answers")[1][1])[:4]
        red("a piece differs", answers / "peer-sends" / "send.out", f"piece 1 0 {piece}", "piece 1 0 ffff")
        pieced_run = scratch / "runs" / "pieced"
        red("a live piece differs", pieced_run / "wz-sends" / "send.out", "piece 3 1 0301", "piece 3 1 ffff")
        red("a piece one side never cut", pieced_run / "peer-sends" / "send.out", "piece 10 0 0a00",
            "spare 10 0 0a00")
        expect("restored pair passes again", judge(scratch) == 0)

    for f in failures:
        print(f"oracle selftest FAIL: {f}")
    print(f"oracle selftest: {'PASS' if not failures else 'FAIL'} ({len(failures)} failure(s))")
    return 0 if not failures else 1


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) == 4 and argv[1] == "prepare":
        try:
            for row in prepare(Path(argv[2]), Path(argv[3])):
                print(f"prepared {row}")
        except Refused as err:
            print(f"app-plane-oracle: the lane file is refused: {err}")
            return 2
        return 0
    if len(argv) == 3 and argv[1] == "judge":
        return judge(Path(argv[2]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
