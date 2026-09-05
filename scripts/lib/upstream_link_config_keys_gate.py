#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2363 (no register item) — EVERY LOCATOR CONFIG KEY AN UPSTREAM LINK CRATE
DECLARES IS EITHER READ BY WZ OR NAMED AS THAT ATOM'S RESIDUAL.

## Why the citation says no item while the file answers for one

The debt this answers is open-debt item 15, the PARTIAL-atom track, and item 15
lives in the half of the register that is not the store, so there is no `debt-`
id to cite — the same standing `upstream_link_axis_gate.py` is in for item 593's
residue. The item is named in full here, which is what a reader grepping for it
will find.

## The class this exists for

`transport-link-unixpipe` carried the residual "does not model zenoh's
configurable `file_mask` locator parameter" for as long as it did because
NOTHING derived the population it belongs to. The key is one `pub const` in one
upstream link crate; whether wz reads it is one grep; and neither was ever run
together with the other. R2363 closed that key, and this is what stops the class
from coming back on the next link.

The population is upstream's, and it is small and exact: a zenoh link crate
declares its locator config vocabulary in a `pub mod config` block, and there
are exactly three such blocks at the pin — udp (`iface`, `join`, `ttl`), serial
(`baudrate`, `exclusive`, `tout`, `release_on_close`) and unixpipe
(`file_mask`). Nothing else in this tree derives that set.

## Two arms, one of which needs a checkout

  * The ORACLE arm reads the pinned upstream's `io/zenoh-links/**` and derives
    the (scheme, key) population. It needs a checkout, which is machine-local,
    so it SKIPS without one — and because a skip must not report green,
    `--require` turns that skip into a FAIL and the lane that HAS a checkout
    passes it. An empty population is a FAIL in both modes: a check whose
    subject vanished must not read as agreement.
  * For each key, the verdict is one of two, and the second is judged by a
    DIFFERENT artifact than the first:
      READ    — wz declares it as a locator config key, i.e. some
                `crates/**/src/**.rs` carries `const <NAME>: &str = "<key>";`.
                That is wz's own spelling for "this key has a reader"
                (`LOCATOR_MCAST_TTL_KEY`, `SERIAL_BAUDRATE_KEY`,
                `LOCATOR_FILE_MASK_KEY`), and it is a declaration rather than a
                mention, so a key named only in a doc comment does not count.
      NAMED   — the atom `transport-link-<scheme>` NAMES the key in its live
                reason in the atomic store. That is the register admitting the
                gap, which is the honest state for a key wz has not built.
    A key that is neither is the finding: an ungraded gap, the debt-47 shape.

## Why the exemption cannot be an escape hatch

There is no table in this file to add a row to. "Not read" is paid for in the
STORE — a different artifact, mutated through a different primitive, and already
graded by `store_reason_citation_gate.py` and the depth-axis census. And the
second rule closes the loop the other way: an atom whose impl axis is COMPLETE
may have NO unread key, so a scheme cannot be declared finished while its own
vocabulary is unbuilt. Naming a key as a residual therefore costs the atom its
COMPLETE tag, which is exactly the price that makes the admission honest.

MEASURED at R2363, against the 1.10.0 pin: population 8. READ 5 (`iface`,
`join`, `ttl`, `baudrate`, and `file_mask` as of this round); NAMED 3 (serial's
`exclusive`, `tout`, `release_on_close`, which this round had to ADD to that
atom's reason — they were unread AND unnamed, and no instrument had ever looked).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The atomic store, read (never written) for the inventory reasons.
STORE = "docs/.atomic/workspace.atomic.json"

#: An upstream link-crate directory suffix -> the wz atom that owns the scheme.
#: Upstream spells two of them with `_`; wz's atom ids use `-`, and unixsock's
#: atom drops upstream's `-stream`. Anything not listed is a FINDING rather than
#: a silent skip -- a link crate that grows a `pub mod config` and has no wz
#: owner is precisely the thing this gate is for.
ATOM_FOR_SCHEME: dict[str, str] = {
    "quic": "transport-link-quic",
    "quic-datagram": "transport-link-quic-datagram",
    "serial": "transport-link-serial",
    "tcp": "transport-link-tcp",
    "tls": "transport-link-tls",
    "udp": "transport-link-udp",
    "unixpipe": "transport-link-unixpipe",
    "unixsock-stream": "transport-link-unixsock",
    "vsock": "transport-link-vsock",
    "ws": "transport-link-ws",
}

#: `pub mod config { ... }` -- the block a zenoh link crate declares its locator
#: config vocabulary in. Non-greedy to the first line that closes at column 0,
#: which is how rustfmt lays these out.
CONFIG_MOD = re.compile(r"^pub mod config \{\n(.*?)^\}", re.M | re.S)

#: `pub const <IDENT>: &str = "<value>";` inside such a block.
CONFIG_KEY = re.compile(r'pub const [A-Z0-9_]+: &str = "([^"]+)"\s*;')

#: wz's own spelling for "this locator config key has a reader": a `const`
#: declaration binding it to a name. A doc comment mentioning the key does NOT
#: match, deliberately -- the unixpipe residual this gate was born from was a
#: doc comment naming `file_mask` and no reader at all.
WZ_KEY_DECL = re.compile(r'const [A-Z0-9_]+: &str = "([^"]+)"\s*;')

#: The impl-axis tag lives at the HEAD of an inventory reason.
IMPL_TAG = re.compile(r"^\s*([A-Z-]+)")


def upstream_root() -> pathlib.Path | None:
    """A checkout of the PINNED zenoh, or `None`.

    DELEGATED, exactly as `upstream_link_axis_gate.upstream_root` delegates, so
    this gate cannot disagree with its siblings about which upstream the tree
    means (open debt 578). One derivation, now four consumers.
    """
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        import upstream_citation_anchor_gate as cite
    except ImportError:  # pragma: no cover - the sibling is tracked beside this
        return None
    root = cite.upstream_root()
    if root is not None and (root / "io" / "zenoh-links").is_dir():
        return root
    return None


def upstream_keys(root: pathlib.Path) -> tuple[dict[str, list[str]], list[str]]:
    """`{scheme: [key, ...]}` from upstream's own `pub mod config` blocks."""
    findings: list[str] = []
    out: dict[str, list[str]] = {}
    links = root / "io" / "zenoh-links"
    for d in sorted(links.iterdir()):
        if not d.is_dir() or not d.name.startswith("zenoh-link-"):
            continue
        scheme = d.name[len("zenoh-link-") :].replace("_", "-")
        keys: list[str] = []
        for path in sorted(d.rglob("*.rs")):
            body = path.read_text(encoding="utf-8", errors="replace")
            for block in CONFIG_MOD.findall(body):
                keys.extend(CONFIG_KEY.findall(block))
        if not keys:
            continue
        if scheme not in ATOM_FOR_SCHEME:
            findings.append(
                f"upstream link crate `{d.name}` declares config key(s) "
                f"{sorted(set(keys))} and this gate knows no wz atom for the "
                f"`{scheme}` scheme -- add it to `ATOM_FOR_SCHEME` or the key "
                f"is graded by nobody"
            )
            continue
        out[scheme] = sorted(set(keys))
    return out, findings


def wz_declared_keys(root: pathlib.Path | None = None) -> set[str]:
    """Every locator config key wz BINDS TO A NAME, across `crates/**/src`."""
    base = (root or ROOT) / "crates"
    found: set[str] = set()
    for path in base.rglob("*.rs"):
        if "/target/" in str(path):
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        found.update(WZ_KEY_DECL.findall(body))
    return found


def store_reasons(root: pathlib.Path | None = None) -> dict[str, str]:
    """`{atom id: live reason}` straight from the atomic store."""
    data = json.loads(((root or ROOT) / STORE).read_text(encoding="utf-8"))
    entries = data.get("inventory_entries")
    if not isinstance(entries, dict):
        raise SystemExit(f"{STORE} holds no `inventory_entries` mapping.")
    return {eid: (e or {}).get("reason") or "" for eid, e in entries.items()}


def findings_for(
    keys: dict[str, list[str]], declared: set[str], reasons: dict[str, str]
) -> tuple[list[str], int, int]:
    """(findings, read, named) over the derived population."""
    findings: list[str] = []
    read = named = 0
    for scheme, scheme_keys in sorted(keys.items()):
        atom = ATOM_FOR_SCHEME[scheme]
        reason = reasons.get(atom)
        if reason is None:
            findings.append(
                f"`{scheme}`: the store carries no atom `{atom}`, so this "
                f"scheme's keys can be named by nobody"
            )
            continue
        tag = IMPL_TAG.match(reason)
        complete = bool(tag) and tag.group(1) == "COMPLETE"
        unread: list[str] = []
        for key in scheme_keys:
            if key in declared:
                read += 1
                continue
            unread.append(key)
            if key in reason:
                named += 1
                continue
            findings.append(
                f"`{scheme}`: upstream declares the locator config key "
                f"`{key}` (`pub mod config`), wz binds it to no `const`, and "
                f"`{atom}`'s reason never names it -- an ungraded gap"
            )
        if complete and unread:
            findings.append(
                f"`{atom}` is tagged COMPLETE while {unread} of its own "
                f"upstream config vocabulary is unread. A scheme is not "
                f"finished while its keys are not built"
            )
    return findings, read, named


def check(require: bool) -> int:
    root = upstream_root()
    if root is None:
        if require:
            print(
                "upstream-link-config-keys: FAIL -- the population is "
                "upstream's and there is no checkout of the pinned zenoh on "
                "this machine, and `--require` was given. A skip must not "
                "report green. Point ZENOHD_SRC at one."
            )
            return 1
        print(
            "  upstream-link-config-keys: SKIPPED -- the population is derived "
            "from a checkout of the pinned zenoh and there is none on this "
            "machine. Nothing was graded; do not read this as agreement."
        )
        return 0

    keys, findings = upstream_keys(root)
    total = sum(len(v) for v in keys.values())
    if total == 0:
        print(
            "upstream-link-config-keys: FAIL -- the derived population is "
            f"EMPTY at {root}. Upstream declares its locator config vocabulary "
            "in `pub mod config` blocks; finding none means this reader stopped "
            "matching upstream, not that upstream stopped having keys."
        )
        return 1

    more, read, named = findings_for(keys, wz_declared_keys(), store_reasons())
    findings.extend(more)
    if findings:
        print(f"upstream-link-config-keys: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return 1
    print(
        f"  upstream-link-config-keys: {total} locator config key(s) across "
        f"{len(keys)} upstream link crate(s) at {root} -- {read} read by wz, "
        f"{named} named as their atom's residual"
    )
    return 0


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------


def _upstream_tree(base: pathlib.Path) -> pathlib.Path:
    """A minimal upstream fixture: two link crates, three keys."""
    links = base / "io" / "zenoh-links"
    udp = links / "zenoh-link-udp" / "src"
    udp.mkdir(parents=True)
    udp.joinpath("lib.rs").write_text(
        'pub const UDP_LOCATOR_PREFIX: &str = "udp";\n'
        "pub mod config {\n"
        '    pub const UDP_MULTICAST_IFACE: &str = "iface";\n'
        '    pub const UDP_MULTICAST_TTL: &str = "ttl";\n'
        "}\n",
        encoding="utf-8",
    )
    pipe = links / "zenoh-link-unixpipe" / "src" / "unix"
    pipe.mkdir(parents=True)
    pipe.joinpath("mod.rs").write_text(
        "pub mod config {\n"
        '    pub const FILE_ACCESS_MASK: &str = "file_mask";\n'
        "}\n",
        encoding="utf-8",
    )
    return base


def _store(base: pathlib.Path, reasons: dict[str, str]) -> pathlib.Path:
    (base / "docs" / ".atomic").mkdir(parents=True, exist_ok=True)
    (base / STORE).write_text(
        json.dumps({"inventory_entries": {k: {"reason": v} for k, v in reasons.items()}}),
        encoding="utf-8",
    )
    return base


CLEAN_REASONS = {
    "transport-link-udp": "PARTIAL: ...",
    "transport-link-unixpipe": "COMPLETE: ...",
}


def selftest() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = _upstream_tree(pathlib.Path(tmp))
        keys, findings = upstream_keys(root)
        if findings:
            print(f"upstream-link-config-keys: SELFTEST FAIL -- {findings}")
            return 1
        if keys != {"udp": ["iface", "ttl"], "unixpipe": ["file_mask"]}:
            print(
                "upstream-link-config-keys: SELFTEST FAIL -- the derivation must "
                f"read upstream's own `pub mod config` blocks; got {keys}"
            )
            return 1

        # CONTROL: every key read.
        declared = {"iface", "ttl", "file_mask"}
        got, read, named = findings_for(keys, declared, CLEAN_REASONS)
        if got or (read, named) != (3, 0):
            print(
                "upstream-link-config-keys: SELFTEST FAIL -- the clean control "
                f"must pass with 3 read; got {got} / {read} / {named}"
            )
            return 1

        # The R2363 defect itself: `file_mask` unread and unnamed.
        got, _, _ = findings_for(keys, {"iface", "ttl"}, CLEAN_REASONS)
        if not any("`file_mask`" in f and "ungraded gap" in f for f in got):
            print(
                "upstream-link-config-keys: SELFTEST FAIL -- an unread, unnamed "
                f"key must be refused; got {got}"
            )
            return 1

        # NAMED pays for it -- but only while the atom is not COMPLETE.
        named_reasons = {
            **CLEAN_REASONS,
            "transport-link-unixpipe": "PARTIAL: ... file_mask is not modelled",
        }
        got, _, named = findings_for(keys, {"iface", "ttl"}, named_reasons)
        if got or named != 1:
            print(
                "upstream-link-config-keys: SELFTEST FAIL -- a key named in the "
                f"atom's reason must be accepted; got {got} / {named}"
            )
            return 1
        got, _, _ = findings_for(
            keys,
            {"iface", "ttl"},
            {**CLEAN_REASONS, "transport-link-unixpipe": "COMPLETE: ... file_mask is not modelled"},
        )
        if not any("tagged COMPLETE while" in f for f in got):
            print(
                "upstream-link-config-keys: SELFTEST FAIL -- an atom may not be "
                f"COMPLETE while one of its own keys is unread; got {got}"
            )
            return 1

        # A key NAMED only in a wz doc comment is not a reader.
        with tempfile.TemporaryDirectory() as wz:
            src = pathlib.Path(wz) / "crates" / "c" / "src"
            src.mkdir(parents=True)
            src.joinpath("l.rs").write_text(
                '/// wz does NOT model zenoh\'s `file_mask` locator parameter.\n'
                'const LOCATOR_IFACE_KEY: &str = "iface";\n',
                encoding="utf-8",
            )
            if wz_declared_keys(pathlib.Path(wz)) != {"iface"}:
                print(
                    "upstream-link-config-keys: SELFTEST FAIL -- a key mentioned "
                    "only in a doc comment must NOT count as read"
                )
                return 1

        # A link crate with a config block and no wz atom is a finding.
        rogue = root / "io" / "zenoh-links" / "zenoh-link-carrier" / "src"
        rogue.mkdir(parents=True)
        rogue.joinpath("lib.rs").write_text(
            'pub mod config {\n    pub const K: &str = "k";\n}\n', encoding="utf-8"
        )
        _, got = upstream_keys(root)
        if not any("knows no wz atom" in f for f in got):
            print(
                "upstream-link-config-keys: SELFTEST FAIL -- an upstream link "
                f"crate with no wz owner must be refused; got {got}"
            )
            return 1

    # An upstream tree with no config block at all grades nothing, and the
    # verdict layer must say so rather than print a clean line over 0 keys.
    with tempfile.TemporaryDirectory() as tmp:
        empty = pathlib.Path(tmp)
        (empty / "io" / "zenoh-links").mkdir(parents=True)
        keys, _ = upstream_keys(empty)
        if sum(len(v) for v in keys.values()) != 0:
            print("upstream-link-config-keys: SELFTEST FAIL -- an empty tree is not empty")
            return 1

    print(
        "upstream-link-config-keys: selftest OK -- the derivation reads "
        "upstream's own `pub mod config` blocks; an unread AND unnamed key is "
        "refused (R2363's own defect); a named one is accepted; a COMPLETE atom "
        "with an unread key is refused; a doc-comment mention is not a reader; "
        "an upstream link crate with no wz owner is refused; an empty "
        "population is empty -- past one clean control"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="read the real tree")
    ap.add_argument(
        "--require",
        action="store_true",
        help="the oracle arm must run; a missing checkout FAILs instead of skipping",
    )
    ap.add_argument("--selftest", action="store_true", help="drive the verdicts")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.check:
        return check(args.require)
    ap.print_usage()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
