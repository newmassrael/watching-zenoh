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

## R2589 — the population was the wrong CLASS

"The keys a link DECLARES" is not "the keys a link READS". Every link crate also
reads keys declared in `zenoh-link-commons` (`bind`, `iface`, `dscp`, the TCP
buffers, the TLS and QUIC material), and `transport-link-udp` was reported clean
while wz read neither `bind` nor `dscp`. The population now follows each crate's
`use zenoh_link_commons::...` imports to the commons files that define what it
imports, and each commons file's own imports in turn. It does not match names: a
first attempt did, and generic method names connected every crate to every key.

READ gained two spellings, because wz reads some of this vocabulary under
other names. One is a zenoh-config path that upstream's `inspect_config` copies
into the key, which wz's `HONOURED_CONFIG_KEYS` carries. The other is a zenoh-pico
config macro a wz crate reads; that is how the C APIs' mTLS options arrive, and
without it the gate called mTLS unread in a tree that builds it. NAMED became the key in
backticks, because a consumed key like `bind` is a substring of prose that never
admits the gap.

MEASURED at R2589, identically under three hash seeds: population 87 (8 declared, 79
consumed), 45 read, 42 named. Four atoms tagged COMPLETE read keys wz reads under
no spelling, and were re-graded PARTIAL in the same push: `transport-link-tcp`
(4), `-tls` (11), `-quic` (10) and `-quic-datagram` (10). REMAINING WORK went from
46 to 50. `transport-link-udp` was found reaching commons QUIC for its RELIABLE
variant (`rel=1`, plaintext QUIC), which wz does not implement. Its reason names
the variant and that path's two MTU keys; the TLS keys are excluded by
`unsecure_quic_only`.

A first cut of this arm memoised a partial key set when it cut an import
cycle, and the same tree graded rc=1, 0, 1 on consecutive runs because set order
is randomised per process. `Commons.file_keys` is now a fixpoint over the whole
graph, and every measurement above was taken under explicit
`PYTHONHASHSEED` values.
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


# ---------------------------------------------------------------------------
# R2588/R2589 -- the CONSUMED half of a link's vocabulary
# ---------------------------------------------------------------------------
#
# A link crate's `pub mod config` is only the keys it DECLARES. It also reads
# keys declared in `zenoh-link-commons` (`bind`, `iface`, `dscp`, the TCP buffer
# and TLS/QUIC keys), and before R2589 nothing counted those. MEASURED at the
# pin: `zenoh-link-udp` consumes `bind` and `dscp`, wz read neither, and no
# atom named either. A population derived only from declarations reported
# `transport-link-udp` clean over two unbuilt keys.
#
# The derivation follows IMPORTS, not names. A first attempt matched item names
# transitively and connected every commons item to every crate through `new`,
# `fmt` and `from`. `use` paths are explicit and protocol-shaped, so they are
# the handle:
#   * a commons FILE reads the key constants its code references (definitions
#     removed), plus every key of each commons file it imports from with
#     `use crate::...` / `use super::...`;
#   * a link CRATE consumes the constants its own code references, plus every
#     key of each commons file that DEFINES an item it imports from
#     `zenoh_link_commons::...` (a glob import takes the module file).

COMMONS_CONST = re.compile(r'pub const ([A-Z0-9_]+): &str = "([^"]+)"\s*;')
USE_STMT = re.compile(r"\buse\s+(zenoh_link_commons|crate|super)::(.*?);", re.S)
#: `let c = config.transport().link().<section>();` opens an `inspect_config`.
INSPECT_SECTION = re.compile(r"config\s*\.\s*transport\(\)\s*\.\s*link\(\)\s*\.\s*([a-z_]+)\(\)")
GETTER = re.compile(r"\bc\s*\.\s*([a-z0-9_]+)\(\)")


def _code(path: pathlib.Path) -> str:
    """Source with line comments removed, so a key named in prose is not a read."""
    return re.sub(r"//[^\n]*", "", path.read_text(encoding="utf-8", errors="replace"))


def _use_leaves(tree: str) -> list[list[str]]:
    """`a::{b, c::{d as e}}` -> [["a","b"], ["a","c","d"]]."""
    tree = tree.strip()
    if "{" not in tree:
        return [[seg.split(" as ")[0].strip() for seg in tree.split("::") if seg.strip()]]
    head, _, rest = tree.partition("{")
    prefix = [seg for seg in head.strip().rstrip(":").split("::") if seg]
    inner = rest[: rest.rfind("}")]
    parts, depth, cur = [], 0, ""
    for ch in inner:
        depth += ch == "{"
        depth -= ch == "}"
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return [prefix + leaf for part in parts if part.strip() for leaf in _use_leaves(part)]


def _block(src: str, open_at: int) -> str:
    depth = 0
    for i in range(open_at, len(src)):
        depth += src[i] == "{"
        depth -= src[i] == "}"
        if depth == 0:
            return src[open_at : i + 1]
    return src[open_at:]


class Commons:
    """`zenoh-link-commons`, read as a graph of files."""

    def __init__(self, root: pathlib.Path):
        self.src = root / "io" / "zenoh-link-commons" / "src"
        self.consts: dict[str, str] = {}
        if self.src.is_dir():
            for path in self.src.rglob("*.rs"):
                self.consts.update(COMMONS_CONST.findall(_code(path)))
        self._keys: dict[pathlib.Path, set[str]] = {}

    def module_file(self, segments: list[str], start: pathlib.Path | None = None) -> pathlib.Path:
        """The file a module path resolves to; an inline module stays in its parent."""
        path = start or self.src / "lib.rs"
        for seg in segments:
            if seg in ("crate", "self"):
                path = self.src / "lib.rs" if seg == "crate" else path
                continue
            if seg == "super":
                path = path.parent / "mod.rs" if path.name != "mod.rs" else path.parent.parent / "mod.rs"
                if not path.exists():
                    path = self.src / "lib.rs"
                continue
            base = path.parent
            for cand in (base / f"{seg}.rs", base / seg / "mod.rs"):
                if path.name in ("lib.rs", "mod.rs") and cand.exists():
                    path = cand
                    break
        return path

    def defining_files(self, module: pathlib.Path, name: str) -> list[pathlib.Path]:
        """Where `name`, imported from `module`, is defined: the module or a glob re-export."""
        if name in ("*", "self"):
            return [module]
        cands = [module]
        for sub in re.findall(r"pub use\s+([a-z_]+)::\*", _code(module)):
            for cand in (module.parent / f"{sub}.rs", module.parent / sub / "mod.rs"):
                if cand.exists():
                    cands.append(cand)
        defn = re.compile(
            r"pub\s+(?:async\s+)?(?:fn|struct|enum|trait|const|type|mod)\s+%s\b" % re.escape(name)
        )
        return [f for f in cands if defn.search(_code(f))] or [module]

    def consts_in(self, code: str) -> set[str]:
        body = COMMONS_CONST.sub("", code)
        return {c for c in self.consts if re.search(r"\b%s\b" % c, body)}

    def imported_files(self, code: str, roots: tuple[str, ...], here: pathlib.Path | None) -> set[pathlib.Path]:
        out: set[pathlib.Path] = set()
        for root_name, tree in USE_STMT.findall(code):
            if root_name not in roots:
                continue
            for leaf in _use_leaves(tree):
                if not leaf:
                    continue
                module_path = ([root_name] if root_name != "zenoh_link_commons" else []) + leaf[:-1]
                start = here if root_name == "super" else None
                module = self.module_file(module_path, start)
                out.update(self.defining_files(module, leaf[-1]))
        return out

    def file_keys(self, path: pathlib.Path) -> set[str]:
        """Keys `path` reads, directly or through the commons files it imports.

        A FIXPOINT over the whole commons import graph, computed once. R2589's
        first cut recursed with a cycle cut and memoised what it had when it cut,
        so a file inside an import cycle kept whatever partial set the traversal
        order happened to give it. The order came from set iteration, which
        Python randomises per process. The same tree then graded rc=1, 0, 1 on
        three consecutive runs, and an unstable gate cannot grade anything.
        """
        if not self._keys and self.src.is_dir():
            files = sorted(self.src.rglob("*.rs"))
            direct = {f: self.consts_in(_code(f)) for f in files}
            edges = {
                f: {d for d in self.imported_files(_code(f), ("crate", "super"), f) if d != f}
                for f in files
            }
            keys = {f: set(v) for f, v in direct.items()}
            changed = True
            while changed:
                changed = False
                for f in files:
                    before = len(keys[f])
                    for dep in edges[f]:
                        keys[f] |= keys.get(dep, set())
                    changed |= len(keys[f]) != before
            self._keys = keys
        return self._keys.get(path, set())


def consumed_keys(root: pathlib.Path) -> dict[str, tuple[set[str], set[pathlib.Path]]]:
    """`{scheme: ({commons key}, {commons files the crate reaches})}`."""
    commons = Commons(root)
    out: dict[str, tuple[set[str], set[pathlib.Path]]] = {}
    links = root / "io" / "zenoh-links"
    if not links.is_dir():
        return out
    for d in sorted(links.iterdir()):
        if not d.is_dir() or not d.name.startswith("zenoh-link-"):
            continue
        scheme = d.name[len("zenoh-link-") :].replace("_", "-")
        code = "\n".join(_code(p) for p in sorted(d.rglob("*.rs")))
        direct = commons.consts_in(code)
        consts = set(direct)
        files = commons.imported_files(code, ("zenoh_link_commons",), None)
        reached = set(files)
        for f in files:
            consts |= commons.file_keys(f)
        if unsecure_quic_only(code):
            consts = {c for c in consts if not c.startswith("TLS_") or c in direct}
        out[scheme] = ({commons.consts[c] for c in consts}, reached)
    return out


#: A commons QUIC builder, from its constructor to the `.await` that runs it.
QUIC_BUILDER_CHAIN = re.compile(r"Quic(?:Client|Server)Builder::new\((.*?)\.await", re.S)


def unsecure_quic_only(code: str) -> bool:
    """True when every commons QUIC builder this crate runs is `.security(false)`.

    R2589 — `zenoh-link-udp` reaches the commons QUIC code for its RELIABLE variant
    (`rel=1`), but builds plaintext QUIC: both of its builders chain
    `.security(false)`, and on that path `TlsServerConfig::new` /
    `TlsClientConfig::new` never read the certificate keys. The file-level import
    graph cannot see a boolean, so without this the UDP link was charged eight TLS
    keys it cannot read. The rule is narrow and read off the call sites. Only
    `TLS_*` constants are dropped (the QUIC MTU keys still apply to plaintext
    QUIC), and only when there is at least one builder and every one of them
    says `false`.
    """
    chains = QUIC_BUILDER_CHAIN.findall(code)
    return bool(chains) and all(".security(false)" in c.replace(" ", "").replace("\n", "") for c in chains)


def config_spellings(sources: list[pathlib.Path]) -> dict[str, set[str]]:
    """`{locator key: {zenoh-config path}}` from upstream's `inspect_config`.

    Upstream copies `transport/link/<section>/<field>` into the endpoint config
    under a locator key, so a wz that honours the config path reads the key too.
    Pairing is by the naming convention those functions follow (`field` ->
    `field` or `field_file`), and a pair counts only if `c.<field>()` really occurs
    in that `inspect_config`, so the convention cannot invent a spelling upstream
    does not have.
    """
    out: dict[str, set[str]] = {}
    for path in sources:
        code = _code(path)
        for m in re.finditer(r"fn inspect_config\b", code):
            brace = code.find("{", m.end())
            if brace < 0:
                continue
            body = _block(code, brace)
            section = INSPECT_SECTION.search(body)
            if not section:
                continue
            getters = set(GETTER.findall(body))
            for field in getters:
                for key in (field, f"{field}_file"):
                    out.setdefault(key, set()).add(
                        f"transport/link/{section.group(1)}/{field}"
                    )
    return out


#: zenoh-pico's config option macros, in the vendored header this tree builds.
PICO_CONFIG_HEADER = "vendor/zenoh-pico/include/zenoh-pico/config.h.in"
PICO_MACRO = re.compile(r"#define\s+(Z_CONFIG_[A-Z0-9_]+_KEY)\b")


def pico_spellings(
    commons_consts: dict[str, str], root: pathlib.Path | None = None
) -> dict[str, set[str]]:
    """`{locator key: {zenoh-pico config macro}}`, verified against pico's header.

    R2589 — wz's C APIs read TLS options under pico's names (`wz-capi-pico` reads
    `Z_CONFIG_TLS_ENABLE_MTLS_KEY` into the same runtime TLS config the Rust side
    uses), and a gate blind to that reported mTLS unread in a tree that builds it.
    pico's macros are upstream's constant names with `Z_CONFIG_` in front and
    `_KEY` behind, except that pico spells the FILE form without its suffix
    (`TLS_ROOT_CA_CERTIFICATE_FILE` is `Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY`). A
    pairing counts only if the macro really exists in the vendored header.
    """
    header = (root or ROOT) / PICO_CONFIG_HEADER
    if not header.is_file():
        return {}
    macros = set(PICO_MACRO.findall(header.read_text(encoding="utf-8", errors="replace")))
    out: dict[str, set[str]] = {}
    for name, key in commons_consts.items():
        stem = name[: -len("_FILE")] if name.endswith("_FILE") else name
        macro = f"Z_CONFIG_{stem}_KEY"
        if macro in macros:
            out.setdefault(key, set()).add(macro)
    return out


def wz_pico_macro_reads(root: pathlib.Path | None = None) -> set[str]:
    """Every pico config macro some wz crate's CODE references (comments removed)."""
    base = (root or ROOT) / "crates"
    found: set[str] = set()
    for path in base.rglob("*.rs"):
        if "/target/" in str(path):
            continue
        found.update(re.findall(r"\b(Z_CONFIG_[A-Z0-9_]+_KEY)\b", _code(path)))
    return found


def wz_honoured_config_keys(root: pathlib.Path | None = None) -> set[str]:
    """`HONOURED_CONFIG_KEYS` in wz's zenoh-config reader, the SSOT that reader tests."""
    path = (root or ROOT) / "crates" / "wz-runtime-tokio" / "src" / "zenoh_config.rs"
    if not path.is_file():
        return set()
    code = _code(path)
    m = re.search(r"pub const HONOURED_CONFIG_KEYS: &\[&str\] = &\[(.*?)\];", code, re.S)
    return set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()


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
    keys: dict[str, list[str]],
    declared: set[str],
    reasons: dict[str, str],
    spellings: dict[str, dict[str, set[str]]] | None = None,
    honoured: set[str] | None = None,
    pico: dict[str, set[str]] | None = None,
    pico_read: set[str] | None = None,
) -> tuple[list[str], int, int]:
    """(findings, read, named) over the derived population.

    READ has two spellings since R2589: a wz `const` binding the locator key,
    or a zenoh-config path that upstream copies into that key
    (`config_spellings`) and wz honours (`HONOURED_CONFIG_KEYS`).

    NAMED is the key in BACKTICKS in the atom's reason. It was a bare
    substring, which was harmless for `file_mask` and `baudrate` and is not for
    a consumed key like `bind`, which occurs inside `bind_multicast` in reasons
    that never admit the gap.
    """
    spellings = spellings or {}
    honoured = honoured or set()
    pico = pico or {}
    pico_read = pico_read or set()
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
            via_config = spellings.get(scheme, {}).get(key, set()) & honoured
            via_pico = pico.get(key, set()) & pico_read
            if key in declared or via_config or via_pico:
                read += 1
                continue
            unread.append(key)
            if f"`{key}`" in reason:
                named += 1
                continue
            findings.append(
                f"`{scheme}`: upstream's link reads the locator config key "
                f"`{key}`, wz binds it to no `const`, honours no zenoh-config path "
                f"upstream copies into it, reads no zenoh-pico macro for it, and "
                f"`{atom}`'s reason never names it in backticks -- an ungraded gap"
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

    declared_by_link, findings = upstream_keys(root)
    keys, spellings = merged_population(root, declared_by_link)
    consumed_total = sum(
        len(set(v) - set(declared_by_link.get(s, []))) for s, v in keys.items()
    )
    total = sum(len(v) for v in keys.values())
    if total == 0:
        print(
            "upstream-link-config-keys: FAIL -- the derived population is "
            f"EMPTY at {root}. Upstream declares its locator config vocabulary "
            "in `pub mod config` blocks; finding none means this reader stopped "
            "matching upstream, not that upstream stopped having keys."
        )
        return 1

    honoured = wz_honoured_config_keys()
    if not honoured:
        print(
            "upstream-link-config-keys: FAIL -- read no `HONOURED_CONFIG_KEYS` from "
            "wz's zenoh-config reader, so the config spelling of READ graded nothing"
        )
        return 1
    pico = pico_spellings(Commons(root).consts)
    if not pico:
        print(
            "upstream-link-config-keys: FAIL -- paired no upstream key with a "
            f"zenoh-pico macro from {PICO_CONFIG_HEADER}, so the pico spelling of "
            "READ graded nothing (is the submodule initialised?)"
        )
        return 1
    more, read, named = findings_for(
        keys,
        wz_declared_keys(),
        store_reasons(),
        spellings,
        honoured,
        pico,
        wz_pico_macro_reads(),
    )
    findings.extend(more)
    if findings:
        print(f"upstream-link-config-keys: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return 1
    print(
        f"  upstream-link-config-keys: {total} locator config key(s) across "
        f"{len(keys)} upstream link crate(s) at {root} ({total - consumed_total} "
        f"declared by the link, {consumed_total} consumed from zenoh-link-commons) "
        f"-- {read} read by wz, {named} named as their atom's residual"
    )
    return 0


def merged_population(
    root: pathlib.Path, declared_by_link: dict[str, list[str]]
) -> tuple[dict[str, list[str]], dict[str, dict[str, set[str]]]]:
    """Declared plus consumed keys per scheme, and each scheme's config spellings."""
    keys = {s: set(v) for s, v in declared_by_link.items()}
    spellings: dict[str, dict[str, set[str]]] = {}
    links = root / "io" / "zenoh-links"
    for scheme, (consumed, reached) in consumed_keys(root).items():
        if not consumed and scheme not in keys:
            continue
        if scheme not in ATOM_FOR_SCHEME:
            continue
        keys.setdefault(scheme, set()).update(consumed)
        crate = links / f"zenoh-link-{scheme.replace('-', '_')}"
        if not crate.is_dir():
            crate = links / f"zenoh-link-{scheme}"
        sources = sorted(crate.rglob("*.rs")) + sorted(reached)
        spellings[scheme] = config_spellings(sources)
    return {s: sorted(v) for s, v in keys.items()}, spellings


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


def _write(base: pathlib.Path, rel: str, text: str) -> None:
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _selftest_consumed() -> int:
    """R2589 — the consumed population and the two new READ spellings."""

    def fail(msg: str) -> int:
        print(f"upstream-link-config-keys: SELFTEST FAIL -- {msg}")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        c = "io/zenoh-link-commons/src"
        _write(base, f"{c}/lib.rs",
               'pub const BIND_SOCKET: &str = "bind";\n'
               'pub const DSCP: &str = "dscp";\n'
               'pub const TLS_ROOT_CA_CERTIFICATE_FILE: &str = "root_ca_certificate_file";\n'
               'pub const TLS_ENABLE_MTLS: &str = "enable_mtls";\n'
               "mod dscp;\nmod unicast;\npub mod quic;\n"
               "pub use dscp::*;\npub use unicast::*;\n")
        _write(base, f"{c}/dscp.rs",
               "pub fn parse_dscp(config: &Config) { config.get(crate::DSCP); }\n")
        # `new` reads a key, and the generic name is the trap: a crate that merely
        # CALLS some `new` must not consume it.
        _write(base, f"{c}/unicast.rs",
               "pub struct LinkUnicast;\n"
               "impl LinkUnicast { pub fn new(c: &Config) { c.get(crate::BIND_SOCKET); } }\n")
        _write(base, f"{c}/quic/mod.rs", "mod socket;\npub use socket::*;\n")
        _write(base, f"{c}/quic/socket.rs",
               "use crate::parse_dscp;\npub struct QuicSocketConfig;\n")
        links = "io/zenoh-links"
        _write(base, f"{links}/zenoh-link-udp/src/lib.rs",
               "use zenoh_link_commons::{parse_dscp, BIND_SOCKET};\n")
        _write(base, f"{links}/zenoh-link-ws/src/lib.rs",
               "// uses parse_dscp in prose only\n"
               "fn f() { Foo::new(); }\n")
        _write(base, f"{links}/zenoh-link-quic/src/lib.rs",
               "use zenoh_link_commons::quic::QuicSocketConfig;\n"
               "fn inspect_config(&self, config: &ZenohConfig) {\n"
               "    let c = config.transport().link().tls();\n"
               "    if let Some(x) = c.root_ca_certificate() { }\n"
               "}\n")

        consumed = {s: v[0] for s, v in consumed_keys(base).items()}
        if consumed.get("udp") != {"bind", "dscp"}:
            return fail(f"a crate importing `parse_dscp` and `BIND_SOCKET` must consume "
                        f"`dscp` and `bind`; got {consumed.get('udp')}")
        if consumed.get("ws"):
            return fail("a crate that names a helper only in a COMMENT, or calls some "
                        f"generic `new`, must consume nothing; got {consumed.get('ws')}")
        if consumed.get("quic") != {"dscp"}:
            return fail("an import of an item defined in a commons file that itself "
                        "imports `parse_dscp` must reach `dscp` through that file; "
                        f"got {consumed.get('quic')}")

        # A plaintext-QUIC crate reads no TLS key; a secure one does.
        secure = "let x = QuicClientBuilder::new(&e).await?;"
        plain = "let x = QuicClientBuilder::new(&e)\n    .security(false)\n    .await?;"
        if unsecure_quic_only(secure) or not unsecure_quic_only(plain) or unsecure_quic_only(
            plain + secure
        ) or unsecure_quic_only("no builder here"):
            return fail("only a crate whose EVERY QUIC builder is `.security(false)` is "
                        "plaintext-only, and a crate with no builder is not")

        crate = base / links / "zenoh-link-quic" / "src" / "lib.rs"
        spell = config_spellings([crate])
        if "transport/link/tls/root_ca_certificate" not in spell.get(
            "root_ca_certificate_file", set()
        ):
            return fail("`inspect_config` reading `c.root_ca_certificate()` from the tls "
                        f"section must spell `root_ca_certificate_file`; got {spell}")

        _write(base, PICO_CONFIG_HEADER,
               "#define Z_CONFIG_TLS_ENABLE_MTLS_KEY 0x51\n"
               "#define Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY 0x4B\n")
        consts = Commons(base).consts
        pico = pico_spellings(consts, base)
        if pico.get("enable_mtls") != {"Z_CONFIG_TLS_ENABLE_MTLS_KEY"} or pico.get(
            "root_ca_certificate_file"
        ) != {"Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY"}:
            return fail(f"pico macros must pair by constant name, FILE unsuffixed; got {pico}")
        if "bind" in pico:
            return fail("a key with no pico macro in the header must not be paired")

        _write(base, "crates/w/src/a.rs",
               "// Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY named in a comment\n"
               "fn f() { cfg.get(Z_CONFIG_TLS_ENABLE_MTLS_KEY); }\n")
        if wz_pico_macro_reads(base) != {"Z_CONFIG_TLS_ENABLE_MTLS_KEY"}:
            return fail("a pico macro only in a comment must not count as read")

        keys = {"tls": ["bind", "enable_mtls", "root_ca_certificate_file"]}
        tls_spell = {"tls": {"root_ca_certificate_file": {"transport/link/tls/root_ca_certificate"}}}
        honoured = {"transport/link/tls/root_ca_certificate"}
        reasons = {"transport-link-tls": "PARTIAL: `bind` is unread"}
        got, read, named = findings_for(
            keys, set(), reasons, tls_spell, honoured, pico, {"Z_CONFIG_TLS_ENABLE_MTLS_KEY"}
        )
        if got or (read, named) != (2, 1):
            return fail("config and pico spellings must each count as READ and a backticked "
                        f"name must pay for the rest; got {got} / {read} / {named}")
        got, _, _ = findings_for(keys, set(), reasons, tls_spell, set(), pico, set())
        if not any("`enable_mtls`" in f for f in got) or not any(
            "`root_ca_certificate_file`" in f for f in got
        ):
            return fail(f"with neither spelling read, both keys must be findings; got {got}")
        got, _, _ = findings_for(
            {"udp": ["bind"]}, set(),
            {"transport-link-udp": "PARTIAL: see bind_multicast"}, {}, set(), {}, set(),
        )
        if not any("`bind`" in f for f in got):
            return fail("`bind` inside `bind_multicast` must NOT name the key; only the "
                        f"backticked key does; got {got}")
    return 0


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
            "transport-link-unixpipe": "PARTIAL: ... `file_mask` is not modelled",
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
            {**CLEAN_REASONS, "transport-link-unixpipe": "COMPLETE: ... `file_mask` is not modelled"},
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

    rc = _selftest_consumed()
    if rc:
        return rc

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
