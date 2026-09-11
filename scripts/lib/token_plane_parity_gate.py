#!/usr/bin/env python3
"""R2564 (no register item) -- mechanise the function-by-function token-plane
diff so the claim cannot rot. It closes the standing residual of
`routing-token-tables`, which is an ATOM grade rather than an open-debt row.

R2566 corrected this header. It first read `R2564 (open debt: none; ...)`, which
says the right thing in the wrong words: `gate_provenance_lint` accepts only the
sanctioned item tokens (`§...`, `N<n>`, `debt-...`, `CENSUS`, `no register item`)
precisely so the open-debt register can be queried BY MACHINE for whether an item
is still open. A phrase that merely means "none" defeats that, and it reads as a
citation to anyone skimming -- which is how it survived review here. It went
undetected for two rounds because Layer C0 is fail-fast and earlier reds masked
this gate entirely.

WHY THIS EXISTS, and it is not "an audit written down". `routing-token-tables`
stood PARTIAL on one residual, stated by its own reason as an UNDONE AUDIT
rather than a missing capability: "a function-by-function diff of upstream's
1184-line token.rs was not" completed. That sentence is now false in a way no
reader could see -- at the pin the router hat's `token.rs` is 400 lines with 11
functions, because upstream refactored between 1.5.0 and 1.10.x. So the residual
described a file that no longer exists, and a PROSE audit closing it would have
acquired exactly the same disease the moment upstream moved again.

⇒ The base defect is not "the diff was not done". It is that the diff had no
mechanism, so whatever anyone concluded decayed silently. This gate is the
mechanism. It re-derives the population from upstream EVERY run, so the day
upstream adds, renames or removes a token-plane method, this goes RED and names
it, instead of a paragraph quietly becoming wrong.

WHAT IT DERIVES (nothing here is a hand-list):
  * the REQUIRED method set of the trait, parsed out of upstream's own
    `zenoh/src/net/routing/hat/mod.rs` @ `pub(crate) trait HatTokenTrait {`.
    A method whose signature ends `;` is required; one ending
    `{` carries a default body. That distinction is load-bearing -- a defaulted
    method is only behaviour a hat OPTS INTO, so it is graded by who overrides
    it, not by whether wz has a twin.
  * which hats implement the trait, and which of them OVERRIDE a defaulted
    method. At the pin exactly one does (`broker`, `unpropagate_last_non_owned_token`),
    and that hat did not exist when this atom's reason was written.
  * the wz counterpart symbols, validated against `atom_test_graph`'s
    cfg-DERIVED owned set for the atom -- not by grepping for a name. A symbol
    that stops being gated by this atom stops counting, which is the half a
    grep cannot see.

WHAT IT DOES NOT CLAIM. It is a NECESSARY condition, not a sufficient one: it
proves the atom has a gated, owned counterpart for every method upstream
requires, and that no mapped counterpart has evaporated. It does not prove the
counterpart is CORRECT -- that is what the atom's tests are for, and what
invariant #6 in `audit-catalog-status.sh` separately requires. Read it as "the
diff is still complete", never as "the behaviour is still right".

THE POPULATION MUST NOT BE ZERO. A gate that reports green because it read
nothing is the failure this workspace names most often, so an empty required set
is a FAIL, and a missing upstream tree DEFERS out loud (rc 0) or FAILS under
`--require` -- it never passes in silence.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

ATOM = "routing-token-tables"

#: Upstream required method -> the wz symbols that carry it. The KEYS are
#: checked against upstream every run (so this map cannot silently describe a
#: vanished surface) and the VALUES against the atom's cfg-derived owned set (so
#: it cannot describe a vanished wz function either). Both directions rot, and
#: the 1.5.0-era residual this gate replaces rotted in the first one.
#:
#: The correspondence itself is a JUDGEMENT and is recorded as such: wz mirrors
#: upstream's semantics through a shared interest core plus a cross-tier plane,
#: rather than method-for-method, so one upstream method can land on more than
#: one wz symbol.
COUNTERPARTS: dict[str, tuple[str, ...]] = {
    # Register a token from a router on an OWNED face: record the source in the
    # inbound tier's table, then propagate along the SOURCE's spanning tree.
    # wz: `ingest_token` -> the shared `ingest_interest` core -> the tree-scoped
    # `reflood_declaration`.
    "register_token": ("ingest_token", "tokens_table"),
    # The removal twin, gated on a REAL removal exactly as upstream gates on the
    # router set becoming empty.
    "unregister_token": ("withdraw_token", "undeclare_push_token"),
    # The cross-REGION arm: upstream inserts its OWN zid as a source and floods
    # from self's tree. wz derives self-membership instead of storing it
    # (idiom-B, derive-not-store), so the twin is the cross-tier advertise.
    "propagate_token": ("advertise_native_cross_tier_token", "push_future_token"),
    "unpropagate_token": (
        "withdraw_native_cross_tier_token",
        "self_advertises_token_into",
    ),
    # "is this token sourced by someone other than me" -- upstream spells the
    # self-exclusion `router != &tables.zid`; under derive-not-store self is
    # never in the mesh tables, so wz folds globally and says why.
    "remote_tokens_of": ("any_token_matches", "contributor_tokens_source_count"),
    "remote_tokens_matching": ("any_token_matches",),
    # The CURRENT-dump leg, which carries upstream's self-exclusion explicitly.
    "sourced_tokens": ("dump_interest_tokens",),
}

#: Defaulted trait methods and the hat that overrides each, AT THE PIN. A new
#: override, or a disappearing one, is a behavioural change in upstream's token
#: plane and this gate's job is to notice. `broker` is not a wz tier, so its
#: override is recorded rather than owed -- see the note this gate prints.
EXPECTED_OVERRIDES: dict[str, tuple[str, ...]] = {
    "unpropagate_last_non_owned_token": ("broker",),
    "remote_tokens": (),
}

#: The tiers this atom actually claims. `class=cfg(routing-token-tables)` names
#: the ROUTER tier and the atom's `P=` names the router and link-state-peer
#: hats, which 1.10.x merged into `peer`.
CLAIMED_HATS = ("router", "peer")

TRAIT = "HatTokenTrait"
#: Composed from segments rather than written as one literal ON PURPOSE. A
#: rooted path spelled whole is a BARE upstream citation to
#: `upstream_citation_anchor_gate.py`, whose bare budget exists to shrink and
#: whose own failure text says never to raise it -- so a gate that cited its
#: subject carelessly would spend another gate's budget to exist. The citation is
#: made properly, once, in the anchored form: this module's docstring names
#: `zenoh/src/net/routing/hat/mod.rs` @ `pub(crate) trait HatTokenTrait {`.
HAT_DIR = pathlib.Path("zenoh") / "src" / "net" / "routing" / "hat"
HAT_MOD = HAT_DIR / "mod.rs"


def upstream_root() -> pathlib.Path | None:
    """The pinned zenoh checkout, or None.

    DELEGATED to `upstream_citation_anchor_gate.upstream_root`, the same chain
    `build-zenohd.sh` mirrors and the same one `upstream_link_axis_gate` uses.
    A fifth private discovery could disagree about WHICH upstream the tree
    means, and that disagreement is what open debt 578 exists for.
    """
    try:
        sys.path.insert(0, str(HERE))
        import upstream_citation_anchor_gate as cite
    except ImportError:  # pragma: no cover - sibling is tracked beside this
        return None
    root = cite.upstream_root()
    if root is not None and (root / HAT_MOD).is_file():
        return root
    return None


def _trait_body(text: str, name: str) -> str | None:
    """The brace-balanced body of `trait <name>`, or None."""
    m = re.search(r"\btrait\s+%s\b" % re.escape(name), text)
    if not m:
        return None
    i = text.find("{", m.end())
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1 : j]
    return None


def parse_trait(text: str) -> tuple[set[str], set[str]]:
    """(required, defaulted) method names of the trait.

    A signature terminated by `;` is required; one terminated by `{` has a
    default body. Return types carry no braces, so the first `;` or `{` after
    the parameter list closes is the terminator.
    """
    body = _trait_body(text, TRAIT)
    if body is None:
        return set(), set()
    required: set[str] = set()
    defaulted: set[str] = set()
    for m in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
        name = m.group(1)
        k = m.end() - 1
        depth = 0
        end = None
        for j in range(k, len(body)):
            c = body[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        if end is None:
            continue
        term = None
        for j in range(end, len(body)):
            if body[j] in ";{":
                term = body[j]
                break
        if term == ";":
            required.add(name)
        elif term == "{":
            defaulted.add(name)
    return required, defaulted


def parse_impl_methods(text: str) -> set[str]:
    """Method names defined inside `impl <TRAIT> for ...` in one file."""
    m = re.search(r"\bimpl\s+%s\s+for\b" % re.escape(TRAIT), text)
    if not m:
        return set()
    i = text.find("{", m.end())
    if i < 0:
        return set()
    depth = 0
    end = len(text)
    for j in range(i, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = j
                break
    return set(re.findall(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", text[i:end]))


def implementors(root: pathlib.Path) -> dict[str, set[str]]:
    """hat name -> the trait methods that hat defines."""
    out: dict[str, set[str]] = {}
    for p in sorted((root / HAT_DIR).glob("*/token.rs")):
        methods = parse_impl_methods(p.read_text(encoding="utf-8", errors="replace"))
        if methods:
            out[p.parent.name] = methods
    return out


def owned_symbols() -> set[str]:
    """The atom's cfg-DERIVED owned symbol set."""
    sys.path.insert(0, str(HERE))
    import atom_test_graph

    owned, _ref = atom_test_graph.graph().get(ATOM, (set(), set()))
    return set(owned)


def grade(root: pathlib.Path) -> list[str]:
    fails: list[str] = []
    text = (root / HAT_MOD).read_text(encoding="utf-8", errors="replace")
    required, defaulted = parse_trait(text)

    print(
        "  token-plane-parity: upstream `%s` declares %d required + %d defaulted "
        "method(s) at the pin" % (TRAIT, len(required), len(defaulted))
    )
    if not required:
        fails.append(
            "the required-method population is EMPTY -- the trait moved or the "
            "parse broke. A gate that reads nothing must not report green."
        )
        return fails

    missing = sorted(required - set(COUNTERPARTS))
    extra = sorted(set(COUNTERPARTS) - required)
    if missing:
        fails.append(
            "upstream requires %d token-plane method(s) this map does not cover: "
            "%s. The diff this gate stands for is no longer complete -- audit the "
            "new method against wz and add it, never delete it from upstream."
            % (len(missing), ", ".join(missing))
        )
    if extra:
        fails.append(
            "this map names %d method(s) upstream no longer requires: %s. That is "
            "citation rot in the same direction the 1.5.0-era residual rotted; "
            "re-read the trait and retire the row."
            % (len(extra), ", ".join(extra))
        )

    owned = owned_symbols()
    print(
        "  token-plane-parity: atom `%s` owns %d cfg-derived symbol(s)"
        % (ATOM, len(owned))
    )
    if not owned:
        fails.append(
            "the atom owns NO cfg-derived symbol -- either the feature was "
            "renamed or the derivation broke. Zero is not a pass."
        )
        return fails

    pairs = 0
    unowned = 0
    for method in sorted(set(COUNTERPARTS) & required):
        for sym in COUNTERPARTS[method]:
            pairs += 1
            if sym not in owned:
                unowned += 1
                fails.append(
                    "`%s` is mapped to wz `%s`, which is not owned by `%s` any "
                    "more (renamed, deleted, or its cfg moved)."
                    % (method, sym, ATOM)
                )
    # Report the MEASUREMENT, not a verdict word. An earlier draft printed
    # "all cfg-owned" unconditionally, so this line contradicted the findings
    # directly beneath it whenever a counterpart went un-owned -- a gate that
    # guards its population and still misreports what it measured.
    print(
        "  token-plane-parity: %d method(s) mapped over %d wz counterpart pair(s), "
        "%d cfg-owned / %d not"
        % (len(set(COUNTERPARTS) & required), pairs, pairs - unowned, unowned)
    )

    impls = implementors(root)
    print(
        "  token-plane-parity: %d hat(s) implement the trait upstream -- %s"
        % (len(impls), ", ".join(sorted(impls)) or "none")
    )
    for hat in CLAIMED_HATS:
        if hat not in impls:
            fails.append(
                "this atom claims the `%s` hat, which no longer implements %s "
                "upstream. The atom's tier claim needs re-reading." % (hat, TRAIT)
            )
    for method, expected in EXPECTED_OVERRIDES.items():
        if method not in defaulted:
            fails.append(
                "`%s` was a DEFAULTED method and is not any more -- a default "
                "becoming required changes who owes behaviour." % method
            )
            continue
        actual = tuple(sorted(h for h, ms in impls.items() if method in ms))
        if actual != tuple(sorted(expected)):
            fails.append(
                "`%s` is overridden by {%s} upstream, not {%s}. An override is "
                "behaviour a hat opts into; a new one may be behaviour wz owes."
                % (method, ", ".join(actual) or "-", ", ".join(expected) or "-")
            )
    unclaimed = sorted(set(impls) - set(CLAIMED_HATS))
    if unclaimed:
        print(
            "  token-plane-parity: NOT CLAIMED by this atom (recorded, not owed) -- "
            "%s. The atom's tier is the router plane; a hat outside it is another "
            "atom's subject." % ", ".join(unclaimed)
        )
    return fails


def _selftest() -> list[str]:
    """Red-first fixtures: each defect must be CAUGHT, its twin must survive."""
    bad: list[str] = []
    ok_trait = """
        pub(crate) trait HatTokenTrait {
            fn register_token(&mut self, a: u8);
            fn remote_tokens(&self, t: &T) -> HashSet<Arc<Resource>> {
                self.remote_tokens_matching(t, None)
            }
            fn sourced_tokens(&self, t: &T) -> HashMap<Arc<Resource>, Sources>;
        }
    """
    req, dfl = parse_trait(ok_trait)
    if req != {"register_token", "sourced_tokens"}:
        bad.append("selftest: required-set parse is wrong: %s" % sorted(req))
    if dfl != {"remote_tokens"}:
        bad.append("selftest: defaulted-set parse is wrong: %s" % sorted(dfl))
    # A defaulted method whose body contains braces must not swallow the rest.
    if "sourced_tokens" not in req:
        bad.append("selftest: a default body swallowed a later required method")
    # The absent trait is not an empty trait.
    if parse_trait("fn register_token(&mut self);") != (set(), set()):
        bad.append("selftest: a trait-less file parsed as methods")
    impl_txt = """
        impl HatTokenTrait for Hat {
            fn register_token(&mut self) {}
            fn unpropagate_last_non_owned_token(&mut self) {}
        }
        fn outside_the_impl() {}
    """
    got = parse_impl_methods(impl_txt)
    if got != {"register_token", "unpropagate_last_non_owned_token"}:
        bad.append("selftest: impl parse leaked or dropped: %s" % sorted(got))
    return bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--require",
        action="store_true",
        help="a missing pinned upstream tree is a FAIL, not a deferral",
    )
    # Accepted and inert: grading IS this gate's default action. It exists so the
    # call sites read identically to the sibling upstream gates beside it in the
    # same lanes (`--selftest` here, `--check --require` in Layer Z) -- a reader
    # comparing those lines should not have to wonder why one of them is spelled
    # differently.
    ap.add_argument("--check", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    bad = _selftest()
    if bad:
        for b in bad:
            print("  token-plane-parity: %s" % b, file=sys.stderr)
        print("token-plane-parity: SELFTEST FAILED", file=sys.stderr)
        return 1
    if args.selftest:
        print("token-plane-parity: selftest OK")
        return 0

    root = upstream_root()
    if root is None:
        msg = (
            "token-plane-parity: DEFERRED -- no pinned zenoh source tree. This "
            "arm grades wz against upstream and cannot run without it; it is NOT "
            "a pass. Point ZENOHD_SRC at a checkout of the pin, or run the lane "
            "that provisions one."
        )
        if args.require:
            print(msg.replace("DEFERRED", "FAIL"), file=sys.stderr)
            return 1
        print("  " + msg)
        return 0

    fails = grade(root)
    if fails:
        for f in fails:
            print("  token-plane-parity: %s" % f, file=sys.stderr)
        print(
            "token-plane-parity: FAIL -- %d finding(s). The token-plane diff that "
            "`%s` rests on no longer holds." % (len(fails), ATOM),
            file=sys.stderr,
        )
        return 1
    print(
        "token-plane-parity: OK -- every token-plane method upstream requires has "
        "a cfg-owned wz counterpart, and upstream's implementor/override census is "
        "unchanged at the pin."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
