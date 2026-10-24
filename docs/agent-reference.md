# Agent reference (on-demand)

This file is NOT auto-loaded. `CLAUDE.md` carries the rules every session needs
and points here for the detail that only matters when the matching action is
being taken (pushing, adding a license header, citing upstream, bumping a pin).
Content here moved out of `CLAUDE.md` to cut the per-session token cost; the
rules themselves stayed in `CLAUDE.md`.

## Local CI gates (read before a push or when a hook refuses)

`.githooks/` provides three hooks. One-time install per clone:

```
git config core.hooksPath .githooks
```

- **pre-commit** -- four checks; ~0.35s for a ledger-only commit, plus
  `cargo fmt` when a `crates/**.rs` is staged. (1) a staged
  `crates/**/Cargo.toml` without its `crates/Cargo.lock` (R52.1);
  (2) `cargo fmt --check` when any `crates/**.rs` is staged (R311au);
  (3) **schema pin (R311y418)**, via `scripts/lib/schema-pin-gate.sh` --
  refuses the commit when the **index's** store `schema_version` exceeds
  `MNEMOSYNE_MAX_SCHEMA` in `scripts/install-mnemosyne-cli.sh`, i.e.
  when a local mutate has migrated the store past what the pinned CI
  reader can open; and when that ceiling moves without `MNEMOSYNE_REV`
  moving too, since raising the ceiling alone only silences the gate.
  Check 4 is blind to the schema case in the shape that has fired (the
  local binary that just migrated the store can still read it, so it
  passes while hosted Layer A reds); all four firings -- R311y15, y401,
  y406, y416 -- surfaced on hosted CI, never locally. Bump
  `MNEMOSYNE_REV` and `MNEMOSYNE_MAX_SCHEMA` together, in their own
  commit. (4) `mnemosyne-cli validate-workspace` -- blocks any commit
  that introduces a new T1 orphan or a resolved-but-still-ledgered
  entry (drift catch).
- **commit-msg** -- enforces `COMMIT_FORMAT.md` (subject and body
  <=72 bytes per line, no multi-line bullet wraps, no
  Co-Authored-By / "Generated with Claude Code" / emoji).
- **pre-push** -- fast publication and SSOT checks by default. The owner's
  2026-09-23 instruction supersedes the accumulated local-sweep requirements:
  **slow checks belong in hosted CI**, even when they only parse source files.
  One push spent over 16 minutes in static checks; the previous full hook took
  about 90 minutes. Historical warm timings are not a current runtime budget.

  Mandatory gates remain: confidential vocabulary, home paths and identities
  (0/0b/0c), schema and tool pins (1), workspace SSOT validation (2), the
  claim-scoped proof audit (2b), and the previous hosted verdict (2c, without
  waiting for a running job). Since open-debt item 897 the default hook also
  runs the cheap, tree-only checks that hosted CI went red on while the hook
  stayed green: the upstream-citation form gates (2f, about 11s), the hosted
  static lanes C0d/C0e/C0f with the count-guard lint (2c2, about 7s), and the
  count-guard oracle in its build-free mode (2c3, item 898, about 2s):
  `guarded_count_gate.py --cached-only` selects the guards the push range
  reaches and judges them against the per-clone measurement cache. A cached
  count that disagrees with its declared number REFUSES the push (a known wrong
  number); a reached guard with no measurement for this tree prints one
  DEFERRED line, naming the count and the command that measures them, and the
  push proceeds (hosted CI judges it); an oracle that cannot run or read
  refuses, since that says nothing about any count. `scripts/lib/hook_default_region_gate.py`
  holds the list of checks above the boundary, with each check's measured
  seconds, and the checks that stay hosted on purpose (Layer U, which needs the
  network, and the count-guard builds, whose cold measurement was 473s for one
  guard). The default hook exits after these checks.

  The remaining static gates, feature tests/census, Layer 0, changed-crate
  tests and documentation checks, reduced-feature checks, clippy and workspace
  builds are **deferred to hosted CI**. Deferral is printed and is not a local
  passing result. Verify the change's focused behavior during development;
  do not repeat a broad CI sweep just because a push is about to happen.

  To explicitly request the preserved extended local sweep, use
  `WZ_PREPUSH_EXTENDED=1 git push origin main`. This does not bypass mandatory
  checks. Count-guard builds remain separately opt-in with
  `WZ_PREPUSH_COUNT_GUARD=1` inside that extended sweep. The scripts and hosted
  lane assertions are unchanged; hosted failures are diagnosed next round.
  Run `bash scripts/run-ci.sh` manually when a full local CI run is wanted.

- **Development speed first** (owner, 2026-10-09). Verification is batched,
  not repeated per item. A worker on one item verifies only that item: its
  build, the item's tests, and clippy of the crates it touched (per crate;
  never two crates with `--all-features` in one command). It does not run the
  full gate array, the Layer C0 family or the count-guard oracle per item.
  Finished work is merged into ONE integration branch; the preflight (gate
  array, C0/C0d/C0e/C0f/U, upstream citation gate, count guards by oracle)
  runs ONCE there and the branch is pushed ONCE with one acknowledgement row,
  so a single hosted run is not cancelled by the next push. Do not hold work
  waiting for a hosted run; read its result when it arrives. Never skip a
  failing gate and never bypass the hooks.

`pre-commit` and `pre-push` require `mnemosyne-cli` on `PATH`
(install via
`cargo install --path /path/to/mnemosyne/crates/mnemosyne-cli`).
The agent-session MCP server is a SEPARATE binary at the same pin --
`bash scripts/install-mnemosyne-mcp.sh`, which reads `MNEMOSYNE_REV`
through the same parser the hooks use. It is deliberately not part of
the CI installer (CI never speaks MCP), which is exactly why it can
drift; see "Stale MCP server" below.
`pre-commit` and `pre-push` additionally require `python3` -- the schema
pin reads the store's `schema_version` with a real JSON parse, which is
indifferent to serialization and type-checks the value (the literal
`schema_version` also occurs 22x in ledger prose inside that file). Its
absence is a hard FAIL, not a skip: a gate that cannot read its input
must not report green. `run-ci.sh` is split on this -- Layers D (:4603)
and F (:4873) SKIP-green on python3 -- but each sits behind a
`WZ_*_REQUIRE` arming flag with a hosted hard-fail behind it, which a
git hook has neither of; Layer C0 (:1061) FAILs, and that is the shape
here.
`commit-msg` needs only bash + GNU grep with the `-P` flag.

## Stale MCP server and the tool pin

**If the Mnemosyne concept resources are unreachable, the MCP server is STALE,
not absent.** `mnemosyne-mcp` is pinned to the same `MNEMOSYNE_REV` as the
CLI but nothing in the CI installer installs it, so a pin bump moves
the CLI and leaves the server behind; it then dies at startup parsing
a `mnemosyne.toml` field it does not know, and the client reports only
`Connection closed` -- which reads exactly like "no server configured".
R311y429 bumped the rev for `scan_exclusions` and this went undiagnosed
for two rounds. Run `bash scripts/install-mnemosyne-mcp.sh` (reads the
rev from the pin, verifies with a real `initialize` handshake) and
restart the session. Do NOT proceed treating the concepts as
unavailable, and do NOT edit `mnemosyne.toml` to make the old server
start.

R311y462 made this failure mode LOUD instead of latent, and added one
rule. `mnemosyne.toml` now carries `[tool] pin`, which must equal
`MNEMOSYNE_REV` in `scripts/install-mnemosyne-cli.sh` -- one fact in two
places on purpose: the installer constant is the SSOT (both workflows
install it; `install-mnemosyne-mcp.sh` parses it out of HEAD), while the
toml key is where every binary reads it, **including the MCP server,
which the installer's schema gate never interrogates**. A build whose
rev does not prefix-match the pin now refuses with an actionable error
instead of silently reinterpreting the tree. Consequence when moving
it: install the new rev's **cli AND mcp**, confirm both from cargo's own
ledger (`~/.cargo/.crates.toml`, not `--version`), then move both
constants in ONE commit. Backwards, the old binary dies in TOML parse
before it can explain itself, and `MNEMOSYNE_PIN_SKIP=1` does not
rescue that -- it is read only after the config has parsed.

## Changelog append: history of the `--impact` leak

`--impact` takes STORE SECTION IDS, not the section-number you would say out
loud -- `feature-inventory--.../5-atomic-feature-catalog/5-4-session`, not
`§5.4-session`. Copy them out of `mnemosyne-cli query --list-sections`.
The wrapper `scripts/append-round.sh` exists solely to resolve those ids BEFORE
the append: this class has leaked six times (Round 193, y327, y503 x2, y579,
y782), and the window is one call wide -- `validate_workspace` catches a bad
ref, but only after the entry has FROZEN, at which point the fix is no longer a
retype but an `[[orphan_ledger]]` row plus a whole re-citing round. Calling
`mnemosyne-cli append-changelog-entry` directly still works and is what the
wrapper `exec`s; it just gives up the only cheap moment there is.

Historical note: an earlier MCP build exposed an `append_changelog_entry_v2`
tool that shelled to an `append-changelog-entry-v2` subcommand the CLI never
shipped, failing `unknown command`. That tool name is RETIRED as of R423
(`c2dbdf14`): the CLI + MCP binaries are version-aligned again and the MCP
server now exposes `append_changelog_entry` (v1). The CLI
`append-changelog-entry` stays the canonical append path; the surviving MCP v1
tool is untested here. New entries use `entry_id_prefix = "Round "` (the
date-based legacy entries remain as prose under the section heading; do not
retrofit them to `Round N` form -- frozen-ledger spirit applies even though
they predate the atomic store).

## Atomic store background

R408 markdown-doc retirement (2026-06-04): Mnemosyne upstream (R395-R400)
retired the ParsedDoc validator, the `GENERATED.md` render, and the
`generate-docs` cascade. The former `mnemosyne.toml::workspace.docs` member
files (ARCHITECTURE.md, README.md, docs/*.md) are now ordinary human-readable
design notes that Mnemosyne no longer parses or section-orphan-validates. Edit
them directly; they are not the validated surface and may drift from the store.
To read the SSOT, use `mnemosyne-cli query` / `query_section`, not a rendered
doc.

Phase A / B / C / D / E atomic-decompose migration completed at Round 27. All
12 registered docs live in the atomic store with typed Section bodies. The
transitional raw `Edit` / `Write` carve-out is closed (historical context only).
Schema v8 at the R408 migration; the section / entry counts move every round,
so read them from `validate_workspace`, never from prose.

No NarrativeSection / `prose_blocks` escape-hatch -- that route is
`mnemosyne://concepts/anti-patterns` #9 violation (schema extensions are out of
scope; the 4 entity types are closed-form per Round 60 ratify). If a piece of
prose appears "un-decomposable", that is a signal to restructure the prose, not
to add an escape-hatch field.

## License + SPDX header policy (detail)

This project is **source-available**:
`LicenseRef-watching-zenoh-NonCommercial-1.0` (free for personal
learning, non-commercial research and an organization's evaluation
outside production) OR `LicenseRef-watching-zenoh-Commercial` (every
other use, agreed in writing). `LICENSE` is the verbatim free-tier
text and `LICENSE-COMMERCIAL.md` states the commercial alternative.
The shape follows `sce-spec-workbench`.

The free tier was `AGPL-3.0-or-later` from 2026-08-25 to 2026-10-18
and `LGPL-3.0-or-later` before that. Revisions published under them
keep those terms for the copies they were given with (their texts are
in the git history; the `LICENSE-*GPL*` files were removed); this tree
carries the non-commercial expression from the relicense commit on.
The first move (LGPL to AGPL) and the second (AGPL to this one) used the
same tool. The
substitution is rerunnable and gated --
`scripts/lib/relicense_spdx.py` (exact-literal, `--check` mode FAILs
when any tracked file still carries the old expression).

That script takes a REQUIRED mode and has no default: `--check`
reads, `--apply` writes, `--selftest` drives both against a fixture.
An unknown argument is refused by name. Until R2104b it decided with
`"--check" in sys.argv`, so every other input -- `--help`, a typo, no
argument at all -- fell through to the REWRITE path; `--help` printed
`rewrote 0 file(s)` and exited 0. Read and write are opposites here,
so the program will not guess which was meant.

(R311y794 removed `runtime/**/*.{rs,c,h}` from the header list: there is no
`runtime/` directory in this tree and there has not been one.)

**Generated files** (`out/**`, committed in-repo since R311y22) carry
whatever header `sce-codegen` emits: SCE's own header where SCE emits
one (the statechart `*_sm.rs` files; MIT before the Round 3008 pin,
AGPL-3.0-only WITH the SCE Linking Exception OR SCE Commercial since),
and NO SPDX header at all on the
codec / buffer-pool emits (SCE does not header those). Do NOT add a wz
SPDX header to any `out/**` file, and do not overwrite an SCE-emitted
one -- SCE owns the generation-time header policy (see
`LICENSE-GENERATED.md` in the SCE repo). They are regenerated by the
`xtask` codegen SSOT and gated by run-ci Layer B2.

**Third-party vendored code** keeps its original SPDX header. When the
first vendored snippet lands, add a top-level `THIRD_PARTY.md` ledger
recording origin, version, and license.

**The zenoh family** (`crates/wz-zenoh-*`, atom `api-compat-rust`) is
derived from upstream's crates, so it is NOT under the wz header: every
source file keeps upstream's notice block, then `SPDX-License-Identifier:
EPL-2.0 OR Apache-2.0`, then our `SPDX-FileCopyrightText` and a `Modified by
... Derived from <crate> 1.10.1, file <path>` statement, and the manifests
declare that expression (`LICENSES/` holds both texts). A new file of a family
crate copies the block of the file it derives from. `scripts/lib/
family_notice_gate.py` enforces it (form in the hook and Layer C0, resolution
against the pin in Layer Z); the only exempt member is the empty `zenoh`
facade, until it declares a public item. Decided 2026-10-24 under the owner's
delegation; the reasoning is in `THIRD_PARTY.md`.

**Doc / config files** that are not source (Markdown, JSON metadata,
config TOML) inherit the repo-level `LICENSE` and do not require
in-file SPDX headers.

## External references (detail)

These are **reference sources, not dependencies** -- wz is a from-scratch
reimplementation, so nothing below is a cargo dep of this workspace. Read them
directly whenever SCE / Zenoh state is in question; never infer from memory.

**Machine-local absolute paths are deliberately NOT recorded in `CLAUDE.md`.**
That file is committed: a path that is correct on one clone is wrong on the
next, it leaks the author's home layout, and nothing gates it. R311y302 is the
proof -- the absolute zenoh checkout path that used to live there had silently
rotted to a directory that no longer exists, and it was cited for months.
Resolve the paths per machine and keep them in agent memory or a local
untracked note.

- **SCE** -- the codegen engine; pinned, and read-only from wz sessions.
- **Zenoh (Rust) core crates** (`zenoh`, `zenoh-protocol`, `zenoh-codec`,
  `zenoh-buffers`, `zenoh-keyexpr`, `zenoh-config`, `zenoh-link-*`) at the
  pinned version, `UPSTREAM_VERSION` in `scripts/lib/upstream_feature_census.py`.
  This is what §5.12-codec / §5.1-transport anchor to, and it is why those
  domains are gradable. Do NOT locate the tree yourself: `upstream_root()` in
  `scripts/lib/upstream_citation_anchor_gate.py` is the one resolver, and it
  accepts only a checkout whose manifest declares exactly that version (no
  fallback; none found is a FAIL). The tree is a cargo git checkout, the
  `build-zenohd.sh` shallow clone, or an explicit `ZENOHD_SRC`; the registry
  cache copy of the crates is last in the census chain and lacks the workspace
  layout `upstream_root()` needs. A checkout of ANY OTHER version left on the
  machine (the previous pin's, for one) is a different upstream: a person who
  finds it reads it coherently and cites it, and the citations are wrong at
  the pin. Never cite from it.
- **Zenoh STORAGE upstream -- needs a DELIBERATE checkout; no build provisions
  it.** `zenoh-plugin-storage-manager` and `zenoh-backend-traits` are nobody's
  cargo dependency, so the cargo-cache route never yields them. The
  §5.11-storage / §5.24-storage-backend atoms and `adminspace.rs` anchor to
  them, so grading their A3 impl axis needs a checkout of the `zenoh` repo's
  `plugins/` tree at the pinned version. **Whether that checkout exists on THIS
  machine is machine-local state: resolve it per the rule above -- never read
  "blocked" off a note, including a prior session's.** R311y339 is the proof:
  a note said "it BLOCKS work" and an agent-memory hook said "ABSENT ->
  UNGRADABLE" for ~37 rounds after the clone had already landed; both were
  quoted instead of checked, and the domain stayed shut for months over a
  directory that was there. Absent the checkout, A3-UNAUDITED is the honest
  state, not a gap to paper over -- but "absent" is a fact to establish, not to
  inherit.
- **zenoh-pico** -- vendored as a SUBMODULE at `vendor/zenoh-pico/`, so it is
  present in a clone that initialises submodules (`--recurse-submodules`, or a
  later `git submodule update --init`) and ABSENT from one that does not: a
  bare clone leaves the directory empty, and `git ls-files vendor/zenoh-pico/`
  yields the gitlink rather than the tree. `vendor/sce` is the same shape, so
  the contrast is not pico-versus-the-rest -- it is the two SUBMODULES against
  the zenoh references above, which no submodule carries and which each need
  provisioning of their own.
