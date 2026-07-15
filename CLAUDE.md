# watching-zenoh — AI Agent Operating Guide

This file is auto-read by Claude Code at every session start. It defines
**Mnemosyne SSOT operating rules** for the 12 design docs registered in
`mnemosyne.toml`.

Prior-session context is recovered from the atomic store changelog
(`query_section(.., include_changelog=true)` or `list_sections` →
ChangelogEntry traversal). The legacy `notes/SESSION_KICKOFF.md`
activity log was removed in Round 10 — atomic ledger entries (Round 1+)
are the audit-traced replacement.

## SSOT contract

The atomic store (`docs/.atomic/workspace.atomic.json`) is the single,
directly-validated SSOT. Its Section / ChangelogEntry bodies are
governed by Mnemosyne: mutations route through the typed `set_section_*`
/ `append-changelog-entry` primitives, not through `Edit` / `Write` on
the sidecar JSON. The justification is the same as for any audit-traced
spec system: a typed primitive validates each change against tier rules
(T1 cross-ref orphan, frozen ledger) before persisting, while a regex
`Edit` silently drifts structure.

R408 markdown-doc retirement (2026-06-04): Mnemosyne upstream
(R395-R400) retired the ParsedDoc validator, the `GENERATED.md` render,
and the `generate-docs` cascade. The former `mnemosyne.toml::workspace.docs`
member files (ARCHITECTURE.md, README.md, docs/*.md) are now ordinary
human-readable design notes that Mnemosyne no longer parses or
§N-orphan-validates. Edit them directly; they are not the validated
surface and may drift from the store. To read the SSOT, use
`mnemosyne-cli query` / `query_section`, not a rendered doc.

## Before any action on a registered doc

1. **Read the Mnemosyne concepts you have not yet internalized this
   session** (in order; `anti-patterns` is must-read second — skipping
   it caused this workspace's NarrativeSection mis-recommendation in
   the 2026-05-08 session):
   - `mnemosyne://concepts/overview`
   - `mnemosyne://concepts/anti-patterns`
   - `mnemosyne://concepts/atomic-store`
   - `mnemosyne://concepts/frozen-ledger`
   - `mnemosyne://concepts/tier-rules`
   - `mnemosyne://concepts/workflow`
2. Run `validate_workspace` to surface the current baseline (T1 orphan
   count, atomic ledger entries/sections, style violations). Snapshot
   the numbers — you will compare against this after your mutation.
   (R408: the round-trip and GENERATED.md-sync dimensions are gone; the
   scan is store-direct.)
3. For section-targeted changes: `query_section(section_id,
   include_related=true, include_changelog=true)` first.

## Mutation rules

- **Store Section body edits** → reach for the `set_section_*` /
  `add_section_*` primitives (MCP or `mnemosyne-cli`). Do not `Edit` /
  `Write` the sidecar JSON directly.
- **Sidecar direct `Write` / `Edit`** on
  `docs/.atomic/workspace.atomic.json` is forbidden by default
  (`anti-patterns` #8) — it bypasses tier-rule validation. Route every
  Section / ChangelogEntry body change through a typed primitive.
  (R408 retired `GENERATED.md` and `generate-docs`; there is no longer a
  render cascade to keep in sync — the store IS the artifact.)
- **Changelog entries** (atomic-store audit ledger + the
  `rfc-open-questions-log.md::Change log`) → append via the CLI:
  `mnemosyne-cli append-changelog-entry --entry-id "Round N"
  --decision <text> --changes-file <path> --verification-file <path>
  --impact §A,§B --carry-file <path>`. (Historical note: an earlier MCP
  build exposed an `append_changelog_entry_v2` tool that shelled to an
  `append-changelog-entry-v2` subcommand the CLI never shipped, failing
  `unknown command`. That tool name is RETIRED as of R423 (`c2dbdf14`):
  the CLI + MCP binaries are version-aligned again and the MCP server now
  exposes `append_changelog_entry` (v1). The CLI `append-changelog-entry`
  above stays the canonical append path; the surviving MCP v1 tool is
  untested here.) The other MCP mutate primitives — `set_section_*`,
  `set_inventory_status`, etc. — are CLI-aligned and remain the preferred
  path. New entries must use the
  configured `entry_id_prefix = "Round "` (the date-based legacy entries
  remain as prose under the section heading; do not retrofit them to
  `Round N` form — frozen-ledger spirit applies even though they predate
  the atomic store).
- **After every mutation** → `validate_workspace`. Confirm orphan delta
  = 0 (no new orphans), T3 warn count not increased, atomic ledger drift
  consistent with the mutation (entries / sections delta matches what the
  call should have produced).
- If a mutation needs to reference a section that does not exist yet,
  add the target section first (avoid creating new orphans).

## Atomic store baseline

`docs/.atomic/workspace.atomic.json` holds the workspace as 257
atomic Sections + 576 ChangelogEntries (R408-migration baseline,
schema v8). The typed mutate API surface is the only path for
mutating Section / ChangelogEntry bodies.

There is no `GENERATED.md` render any more (R408 retired it). The
atomic store IS the artifact and the SSOT; read it via
`mnemosyne-cli query` / `query_section`. The former prose docs
(ARCHITECTURE.md, README.md, docs/*.md) survive as un-validated
human design notes — useful narrative, but not authoritative and not
kept in sync with the store.

No NarrativeSection / `prose_blocks` escape-hatch — that route is
`mnemosyne://concepts/anti-patterns` #9 violation (schema extensions
are out of scope; the 4 entity types are closed-form per Round 60
ratify). If a piece of prose appears "un-decomposable", that is a
signal to restructure the prose, not to add an escape-hatch field.

Phase A / B / C / D / E atomic-decompose migration completed at
Round 27 (Phase E final — README atomic decompose). All 12 registered
docs live in the atomic store with typed Section bodies; no doc
remains in the transitional raw-markdown state.

## Raw `Edit` carve-out — closed

The transitional `Edit` / `Write` carve-out applied while docs were
mid-migration from raw markdown to atomic Section form. With migration
complete at Round 27, no registered doc remains in the transitional
state; all Section body mutations route through the typed primitives.
The clause is preserved here as historical context only.

## Local CI gates

`.githooks/` provides three hooks. One-time install per clone:

```
git config core.hooksPath .githooks
```

- **pre-commit** — fast `mnemosyne-cli validate-workspace` gate;
  blocks any commit that introduces a new T1 orphan or a
  resolved-but-still-ledgered entry (drift catch).
- **commit-msg** — enforces `COMMIT_FORMAT.md` (subject and body
  ≤72 bytes per line, no multi-line bullet wraps, no
  Co-Authored-By / "Generated with Claude Code" / emoji).
- **pre-push** — re-runs `mnemosyne-cli validate-workspace` at
  push time so the integrity gate also covers post-commit state
  changes (manual atomic.json edits, amends, rebases) before
  remote share.

`pre-commit` and `pre-push` require `mnemosyne-cli` on `PATH`
(install via
`cargo install --path /path/to/mnemosyne/crates/mnemosyne-cli`).
`commit-msg` needs only bash + GNU grep with the `-P` flag.

## License + SPDX header policy

This project is **dual-licensed**: `LGPL-3.0-or-later` (free, with
LGPL-3 obligations including anti-tivoization) OR
`LicenseRef-watching-zenoh-Commercial` (paid, 5-way exemption). See
`LICENSE` for the overview, `LICENSE-LGPL-3.0.md` /
`LICENSE-GPL-3.0.md` for the verbatim free-tier texts, and
`LICENSE-COMMERCIAL.md` for the commercial alternative.

Author-side source files (SCXML, Rust, C, header, deploy YAML) carry
the SPDX header:

```
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
```

Applies to: `sources/**.scxml`, `crates/**/*.rs`,
`runtime/**/*.{rs,c,h}`, `deploy/**.yaml`.

**Generated files** (`out/**`, committed in-repo since R311y22) carry
whatever header `sce-codegen` emits: SCE's MIT header where SCE emits
one (the statechart `*_sm.rs` files), and NO SPDX header at all on the
codec / buffer-pool emits (SCE does not header those). Do NOT add a wz
SPDX header to any `out/**` file, and do not overwrite an SCE-emitted
one — SCE owns the generation-time header policy (see
`LICENSE-GENERATED.md` in the SCE repo). They are regenerated by the
`xtask` codegen SSOT and gated by run-ci Layer B2.

**Third-party vendored code** keeps its original SPDX header. When the
first vendored snippet lands, add a top-level `THIRD_PARTY.md` ledger
recording origin, version, and license.

**Doc / config files** that are not source (Markdown, JSON metadata,
config TOML) inherit the repo-level `LICENSE` and do not require
in-file SPDX headers.

## Hard prohibitions

- Do not `Edit` / `Write` `mnemosyne.toml` to bypass validation
  (e.g. removing a doc from `workspace.docs` to silence its orphans).
  If a doc genuinely cannot be carried, raise it explicitly.
- Do not retroactively rewrite an existing changelog entry body —
  frozen-ledger anti-pattern. New corrections arrive as new entries.
- Do not drive T3 warn / T4 info counts to zero by mass prose
  rewrite — Round 138 tier mobility ratify, the warning surface is
  intentionally non-zero.

## External references

These are **reference sources, not dependencies** — wz is a from-scratch
reimplementation, so nothing below is a cargo dep of this workspace. Read them
directly whenever SCE / Zenoh state is in question; never infer from memory
(see Response style).

**Machine-local absolute paths are deliberately NOT recorded in this file.**
This file is committed: a path that is correct on one clone is wrong on the
next, it leaks the author's home layout, and nothing gates it. R311y302 is the
proof — the absolute zenoh checkout path that used to live here had silently
rotted to a directory that no longer exists, and it was cited for months.
Resolve the paths per machine and keep them in agent memory or a local
untracked note.

- **SCE** — the codegen engine; pinned, and read-only from wz sessions.
- **Zenoh 1.5.0 (Rust)** — the CORE crates (`zenoh`, `zenoh-protocol`,
  `zenoh-codec`, `zenoh-buffers`, `zenoh-keyexpr`, `zenoh-config`,
  `zenoh-link-*`) land in the local cargo **registry cache** as a side effect
  of building; `cargo fetch` if absent. This is what §5.12-codec / §5.1-transport
  anchor to, and it is why those domains are gradable.
- **Zenoh STORAGE upstream — not obtainable that way, and it BLOCKS work.**
  `zenoh-plugin-storage-manager` and `zenoh-backend-traits` are nobody's cargo
  dependency, so no build ever provisions them. The §5.11-storage /
  §5.24-storage-backend atoms and `adminspace.rs` anchor to them — 14 modules
  cite the plugin by path — so **their A3 impl axis cannot be graded** without a
  deliberate checkout of the `zenoh` repo's `plugins/` tree at the pinned
  version. Until then those atoms stay A3-UNAUDITED, which is the honest state,
  not a gap to paper over. The read-directly rule is NOT waived by the reference
  being inconvenient.
- **zenoh-pico** — vendored in-repo at `vendor/zenoh-pico/`, so unlike the
  others this one is always available to every clone.

## Response style

- Korean for prose; file paths and code identifiers in English.
- Cite file:line for any source claim. No memory-only assertions about
  SCE / Zenoh state — verify by direct read.
- Complex multi-line regex on a registered doc → ask the user to apply
  it manually rather than risk corruption.

## Auto-kickoff trigger

사용자가 첫 메시지로 `/load`, `시작`, `이어가자`, `kickoff` 중 하나만
입력하면 아래 5단계를 그대로 수행한다 (R58: NEXT_SESSION.md 활동 로그
genre가 atomic ledger의 carry_forward와 중복이라 제거됨 — 시작 프롬프트는
이 파일이 단일 소스):

1. Mnemosyne concept 6종 적재 (overview → anti-patterns →
   atomic-store → frozen-ledger → tier-rules → workflow) — 이번 세션에
   아직 안 읽은 것만
2. `validate_workspace` 로 베이스라인 (T1 orphan / atomic ledger
   entries·sections / style) 캡처 (R408: round-trip·GENERATED.md sync
   차원은 제거됨 — store-direct 스캔)
3. 가장 최근 atomic changelog entry 조회 후 `carry_forward` 복원 —
   `mnemosyne-cli query` / `query_section` 으로 latest impact_refs 추적
   (R408: `docs/GENERATED.md` 렌더는 폐기됨; store 가 단일 소스)
4. `git status` + `git log --oneline -5` 로 미푸시 commit + 최근 활동 확인
5. SCE 상태가 작업에 필요하면 SCE 소스를 직접 read (경로는 머신-로컬 —
   External references 규칙에 따라 여기 하드코딩하지 않음; agent memory /
   `vendor/sce`에서 확인)

실행 시 "kickoff 시작" 만 짧게 알리고 중간 단계별 verbose 보고는 생략.
종료 후 carry 우선순위 + 다음 단계 제안.
