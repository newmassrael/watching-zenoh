# watching-zenoh — AI Agent Operating Guide

Auto-read at every session start. Defines the **Mnemosyne SSOT operating rules**
for the 12 design docs registered in `mnemosyne.toml`. Detail that matters only
for one action (push, license header, upstream citation, pin bump) lives in
`docs/agent-reference.md` — read the named section when you take that action.

Prior-session context comes from the atomic store changelog
(`query_section(.., include_changelog=true)` or `list_sections` →
ChangelogEntry traversal), not from a session log file.

## SSOT contract

The atomic store (`docs/.atomic/workspace.atomic.json`) is the single,
directly-validated SSOT. Its Section / ChangelogEntry bodies change only through
the typed `set_section_*` / `add_section_*` / `append-changelog-entry`
primitives, never through `Edit` / `Write` on the sidecar JSON: a typed
primitive validates against tier rules (T1 cross-ref orphan, frozen ledger)
before persisting, while a regex `Edit` silently drifts structure.

The former member docs (ARCHITECTURE.md, README.md, docs/*.md) are ordinary
human-readable design notes since R408: not parsed, not validated, may drift
from the store. Edit them directly. Read the SSOT with `mnemosyne-cli query` /
`query_section`. There is no `GENERATED.md` and no NarrativeSection /
`prose_blocks` escape hatch (`anti-patterns` #9); un-decomposable prose means
restructure the prose. Background: `docs/agent-reference.md` § Atomic store.

## Before any action on a registered doc

1. Read the Mnemosyne concepts not yet read this session, in order
   (`anti-patterns` is must-read second): `mnemosyne://concepts/` `overview`,
   `anti-patterns`, `atomic-store`, `frozen-ledger`, `tier-rules`, `workflow`.
   **Unreachable resources mean the MCP server is STALE, not absent** (it dies
   parsing a `mnemosyne.toml` field it does not know; the client says only
   `Connection closed`). Run `bash scripts/install-mnemosyne-mcp.sh`, restart
   the session, and do NOT edit `mnemosyne.toml` to make the old server start.
   Pin-bump procedure: `docs/agent-reference.md` § Stale MCP server and the
   tool pin.
2. Run `validate_workspace` and snapshot the baseline (T1 orphan count, ledger
   entries/sections, style violations) to compare after your mutation.
3. For section-targeted changes: `query_section(section_id,
   include_related=true, include_changelog=true)` first.

## Mutation rules

- Section body edits → `set_section_*` / `add_section_*` (MCP or
  `mnemosyne-cli`). Never `Edit` / `Write` the sidecar JSON.
- Changelog entries (atomic ledger and `rfc-open-questions-log.md::Change log`)
  → **`bash scripts/append-round.sh`**, which takes the CLI's own arguments:
  `--entry-id "Round N" --decision-file <path> --changes-file <path>
  --verification-file <path> --impact <id>[,<id>...] --carry-file <path>`.
  **`--impact` takes STORE SECTION IDS** (copy from `mnemosyne-cli query
  --list-sections`), not the §-number you would say aloud. The wrapper resolves
  them before the append; once an entry freezes, a bad ref costs a whole
  re-citing round. Entry ids use the `Round ` prefix.
- After every mutation → `validate_workspace`: orphan delta 0, T3 warn count
  not increased, entries/sections delta matches the call.
- If a mutation references a section that does not exist yet, add the target
  section first.

## Local CI gates

One-time per clone: `git config core.hooksPath .githooks`. Requires
`mnemosyne-cli` and `python3` on `PATH` (a missing python3 is a hard FAIL).

- **pre-commit** — Cargo.toml ↔ Cargo.lock pairing, `cargo fmt --check`,
  schema pin (store `schema_version` ≤ `MNEMOSYNE_MAX_SCHEMA`; bump
  `MNEMOSYNE_REV` and `MNEMOSYNE_MAX_SCHEMA` together in their own commit),
  `mnemosyne-cli validate-workspace` (no new T1 orphan).
- **commit-msg** — enforces `COMMIT_FORMAT.md`: subject and body ≤72 bytes per
  line, no multi-line bullet wraps, no Co-Authored-By / "Generated with Claude
  Code" / emoji.
- **pre-push** — fast publication and SSOT checks only; slow checks belong to
  hosted CI (owner, 2026-09-23). Deferral is printed and is not a local pass.
  Verify the change's focused behavior while developing; do not repeat a broad
  sweep because a push is near. `WZ_PREPUSH_EXTENDED=1 git push origin main`
  requests the extended sweep; `bash scripts/run-ci.sh` is the full local CI.
  Gate list, timings and opt-ins: `docs/agent-reference.md` § Local CI gates.
- **Development speed first** (owner, 2026-10-09). Verification is batched. A
  worker on one item verifies only that item: its build, its tests, and clippy
  of the crates it touched (per crate; never two crates with `--all-features`
  in one command) — not the full gate array, Layer C0 family or count-guard
  oracle. Finished work merges into ONE integration branch; the preflight runs
  ONCE there and the branch is pushed ONCE with one acknowledgement row. Do not
  hold work waiting for a hosted run; read its result when it arrives. Never
  skip a failing gate and never bypass the hooks.

## License + SPDX header policy

Source-available, non-commercial or commercial:
`LicenseRef-watching-zenoh-NonCommercial-1.0` OR
`LicenseRef-watching-zenoh-Commercial` (see `LICENSE`, `LICENSE-COMMERCIAL.md`).
The free tier was AGPL-3.0-or-later before 2026-10-18. Author-side source files carry this header:

```
SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
```

Applies to `sources/**.scxml`, `crates/**/*.rs`, `deploy/**.yaml`. Do NOT add it
to `out/**` (generated; SCE owns that header policy) and do not overwrite an
SCE-emitted one. Vendored code keeps its original header; Markdown/JSON/TOML
inherit `LICENSE`. `scripts/lib/relicense_spdx.py` requires an explicit mode
(`--check` / `--apply` / `--selftest`). Detail: `docs/agent-reference.md`
§ License.

## Hard prohibitions

- Do not `Edit` / `Write` `mnemosyne.toml` to bypass validation (e.g. removing a
  doc from `workspace.docs` to silence its orphans). If a doc genuinely cannot
  be carried, raise it explicitly.
- Do not retroactively rewrite an existing changelog entry body — frozen-ledger
  anti-pattern. Corrections arrive as new entries.
- Do not drive T3 warn / T4 info counts to zero by mass prose rewrite — the
  warning surface is intentionally non-zero (Round 138 tier mobility ratify).

## External references

Reference sources, not dependencies — wz is a from-scratch reimplementation.
Read them directly whenever SCE / Zenoh state is in question; never infer from
memory. **Machine-local absolute paths are NOT recorded here** (committed file;
resolve per machine, keep in agent memory).

- **SCE** — codegen engine; pinned, read-only from wz sessions.
- **Zenoh (Rust), at the PINNED version** — core crates (`zenoh`,
  `zenoh-protocol`, `zenoh-codec`, `zenoh-buffers`, `zenoh-keyexpr`,
  `zenoh-config`, `zenoh-link-*`). The version compared against and enforced is
  `UPSTREAM_VERSION` in `scripts/lib/upstream_feature_census.py` (1.10.1). The
  number written here is HELD by `scripts/lib/claude_md_upstream_pin_gate.py`,
  which fails on any version token in this bullet that differs from the
  constant, and on a bullet that no longer names the constant or states a
  version; move the constant and this number in one commit. Do NOT locate the
  tree yourself: `upstream_root()` in
  `scripts/lib/upstream_citation_anchor_gate.py` is the one resolver, and it
  accepts only a checkout of exactly that version (none found is a FAIL). Never
  cite from a checkout of any other version left on the machine.
- **Zenoh STORAGE upstream** (`zenoh-plugin-storage-manager`,
  `zenoh-backend-traits`) — needs a DELIBERATE checkout of the `zenoh` repo's
  `plugins/` tree at the pinned version; no build provisions it. Whether it
  exists on THIS machine is a fact to establish per session, never to inherit
  from a note. Absent → A3-UNAUDITED is the honest state.
- **zenoh-pico**, **`vendor/sce`** — git SUBMODULES; empty in a clone that did
  not init submodules (`git submodule update --init`).

Full detail and the failure history: `docs/agent-reference.md` § External
references.

## Response style

- Korean for prose; file paths and code identifiers in English.
- Cite file:line for any source claim. No memory-only assertions about
  SCE / Zenoh state — verify by direct read.
- Complex multi-line regex on a registered doc → ask the user to apply it
  manually rather than risk corruption.

## Auto-kickoff trigger

사용자가 첫 메시지로 `/load`, `시작`, `이어가자`, `kickoff` 중 하나만
입력하면 아래 5단계를 그대로 수행한다:

1. Mnemosyne concept 6종 적재 (overview → anti-patterns →
   atomic-store → frozen-ledger → tier-rules → workflow) — 이번 세션에
   아직 안 읽은 것만
2. `validate_workspace` 로 베이스라인 (T1 orphan / atomic ledger
   entries·sections / style) 캡처
3. 가장 최근 atomic changelog entry 조회 후 `carry_forward` 복원 —
   `mnemosyne-cli query` / `query_section` 으로 latest impact_refs 추적
4. `git status` + `git log --oneline -5` 로 미푸시 commit + 최근 활동 확인
5. SCE 상태가 작업에 필요하면 SCE 소스를 직접 read (경로는 머신-로컬 —
   `vendor/sce` 또는 agent memory 에서 확인)

실행 시 "kickoff 시작" 만 짧게 알리고 중간 단계별 verbose 보고는 생략.
종료 후 carry 우선순위 + 다음 단계 제안.
