<!--
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# sources/

SCE Forge 입력 SCXML 보관 위치. Mnemosyne SSOT 대상 design-doc
(`docs/` 하위 11종)이 아니며, `sce-codegen` CLI의 입력으로 사용되어
`out/` (gitignored)에 6 backend (rust/cpp/c11/kotlin/go/python) 코드를
생성함.

`docs/`가 "왜 / 무엇을" 결정한 결과라면, `sources/`는 그 결정을
"기계가 읽을 수 있는 SCXML 형태"로 lowering한 결과임.

## 디렉터리 골격

ARCHITECTURE.md §428 (Repository Layout)에 명시된 7-subdir 구조.
서브디렉터리는 첫 SCXML이 들어올 때 생성됨 (lazy). 빈 디렉터리
sentinel(`.keep` 등) 미사용 — design intent는 ARCHITECTURE.md 가
single source of truth.

| Subdir | sce:kind | Phase | Notes |
|---|---|---|---|
| `algorithms/` | `algorithm` | A3+ | CRC, VLE, KeyExpr matching. Generic kind (6-backend emit) |
| `codecs/` | `codec` | B1+ | Zenoh wire 메시지 (~30종). Generic kind |
| `session/` | `statechart` | C8+ | Unicast/multicast/scouting FSM |
| `network/` | `statechart` | B6+ | declare/sub/query/fragment/liveliness FSM |
| `links/` | `link` | B6+ | UDP/TCP/Serial/WS. **MCU-class** (rust + c11 only) |
| `pools/` | `buffer-pool` | B7+ | RX/TX/reassembly pool. **MCU-class** |
| `workers/` | `worker` | C2+ | RX/TX/keepalive worker. **MCU-class** |
| `collections/` | `bounded-collection` | C6+ | Runtime sub/queryable/pending-query/reassembly tables |

**MCU-class** kind는 RFC §5.J.4에 따라 `(rust, *) + (c11, bare_metal)`
에만 emit; cpp/kotlin/go/python은 `codegen/mcu-class-kind-on-non-mcu-
language` hard error로 reject.

## SPDX header convention

모든 `.scxml`는 XML 선언 직후 SPDX header block을 두고, 그 아래
별도의 description comment block을 둠. 두 블록을 분리하는 이유는
REUSE 3.0 spec과 Linux kernel/GNU 관행 — SPDX scanner는 첫 comment
block을 line-by-line parse하므로 license 정보와 description prose를
한 블록에 섞으면 scanner false-positive 위험과 description 편집 시
license header 휘말림 위험이 발생.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
  SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
  SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->
<!--
  (kind, RFC §N 인용, design intent — human-readable prose)
-->
<scxml xmlns="http://www.w3.org/2005/07/scxml"
       xmlns:sce="http://sce.dev/ext"
       sce:kind="..."
       ...>
  ...
</scxml>
```

SPDX 식별자 `LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial`
는 Round 12 (`73c509e`) 이중 라이선스 결정의 표현형. 자세한 라이선스
선택지는 root `LICENSE` 파일 참조.

## 파일명 convention

- **snake_case** (kebab-case 금지, camelCase 금지)
- variant suffix는 underscore (`crc16_ccitt`, `vle_u64`, `udp_unicast`)
- 동일 kind 내 disambiguation은 가장 좁은 식별자가 마지막
  (`keyexpr_intersect`, not `intersect_keyexpr`)
- 함수명 / 모듈명은 입력 파일 stem에서 derive됨
  (`crc16_ccitt.scxml` → `pub fn crc16_ccitt`); 파일명 변경 시
  6 backend의 symbol 모두 영향 — rename은 별도 라운드로 분리

## SCE fixture와의 관계

SCE는 `tests/forge/resources/` 하위에 동일한 의미의 fixture를
보유함 (예: `algorithm_crc16.scxml`). SCE의 fixture는 codegen
engine의 self-test 용도 — SCE Forge harness가 6 backend byte-golden
parity를 검증.

watching-zenoh `sources/`는 downstream installation — `sce-codegen`
CLI가 watching-zenoh 측 입력에 대해 호출됐을 때 SCE의 fixture와
의미적으로 동등한 output을 생성하는지 확인하는 사용자 측 거점.

본문 SCXML body (`<sce:signature>`, `<sce:body>`, `<sce:test-vector>`
등 의미 노드)는 SCE fixture와 byte-identical 유지가 원칙. 차이는
다음 두 가지만 허용:

1. **SPDX header block 추가** — watching-zenoh 측 프로젝트 라이선스
   메타데이터; codegen output에는 영향 없음 (XML parser가 comment
   strip)
2. **파일명 변경** — `algorithm_crc16` (SCE 측 kind-prefix convention)
   → `crc16_ccitt` (watching-zenoh 측 variant-name convention). 이
   차이는 generated symbol 이름과 SCE-MAP 경로에 반영됨

SCE 측 fixture가 갱신될 경우 mechanical sync (본문 변경분을 그대로
가져오고 SPDX header만 유지). divergence는 audit-trace 항목으로
회수 — 무단 divergence 금지.

## 코드젠 호출

단일 파일 (개발 중):

```bash
sce-codegen generate sources/algorithms/crc16_ccitt.scxml \
  -l rust -o /tmp/wz-out/
```

전체 deploy.yaml 기반 build (Phase D 이후):

```bash
sce-codegen build deploy/mcu_target.yaml
# → out/mcu/{inc,src,linker_fragment.ld,memory_map.h}
sce-codegen build deploy/ap_standalone.yaml
# → out/ap/{Cargo.toml, src/}
```

`out/` 디렉터리는 `.gitignore` 대상 — generated artifacts는 SCE의
MIT 라이선스 헤더를 갖고 SCE가 emit policy를 owns함
(`LICENSE-GENERATED.md` in SCE repo).

## third-party vendored snippets

Phase A 코딩 진행 중 vendored 코드 (e.g., zenoh-pico에서 가져온
table data, upstream Zenoh test vectors)가 land할 경우, 해당 코드는
원본 SPDX header를 유지하며, top-level `THIRD_PARTY.md` ledger에
출처/버전/라이선스를 기록함 (CLAUDE.md "License + SPDX header
policy" 단락 참조). 본 README 작성 시점(Round 13)에는 vendored
코드 없음.
