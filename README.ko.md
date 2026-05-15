<!--
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# watching-zenoh (한국어)

> Primary / English: README.md

zenoh 와이어 프로토콜의 MVP 부분집합을 임베디드 (zenoh-pico) 와
서버 (zenoh) 양면 interop 기준으로 재구현하는 6 backend codegen
프로젝트. Source of truth 는 SCXML, Rust no_std / C11 / C++ /
Kotlin / Go / Python 6 언어가 동일 author-side 파일에서 생성된다.

## 무엇인가

이 저장소는 두 가지를 동시에 만든다.

1. **와이어 호환성** — zenoh-pico 1.5.x 클라이언트와 zenoh 1.5.x
   라우터 / 피어가 주고받는 wire format 의 MVP 부분집합. 범위는
   docs/wire-spec-subset.md 에 명시: 스카우팅 계층, transport
   session 계층, 네트워크 라우팅 계층, zenoh payload 계층,
   extension chain mechanism. 부가 surface (compression, patch,
   full liveliness 등) 은 Phase B+ 로 미룬다.

2. **단일 소스 6 backend codegen** — sources/ 하위 동일 SCXML 이
   Rust no_std (MCU) / C11 / C++ / Kotlin / Go / Python 으로
   SCE Forge 가 생성한다. Conformance harness 가 6 언어를 동일
   vector 로 검증한다. 설계 RFC 는 docs/rfc-sce-protocol-synthesis.md.

설계 SSoT 진입점은 ARCHITECTURE.md. docs/ 하위 11 spec doc 은
Mnemosyne 가 관리 (atomic-store + GENERATED.md lifecycle); 운영
규칙은 CLAUDE.md.

## 현재 상태

스냅샷은 Round 26 (2026-05-15) 시점 갱신. 라운드별 델타는
docs/.atomic/ 의 atomic changelog 가 최신본.

- **Phase A3** (author-side SCXML 적재): 9 algorithm, 6 backend
  검증 통과 — CRC16, VLE u64 decode, VLE byte length, KeyExpr
  intersect/includes, extension dispatch, MID validator 5종
  (scouting / session / network / declare-sub / payload-Z).
- **Phase A4** (cursor + Result type + build-time const-fold
  gate): SCE upstream 대기. watching-zenoh 측 carry 는
  tlv_advance, vle_u64_encode, 메시지별 codec body (Put / Del /
  Query / Reply / Err).
- **Phase B+**: SCE schema 확장 (test-vector multi-arg) + 외부
  ratify 의존.

라운드별 결정은 atomic changelog (docs/.atomic/workspace.atomic.json)
와 activity log notes/NEXT_SESSION.md.

## 디렉터리

| 경로 | 역할 |
|---|---|
| ARCHITECTURE.md | 설계 진입점 |
| docs/ | Mnemosyne 가 관리하는 11 spec doc |
| docs/.atomic/ | Atomic-store sidecar (typed primitive 만 mutate) |
| docs/GENERATED.md | Cascade-render 결과 (gitignored, 직접 편집 금지) |
| sources/ | SCE Forge 입력 SCXML (sources/README.md 참조) |
| scripts/ | build-sce.sh + verify-codegen.sh |
| vendor/sce/ | SCE submodule, vendor pin |
| notes/ | Activity-log 장르 (Mnemosyne 외) |
| .githooks/ | pre-commit / commit-msg / pre-push 게이트 |
| deploy/ | deploy.yaml skeleton (Phase B+) |

## 빌드 + 검증

SCE codegen 바이너리는 vendor submodule 에서 빌드한다.

```sh
git submodule update --init --recursive
./scripts/build-sce.sh
```

단일 SCXML 을 6 backend 로 검증한다 (Layer 1).

```sh
./scripts/verify-codegen.sh sources/algorithms/crc16_ccitt.scxml
```

SCE upstream 에 paired fixture 가 있는 경우 두 번째 인자로
byte-golden diff 까지 활성화한다 (Layer 2 — traceability-anchor
정규화 후 body equivalence).

```sh
./scripts/verify-codegen.sh \
  sources/algorithms/keyexpr_intersect.scxml \
  vendor/sce/tests/forge/resources/algorithm_keyexpr_intersect_exact.scxml
```

## Local CI gates

Clone 직후 한 번만 install.

```sh
git config core.hooksPath .githooks
```

세 hook 이 자동 작동한다.

- **pre-commit** — `mnemosyne-cli validate-workspace` (T1
  cross-ref orphan + round-trip + atomic ledger drift 게이트).
- **commit-msg** — COMMIT_FORMAT.md 강제 (subject + 본문 72
  byte/line, no emoji, no co-author, no wrapped bullets).
- **pre-push** — push 시점 재검증으로 manual edit, amend, rebase
  직후 상태를 잡는다 (pre-commit 미커버 영역).

`pre-commit` 과 `pre-push` 는 `mnemosyne-cli` 가 PATH 에 있어야
한다.

```sh
cargo install --path /path/to/mnemosyne/crates/mnemosyne-cli
```

## 라이센스

이 저장소는 **dual-licensed**.

- **LGPL-3.0-or-later** — free tier, LGPL-3 의무사항 (anti-
  tivoization 포함) 동의. 자세히는 LICENSE-LGPL-3.0.md 와
  LICENSE-GPL-3.0.md.
- **LicenseRef-watching-zenoh-Commercial** — paid tier, 5-way
  면제. 자세히는 LICENSE-COMMERCIAL.md.

개요는 LICENSE 가 출발점.

저작자측 소스 파일 (SCXML, Rust, C, header, deploy YAML) 은
다음 SPDX 헤더를 carry 한다.

```
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
```

생성 파일 (`out/**`) 은 SCE 의 MIT 헤더를 carry. Vendored 코드는
원본 SPDX 헤더 유지 + 최상위 THIRD_PARTY.md 원장 (첫 vendored
snippet land 시 생성).

## 외부 참조

- SCE (build infrastructure): scxml-core-engine
  - https://github.com/newmassrael/scxml-core-engine
- Mnemosyne (atomic-store + GENERATED.md lifecycle): mnemosyne
  - https://github.com/newmassrael/mnemosyne
- zenoh upstream
  - https://github.com/eclipse-zenoh/zenoh
- zenoh-pico upstream
  - https://github.com/eclipse-zenoh/zenoh-pico

## 기여

SSOT contract, atomic-store lifecycle, SPDX 헤더 정책이 본
프로젝트 인프라의 핵심이다. 신규 기여자는 CLAUDE.md 를 먼저 읽기
바란다 — AI agent operating guide 형식이지만 거버넌스 규칙은 사람
기여자에게도 동일 적용된다. 결정은 atomic changelog 의 Round
entry 로, 활동 노트는 notes/NEXT_SESSION.md 에 누적된다.
