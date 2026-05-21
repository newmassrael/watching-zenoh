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

1. **와이어 호환성** — zenoh-pico 1.x 클라이언트와 zenoh 1.x
   라우터 / 피어가 주고받는 wire format 의 MVP 부분집합. 범위는
   docs/wire-spec-subset.md 에 명시: 스카우팅 계층, transport
   session 계층, 네트워크 라우팅 계층, zenoh payload 계층,
   extension chain mechanism. 부가 surface (compression, patch,
   full liveliness) 는 후속 phase 로 미룬다.

2. **단일 소스 6 backend codegen** — sources/ 하위 동일 SCXML 이
   Rust no_std (MCU) / C11 / C++ / Kotlin / Go / Python 으로
   SCE Forge 가 생성한다. Conformance harness 가 6 언어를 동일
   vector 로 검증한다. 설계 RFC 는 docs/rfc-sce-protocol-synthesis.md.

설계 SSoT 진입점은 ARCHITECTURE.md. docs/ 하위 12 spec doc 은
Mnemosyne 가 관리 (atomic-store + GENERATED.md lifecycle); 운영
규칙은 CLAUDE.md.

## 현재 상태

스냅샷은 Round 210 (2026-05-21) 시점 갱신. 라운드별 델타는
docs/.atomic/ 의 atomic changelog 가 최신본.

- **Phase A** (author-side SCXML primitive — algorithm): CLOSED.
  algorithm-kind SCXML 전 항목이 6 backend 모두 검증 통과
  (CRC16, VLE u64 decode, VLE byte length, KeyExpr
  intersect/includes, extension dispatch, MID validator 5종 —
  scouting / session / network / declare-sub / payload-Z).
- **Phase B** (codec catalog): wire-spec subset 범위 CLOSED.
  35 wz-emitted codec 이 transport (INIT / OPEN / CLOSE /
  KEEP_ALIVE / FRAME), network (REQUEST / PUSH / RESPONSE /
  RESPONSE_FINAL / OAM / INTEREST / DECLARE), declaration
  sub-MID (DECL_KEXPR / SUBSCRIBER / QUERYABLE / TOKEN /
  INTEREST / FINAL + UNDECL pair), payload body (Reply / Err /
  MsgPut / MsgDel / Query), 그리고 공유 인프라 (ext_envelope /
  ext_entry / ext_unit / ext_zint / ext_zbuf + wireexpr /
  locator / hello / scout / encoding / timestamp / fragment /
  open_body / init_body / join) 까지 모두 커버한다. envelope
  전체가 zenoh-pico `_z_*_encode` 와 byte-equivalent Layer 3
  wire-interop 보유 (crates/wz-integration-tests/tests/
  layer3_*.rs).
- **Phase C** (session-FSM + AP MVP runtime): unicast 트랙
  closed. session_fsm_unicast.scxml 가 timer event
  (link.open_timeout=5s, init/open_ack=2s, closing=100ms) +
  Init→Established→Close 전 경로 보유. TCP transport 완료.
  Cookie HMAC-SHA256 (RFC 4231 TC1-TC7) R70 검증 완료. Pub/Sub
  outbound 100% / inbound 65%. DECLARE outbound 9/9 + inbound
  6/6 완료. Query/Reply outbound + inbound 완료 — Request 레벨
  qos / tstamp / target / budget / timeout extension chain 과
  Response 레벨 responder ext (R210
  `QueryResponder::with_responder` 경유) 포함. Scouting,
  multicast, reassembly, fragmentation 은 후속 phase.
- **Phase W** (lwIP / MCU runtime): first external release 이후
  착수. R58 NOP-stub 은 R63 에 revert (document-around-hack
  금지); 재진입은 cargo publish dry-run + tagged release flow
  안착 이후.
- **First external release** (v0.1.0-mvp): 다음 milestone. 5
  sub-round 으로 README 정돈, deploy.yaml schema 정리, GitHub
  Actions release flow, THIRD_PARTY.md 원장, cargo publish
  dry-run + tag 까지 커버한다.

라운드별 결정은 atomic changelog (docs/.atomic/workspace.atomic.json).
현재 210 entry / 214 atomic section; workspace test ~333 통과
(wz-runtime-tokio lib 단독 185); 로컬 8-lane CI
(scripts/run-ci.sh 의 Layer 0 / A / A2 / B / C1 / C2 / D / E)
가 GitHub Actions workflow 와 동기.

## 디렉터리

| 경로 | 역할 |
|---|---|
| ARCHITECTURE.md | 설계 진입점 |
| docs/ | Mnemosyne 가 관리하는 12 spec doc |
| docs/.atomic/ | Atomic-store sidecar (typed primitive 만 mutate) |
| docs/GENERATED.md | Cascade-render 결과 (gitignored, 직접 편집 금지) |
| sources/ | SCE Forge 입력 SCXML (codec + algorithm + session FSM) |
| crates/wz-codecs | sources/codecs/*.scxml 에서 생성된 codec 타입 |
| crates/wz-runtime-tokio | Tokio 기반 AP 런타임 + session glue + builder |
| crates/wz-runtime-lwip | lwIP / MCU 런타임 skeleton (Phase W) |
| crates/wz-ap-demo | AP MVP demo binary (initiator + acceptor) |
| crates/wz-integration-tests | Layer 3 wire-interop + round-trip suite |
| crates/wz-runtime-tokio-test-support | 런타임 테스트용 shared harness |
| crates/zenoh-pico-sys | vendored zenoh-pico FFI binding (smoke layer) |
| scripts/ | build-sce.sh + verify-codegen.sh + run-ci.sh + audit-mid-values.sh |
| vendor/sce/ | SCE submodule, vendor pin |
| .githooks/ | pre-commit / commit-msg / pre-push 게이트 |
| deploy/ | deploy.yaml skeleton (ap_standalone / mcu_target / ap_mcu_pair) |

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
기여자에게도 동일 적용된다. 결정은 docs/.atomic/workspace.atomic.json
의 atomic changelog Round entry 로 누적되며, 세션 간 인수인계도
이곳에서 이뤄진다 (별도 활동 로그 없음).
