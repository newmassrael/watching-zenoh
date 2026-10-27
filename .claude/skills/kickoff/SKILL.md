---
name: kickoff
description: watching-zenoh 세션을 시작하거나 이어갈 때 사용. 사용자의 첫 메시지가 `/kickoff`, `시작`, `이어가자`, `kickoff` 중 하나뿐일 때 Mnemosyne 개념 적재, 베이스라인, carry 복원, 미푸시 커밋 확인을 한 번에 한다.
---

# 세션 kickoff

실행할 때 "kickoff 시작" 만 짧게 알리고, 단계마다 보고하지 않는다.

1. Mnemosyne concept 6종을 이 순서로 적재한다 — overview → anti-patterns →
   atomic-store → frozen-ledger → tier-rules → workflow. 이번 세션에 아직 안 읽은
   것만 읽는다.
2. `validate_workspace` 로 베이스라인(T1 orphan / atomic ledger entries·sections /
   style)을 캡처한다.
3. 가장 최근 atomic changelog entry 를 조회해 `carry_forward` 를 복원한다 —
   `mnemosyne-cli query` / `query_section` 으로 latest impact_refs 를 따라간다.
4. `git status` 와 `git log --oneline -5` 로 미푸시 커밋과 최근 활동을 확인한다.
5. SCE 상태가 작업에 필요하면 SCE 소스를 직접 읽는다(경로는 머신-로컬이다 —
   `vendor/sce` 또는 agent memory 에서 확인).

끝나면 carry 의 우선순위와 다음 단계를 제안한다.
