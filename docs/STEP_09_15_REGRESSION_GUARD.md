# Step 9.15 Regression Guard

Regression Guard는 보완 전/후 테스트 결과를 비교하여 방어 품질이 실제로 개선됐는지 판정한다.

## Purpose

점수나 단일 분석 결과만으로는 부족하다. 보안 보완은 다음 질문에 답해야 한다.

- crash가 줄었는가?
- hang/timeout이 줄었는가?
- parse-error가 줄었는가?
- 실패율이 낮아졌는가?
- 새롭게 생긴 실패 케이스가 있는가?
- 보완 후에도 남은 top failure는 무엇인가?
- CI에서 통과/실패로 판단할 수 있는가?

## Input

Regression Guard는 다음 입력을 지원한다.

- `--triage-results`로 생성한 triage JSON
- raw JSON/JSONL corpus execution result

raw result는 내부적으로 Result Triage 형식으로 정규화한 뒤 비교한다.

## Status severity order

- crash: highest risk
- hang / timeout
- parse-error
- unknown
- reject / ok

## Default gate

기본 gate는 다음 조건에서 실패한다.

- crash count가 증가한 경우
- timeout/hang count가 증가한 경우
- 전체 failing count가 증가한 경우
- fail rate가 증가한 경우
- critical/high severity count가 증가한 경우

## Output

- before/after status counts
- before/after severity counts
- failure delta
- fail rate delta
- new failing cases
- resolved failing cases
- persistent failing cases
- pass/fail decision
- remediation hints

## Defensive workflow

1. robustness corpus 생성
2. 보완 전 테스트 실행
3. result triage 생성
4. 코드/파서/입력검증 보완
5. 보완 후 같은 corpus 재실행
6. Regression Guard로 전후 비교
7. CI gate로 사용
