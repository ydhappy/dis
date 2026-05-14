# Step 9.14 Result Triage

이 단계는 robustness corpus, bypass resilience, 자체 파서/디코더/서버 테스트 결과를 수집하여 어떤 입력이 문제를 일으켰는지 분류한다.

## Purpose

점수만 보는 것이 아니라, 실제 방어 루프에서 중요한 결과를 자동 정리한다.

- 어떤 입력 case가 crash를 일으켰는가
- 어떤 입력 case가 hang/timeout을 일으켰는가
- 어떤 입력 case가 parse-error를 일으켰는가
- 정상 case와 비정상 case의 입력 프로파일 차이가 무엇인가
- 원본 대비 어떤 mutation이 문제 발생률이 높은가
- 재현에 필요한 seed/case/path가 무엇인가

## Input format

JSON 또는 JSONL 결과 파일을 지원한다.

각 record 예시:

```json
{
  "case_id": 7,
  "case_path": "corpus/case_0007_edge_byte.bin",
  "status": "crash",
  "exit_code": 139,
  "duration_ms": 31,
  "stderr": "segmentation fault",
  "stdout": ""
}
```

지원 status:

- ok
- crash
- hang
- timeout
- parse-error
- reject
- unknown

## Included

- JSON/JSONL result parsing
- status normalization
- severity classification
- mutation별 실패율 집계
- duration 통계
- stderr/stdout keyword tagging
- top failing cases extraction
- remediation hints
- JSON summary output

## Excluded

- target process execution
- exploit generation
- remote testing
- live traffic injection
- protection bypass
- crash exploitability proof

## Defensive workflow

1. `--robustness-input`으로 corpus를 만든다.
2. 자체 테스트 하네스에서 corpus를 실행한다.
3. 결과를 JSON/JSONL로 저장한다.
4. `--triage-results`로 결과를 분류한다.
5. crash/hang/parse-error case를 dump/opcode/transform 도구로 다시 본다.
6. 입력 검증/예외 처리/경계값 처리를 보완한다.
7. 다시 실행하여 실패율이 줄었는지 비교한다.
