# Step 9.11 Defensive Input Robustness

화이트햇 분석에서 중요한 지점은 단순 점수화가 아니라, 입력 하나가 잘못됐을 때 어디가 깨지는지 찾는 것이다.

이 단계는 공격/침투 자동화가 아니라 방어 목적의 입력 강건성 검증 도구를 추가한다.

## Included

- 파일/덤프/패킷 페이로드 입력 강건성 테스트용 변형 corpus 생성
- 1-byte flip, edge byte 삽입, truncate, duplicate, zero-fill 변형
- 입력 길이/엔트로피/ASCII 비율/NULL 비율/제어문자 비율 산출
- 변형 전후 구조 변화 요약
- 오프라인 PCAP 패킷 payload anomaly 요약
- crash reproduction을 위한 deterministic seed 기록
- JSON summary 출력

## Excluded

- 타 시스템 대상 자동 공격
- live packet injection
- live sniffing
- exploit payload 생성
- shellcode 생성
- 보호 우회/언패킹/라이선스 우회
- 원격 서비스 fuzz 실행

## Purpose

이 기능은 분석자가 자신이 보유한 샘플, 자체 프로토콜 캡처, 자체 입력 파일을 대상으로 다음을 확인하도록 돕는다.

- 어느 입력 구간이 깨지기 쉬운가
- 어떤 바이트 범위가 파서/디코더/복호화 루틴에 민감한가
- 비정상 길이/NULL/제어문자/high entropy 데이터가 존재하는가
- 수정 전후 강건성이 개선되는가
