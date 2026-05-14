# Step 9.12 Attacker-Informed Defense

방어자는 공격자의 사고방식을 이해해야 한다. 그러나 이 프로젝트는 침해 실행, 보호 우회, 크랙, 라이선스 우회, 실시간 스니핑, 타 프로세스 메모리 덤프를 자동화하지 않는다.

대신 공격자가 실제로 보는 관점으로 다음을 모델링한다.

## 핵심 관점

- 입력이 어디서 들어오는가
- 파서가 어디서 깨질 수 있는가
- 길이/타입/경계값 검증이 어디서 약한가
- 암호화/압축/인코딩 데이터가 어디에 있는가
- EntryPoint/TLS/섹션 권한이 비정상인가
- 네트워크 payload가 어떤 구조를 갖는가
- 오프라인 PCAP에서 어떤 endpoint/protocol이 민감한가
- 메모리 dump에서 PE/MZ/high entropy/string이 어디에 있는가
- 수정 전후 diff에서 어떤 바이트 range가 바뀌었는가

## 구현 방향

AIA Reverse Lab은 다음 기능으로 공격자 관점을 방어 검증으로 변환한다.

- Problem Locator
- Exposure Assessment
- Input Robustness Corpus
- Binary Dump Viewer
- Offline Memory Dump Analyzer
- Offline PCAP Analyzer
- Opcode Viewer
- Safe Transform Tools
- Static VMProtect Profile
- Crypto/Encoding Indicator Analysis

## 명시적 비목표

- 타 시스템 공격 자동화
- exploit payload 생성
- shellcode 생성
- 보호 우회
- 라이선스 우회
- VMProtect unpack/devirtualize
- 라이브 패킷 스니핑
- 타 프로세스 실시간 메모리 덤프

## 방어 검증 루프

1. 분석 대상 파일/덤프/PCAP을 정적 분석한다.
2. problem_locations에서 우선순위 높은 지점을 본다.
3. dump/opcode/transform 도구로 값을 직접 확인한다.
4. robustness corpus로 입력 변형을 만든다.
5. 자체 파서/서버/디코더에서 crash/hang/error를 재현한다.
6. 취약 지점의 입력 검증/경계값/권한/암호화 처리/예외 처리를 보완한다.
7. 다시 분석하여 exposure score, problem locations, crash 결과를 비교한다.

이 방식은 공격 지식을 방어 품질로 변환하되, 악용 자동화는 포함하지 않는다.
