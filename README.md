# AIA Reverse Lab

AIA Reverse Lab는 EXE/DLL 정밀 분석을 위한 연구용 바이너리 분석 플랫폼입니다.

이 프로젝트는 본인 소유 파일, 허가받은 샘플, 악성코드 방어 분석, CTF/연구용 바이너리 분석을 목적으로 합니다.

## 1차 목표

현재 1차 목표는 안전한 정적 분석 MVP를 만드는 것입니다.

- PE Header 분석
- Section Table 분석
- Import / Export 분석
- 문자열 추출
- Entropy 계산
- Overlay 탐지
- 패커/프로텍터 의심 탐지
- VMProtect 의심 여부 표시
- JSON / HTML 리포트 생성

## 구현 제한

다음 기능은 공개 배포용 연구도구에 포함하지 않습니다.

- 상용 프로그램 크랙
- 라이선스 우회
- 보호 제거 패치 생성
- VMProtect 자동 언패킹
- 안티디버깅 우회 자동화
- 불법 복제 목적의 실행파일 복원

VMProtect 관련 기능은 보호 우회가 아니라 분석 대상 파일의 구조적 특징, 엔트로피, Import 축소, EntryPoint 이상 여부, 난독화 의심 구간 표시 등 관찰 중심으로 구현합니다.

## 개발 단계

### Step 1

저장소 초기화 및 프로젝트 기준 문서 작성

### Step 2

Python 기반 CLI 프로젝트 구조 생성

### Step 3

PE 기본 분석 코어 구현

### Step 4

문자열 / 엔트로피 / 패커 의심 분석 추가

### Step 5

JSON / HTML 리포트 생성

### Step 6

GUI 또는 고급 분석 모듈 확장

## 사용 예정 기술

- Python 3.11+
- pefile
- Jinja2
- Rich
- SQLite
- Capstone, 선택 확장
- YARA, 선택 확장
- TShark, 선택 확장

## 프로젝트 방향

최종 목표는 하나의 통합형 분석 워크벤치입니다.

```text
AIA Reverse Lab
├─ Static Analyzer
├─ String Analyzer
├─ Entropy Analyzer
├─ Protector Detector
├─ Report Generator
├─ Memory Analyzer, planned
├─ Packet Analyzer, planned
└─ GUI Dashboard, planned
```
