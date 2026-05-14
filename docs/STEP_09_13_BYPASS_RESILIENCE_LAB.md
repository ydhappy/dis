# Step 9.13 Bypass Resilience Lab

이 단계는 실제 보호우회, 라이선스우회, VMProtect 우회, 탐지 회피 악용 코드를 구현하지 않는다.

대신 방어 검증을 위해 자체 입력 검증/탐지 규칙/파서가 변형 입력에 얼마나 강한지 확인하는 Bypass Resilience Lab을 제공한다.

## Included

- Local-only rule resilience testing
- Canonicalization mismatch checks
- Case folding variants
- Whitespace variants
- Unicode normalization variants
- URL percent-encoding variants
- Hex/base64 representation variants
- Prefix/suffix padding variants
- Null/control-byte visibility checks
- Rule hit/miss comparison
- JSON output for remediation tracking

## Excluded

- Real software protection bypass
- VMProtect unpacking/devirtualization/bypass
- License bypass or emulator generation
- Anti-debug bypass implementation
- Detection evasion payloads for third-party systems
- Live target testing
- Exploit generation
- Patch/crack generation

## Purpose

화이트햇 관점에서 우회 실험은 필요하다. 이 모듈은 공격 자동화를 제공하지 않고, 다음 질문에 답한다.

- 우리 검증 로직은 정규화 전에 검사하는가, 후에 검사하는가?
- 대소문자/공백/유니코드/인코딩 변형에서 탐지가 빠지는가?
- 룰이 너무 좁거나 너무 넓은가?
- 입력 canonicalization을 어디에서 통일해야 하는가?
- 보완 전후 탐지율이 올라갔는가?

## Defensive workflow

1. 자체 룰 파일을 준비한다.
2. 테스트할 문자열/입력 샘플을 넣는다.
3. Bypass Resilience Lab이 안전한 변형 후보를 만든다.
4. 각 변형이 룰에 hit/miss 되는지 기록한다.
5. miss된 변형을 기준으로 canonicalization, allowlist, parser validation을 보완한다.
6. 다시 실행하여 miss count를 줄인다.
