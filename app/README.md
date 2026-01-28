# App

피싱 URL 탐지 시스템의 메인 애플리케이션

## 구성 파일

- **main.py**
  - Streamlit 기반 메인 실행 파일
  - 다크 모드 자동 감지 및 위험도별 색상 박스 표시
  - 사이드바에 DB/ML/Web 에이전트 호출 과정 실시간 로깅
  - 실행: `streamlit run main.py`

- **decision.py**
  - 분석 결과 메시지 생성 모듈
  - 피싱/안전 판정에 따른 응답 템플릿 및 안전 조치사항 제공

- **utils.py**
  - 공통 유틸리티 함수 모음
  - URL 추출, 도메인 파싱, OpenAI 클라이언트 초기화 등

- **.env**
  - 환경변수 설정 파일 (API 키, DB 경로, 모델 경로 등)

## agents 폴더

- **main_agent.py**
  - 메인 오케스트레이터
  - OpenAI Function Calling 기반 멀티 에이전트 흐름 제어
  - Phase A(DB/ML/유사탐색) → Phase B(웹검색) 순차 처리

- **db_agents.py**
  - DB 에이전트: 안전/위험 DB에서 도메인 조회
  - 유사 탐색 에이전트: Levenshtein 기반 공식 URL 후보 추천

- **ml_agent.py**
  - ML 에이전트: LightGBM 모델로 피싱 확률 예측
  - 23개 lexical feature 추출 및 임계값 기반 판정

- **web_agent.py**
  - Web 에이전트: OpenAI 웹검색으로 공식 URL 탐색
  - 로컬 유사 탐색 실패 시 보조 수단으로 사용

## data 폴더

- **benign_domains.db** - 안전 도메인 DB (Top 1M 기반)
- **phishing_domains.db** - 피싱 도메인 DB
- **phishing_LightGBM.pkl** - 학습된 LightGBM 모델

## 실행 방법

```bash
cd app
streamlit run main.py
```
