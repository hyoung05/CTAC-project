# 피싱 URL 탐지 AI 챗봇

사용자가 입력한 URL의 피싱 여부를 예측하고, 판단 근거 및 대응 가이드를 제공하는 AI 챗봇입니다.

## 주요 기능

- URL 특성 기반 피싱 탐지 (ML 모델)
- 신뢰 도메인 DB 검증
- 웹 검색을 통한 최신 피싱 정보 조회
- 피싱 대응 가이드 제공

## 프로젝트 구조

```
CTAC-project/
├── README.md
│
├── requirements.txt
│
├── ui/                         # Streamlit ui
│
├── preprocessing/              # 학습데이터 전처리
│
├── models/                     # ML 학습
│
├── database/                   # 정상/피싱 URL DB 전처리
│
├── websearch/                  # 웹서치 기능
│
└── app/                        # 실제 구동 (통합)
    ├── data/                   # db 모음(git에 올리기보다 구글 드라이브에)
    ├── agent/                  # 전체 agent 관리
```

### 커밋 순서(이항목 추후 삭제 예정)

1. Streamlit ui(ui작업하실때 생긴 프로토 탙입 코드 넣으시됩니다.)
2. 학습데이터 전처리
3. ML 학습
4. 정상/피싱 URL DB 전처리
5. 웹서치
6. 실제 구동 (통합)

## 설치

```bash
pip install -r requirements.txt
```

## 실행

```bash
streamlit run app/main.py
```

## 시스템 아키텍처

1. 사용자 URL 입력
2. ML 모델 예측 (RandomForest, 94.79% 정확도)
3. 신뢰 도메인 DB 검증
4. 웹 검색으로 추가 정보 조회
5. 종합 판단 및 대응 가이드 제공

## 모델 성능

- (추후 각 모델별 성능표 마크업으로 넣기)

## 사용 데이터

- [Kaggle Phishing URL Dataset](상세 주소 입력 필요)
- [KISA 피싱 URL 데이터](상세 주소 입력 필요)
- [Top 1M 도메인 리스트](상세 주소 입력 필요)

## 팀구성

- 추가 작성 필요

## 기술 스택

### 데이터 처리

- Python 3.12
- Pandas, NumPy
- urllib.parse (URL 파싱)

### 머신러닝

- Scikit-learn (RandomForest, LogisticRegression, DecisionTree)
- GroupKFold 교차검증
- Pickle (모델 저장/로드)

### AI 에이전트

- OpenAI API (Function Calling)
- 웹 검색 연동

### 데이터베이스

- SQLite (신뢰 도메인 DB)

### UI

- Streamlit

### 개발 환경

- python-dotenv (환경변수 관리)
