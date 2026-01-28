# 🛡️ CTAC - 피싱 URL 탐지 AI 챗봇

> SK Shieldus Rookies 30기 3조 모듈 프로젝트

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
├── requirements.txt
├── preprocessing/              # 학습데이터 전처리
├── models/                     # ML 학습
├── database/                   # 정상/피싱 URL DB 전처리
├── websearch/                  # 웹서치 기능
├── ui/                         # Streamlit UI 프로토타입
└── app/                        # 실제 구동 (통합)
    ├── main.py                 # Streamlit 메인 실행
    ├── decision.py             # 결과 메시지 생성
    ├── utils.py                # 공통 유틸리티
    ├── agents/                 # 멀티 에이전트
    │   ├── main_agent.py       # 오케스트레이터
    │   ├── db_agents.py        # DB 에이전트
    │   ├── ml_agent.py         # ML 에이전트
    │   └── web_agent.py        # Web 에이전트
    └── data/                   # .gitignore 제외
        ├── benign_domains.db
        ├── phishing_domains.db
        └── phishing_LightGBM.pkl
```

## 시스템 아키텍처

```
           사용자 입력
               ↓
      ┌─────────────────┐
      │  Main Agent     │ ← OpenAI Function Calling
      │  (Orchestrator) │
      └────────┬────────┘
               │
    ┌──────────┼───────────┐
    ↓          ↓           ↓
┌────────┐ ┌────────┐ ┌─────────┐
│DB Agent│ │ML Agent│ │Web Agent│
└────────┘ └────────┘ └─────────┘
    ↓         ↓          ↓
 안전/위험   피싱 확률   공식 URL
 DB 매칭    예측       검색
```

**처리 흐름**

1. 사용자 URL 입력
2. 안전/위험 도메인 DB 검증 (Suffix 매칭)
3. DB 미확인 시 ML 모델 예측 (LightGBM)
4. 피싱 판정 시 웹 검색으로 공식 URL 추천
5. 종합 판단 및 대응 가이드 제공

## URL 특징 추출 (23개 피처)

| 구분        | 피처                                         |
| ----------- | -------------------------------------------- |
| 길이 기반   | URL, 호스트, 경로, 쿼리 길이                 |
| 문자 카운트 | `.` `-` `_` `@` `%` `/` `?` `&` `=` `#` 개수 |
| 구조 분석   | 서브도메인 수, 숫자 개수, 숫자 비율          |
| 키워드      | 의심 키워드(login, verify 등) 포함 여부      |
| 호스트 형태 | IP 주소 형태 여부                            |
| 인코딩      | 퍼센트 인코딩 횟수, 특수문자 반복 길이       |
| TLD         | 의심 TLD(tk, xyz 등) 여부                    |

## 모델 성능

| 모델               | Accuracy  | Precision | Recall    | F1        |
| ------------------ | --------- | --------- | --------- | --------- |
| LogisticRegression | 0.864     | 0.702     | 0.598     | 0.644     |
| LR (TF-IDF)        | 0.908     | 0.700     | 0.971     | 0.814     |
| Decision Tree      | 0.891     | 0.705     | 0.814     | 0.755     |
| RandomForest       | 0.900     | 0.701     | 0.901     | 0.788     |
| **LightGBM**       | **0.902** | **0.700** | **0.923** | **0.796** |

→ LR (TF-IDF)는 Recall이 가장 높지만 처리 속도가 느려 실사용에 부적합  
→ 성능과 속도를 고려하여 **LightGBM**을 최종 모델로 선정

## 설치

```bash
pip install -r requirements.txt
```

## 환경 설정

프로젝트 루트에 `.env` 파일 생성:

```dotenv
# OpenAI
OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL=gpt-5

# Local DBs
BENIGN_DB_PATH=./data/benign_domains.db
PHISHING_DB_PATH=./data/phishing_domains.db

# ML model
MODEL_PATH=./data/phishing_LightGBM.pkl
MODEL_THRESHOLD=0.8
```

## 실행

```bash
streamlit run app/main.py
```

## 사용 데이터

- [Kaggle Phishing URL Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset/data)
- [KISA 피싱 URL 데이터](https://www.data.go.kr/data/15109780/fileData.do)
- [Top 1M 도메인 리스트](https://tranco-list.eu/list/ZWJ8G/1000000)

## 기술 스택

- Python 3.12
- OpenAI API (Function Calling)
- Streamlit
- LightGBM, Scikit-learn
- SQLite
- python-dotenv

## 데이터 다운로드

학습된 모델과 DB 파일은 용량 문제로 GitHub에 포함되지 않습니다.

[Google Drive에서 다운로드](https://drive.google.com/drive/folders/13JETZMYN0LtMlEu9A9ySjfvTrDP8bRq4?usp=drive_link)

다운로드 후 `app` 폴더 내부에 `data` 폴더 생성 후 아래 파일을 배치하세요:

- `benign_domains.db`
- `phishing_domains.db`
- `phishing_LightGBM.pkl`
