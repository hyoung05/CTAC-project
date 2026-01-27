# Models
피싱 URL 탐지를 위한 머신러닝 학습 및 최종 산출물

## 구성 파일

- **CTAC_run_experiment_final.ipynb**
  - 실험을 수행한 실행 노트북
  - 임계값 탐색 및 모델 성능 비교 실험 수행

- **CTAC_train_model_final.py**
  - 4가지 분류 모델을 학습하는 메인 학습 모듈
  - GroupKFold 기반 검증 및 threshold 선택 로직 포함
 
- **CTAC_train_model2_TFIDF_Logistic.py**
  - TF-IDF로 전처리된 데이터를 기반으로
    Logistic Regression 모델을 학습하는 모듈
  - 희소 행렬(sparse matrix) 특성으로 인해
    표준화(StandardScaler) 과정은 제외함

- **phishing_LightGBM.pkl**
  - 가장 우수한 성능을 보인 LightGBM 기반 최종 학습 모델
  - 생성형 AI 함수 호출에서 사용 예정
