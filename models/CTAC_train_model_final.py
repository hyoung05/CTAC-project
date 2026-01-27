import numpy as np
import pickle
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sklearn.model_selection import GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

# ---------------------------
# threshold selection
# ---------------------------
def choose_threshold_by_precision(prob, y_true, target_precision, min_recall_floor):
    """
    Precision 제약 조건 하에서 Recall을 최대화하는 threshold를 선택하는 함수.

    목적:
    - 피싱 탐지 환경에서 False Negative를 최소화하기 위해
      Precision 하한을 만족하는 threshold 중 Recall이 최대가 되는 값을 선택

    동작 방식:
    1. [0, 1] 구간의 threshold 후보들을 순회
    2. Precision ≥ target_precision AND Recall ≥ min_recall_floor 조건을 만족하는 후보 필터링
    3. 해당 후보 중 Recall이 가장 큰 threshold 선택
    4. 조건을 만족하는 threshold가 없을 경우,
       Precision이 최대가 되는 threshold를 fallback으로 선택
    """

    thresholds = np.linspace(0.0, 1.0, 2001)

    found = False
    best_thr = 1.0
    best_prec = -1.0
    best_rec = 0.0
    best_f1 = 0.0
    best_rec_under_constraint = -1.0

    for thr in thresholds:
        pred = (prob >= thr).astype(int)
        prec = precision_score(y_true, pred, zero_division=0)
        rec = recall_score(y_true, pred, zero_division=0)
        f1v = f1_score(y_true, pred, zero_division=0)

        if prec >= target_precision and rec >= min_recall_floor:
            found = True
            if rec > best_rec_under_constraint:
                best_rec_under_constraint = rec
                best_thr = thr
                best_prec = prec
                best_rec = rec
                best_f1 = f1v

    if not found:
        best_thr = 1.0
        best_prec = -1.0
        best_rec = 0.0
        best_f1 = 0.0

        for thr in thresholds:
            pred = (prob >= thr).astype(int)
            prec = precision_score(y_true, pred, zero_division=0)
            rec = recall_score(y_true, pred, zero_division=0)
            f1v = f1_score(y_true, pred, zero_division=0)

            if prec > best_prec:
                best_prec = prec
                best_rec = rec
                best_f1 = f1v
                best_thr = thr

    return float(best_thr), float(best_prec), float(best_rec), float(best_f1)


def take_rows(a, idx):
    # pandas DataFrame/Series: 행 인덱싱은 iloc
    if hasattr(a, "iloc"):
        return a.iloc[idx]
    # scipy sparse matrix: 행 슬라이싱 지원
    return a[idx]


def _get_proba(model, X):
    """
    모델로부터 positive class 확률을 추출하는 함수.

    동작 규칙:
    - predict_proba를 지원하는 모델: 그대로 사용
    - decision_function만 제공하는 모델: sigmoid 함수로 확률 근사
    - 둘 다 없으면 오류 발생

    목적:
    - 서로 다른 분류 모델(Logistic, Tree, SVM 계열 등)을
      동일한 확률 기반 threshold 전략으로 처리하기 위함
    """
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    if hasattr(model, "decision_function"):
        z = model.decision_function(X)
        return 1.0 / (1.0 + np.exp(-z))
    raise ValueError(f"{type(model).__name__} does not support probability/score output.")

def _make_lgbm(random_state, y):
    # 클래스 불균형을 고려한 LightGBM 모델을 생성하는 함수
    from lightgbm import LGBMClassifier
    pos = int((y == 1).sum())
    neg = int((y == 0).sum())
    spw = neg / max(pos, 1)

    return LGBMClassifier(
        n_estimators=800,
        learning_rate=0.05,
        num_leaves=31,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=random_state,
        n_jobs=-1,
        scale_pos_weight=spw,  # 불균형 대응
    ), spw

def _build_models(random_state=123):
    """
    비교 실험에 사용할 여러 분류 모델을 생성하는 함수.

    포함 모델:
    - Logistic Regression (StandardScaler 포함)
    - Decision Tree
    - Random Forest

    공통 특징:
    - class_weight='balanced' 설정
    - 동일한 random_state 사용
    """
    models = {}

    models["LogisticRegression"] = Pipeline([
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(
            max_iter=3000,
            solver="liblinear",
            class_weight="balanced",
            random_state=random_state,
        ))
    ])

    models["DecisionTree"] = DecisionTreeClassifier(
        max_depth=10,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=random_state,
        class_weight="balanced",
    )

    models["RandomForest"] = RandomForestClassifier(
        n_estimators=300,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced",
        min_samples_leaf=2,
    )


    return models


def run_training_multi_models(
    x,
    y,
    groups,
    model_dir=".",
    n_splits=5,
    target_precision=0.70,
    min_recall_floor=0.20,
    random_state=123,
    save_models=True,
):
    """
    GroupKFold 기반으로 여러 분류 모델을 학습·평가하고,
    Precision 제약 조건 하에서 최적 threshold를 선택하는 메인 학습 함수.

    전체 흐름:
    1. GroupKFold를 이용한 URL 그룹 기반 데이터 분할
    2. 각 fold별 모델 학습
    3. validation 데이터에서 threshold 후보 탐색
       - Precision ≥ target_precision 조건
       - Recall 최대화
    4. fold별 성능 지표 및 threshold 기록
    5. fold 평균 threshold를 사용하여
       전체 데이터로 최종 모델 재학습
    6. 모델 + threshold를 하나의 bundle로 저장
    """
        
    gkf = GroupKFold(n_splits=n_splits)
    models = _build_models(random_state=random_state)

    
    # LightGBM 추가
    try:
        gbm, spw = _make_lgbm(random_state, y)
        models["LightGBM"] = gbm
    except Exception:
        spw = None

    all_results = {}

    for model_name, model in models.items():
        fold_avg_prec, fold_acc, fold_prec, fold_rec, fold_f1, fold_thr = [], [], [], [], [], []
        fold_y_test, fold_y_pred = [], []

        for fold, (tr_idx, te_idx) in enumerate(gkf.split(x, y, groups=groups), start=1):
            Xtr = take_rows(x, tr_idx)
            Xte = take_rows(x, te_idx)
            ytr = take_rows(y, tr_idx)
            yte = take_rows(y, te_idx)

            clf = model 
            clf = pickle.loads(pickle.dumps(clf))

            clf.fit(Xtr, ytr)

            prob = _get_proba(clf, Xte)

            thr, p, r, f1v = choose_threshold_by_precision(
                prob, yte,
                target_precision=target_precision,
                min_recall_floor=min_recall_floor
            )

            pred = (prob >= thr).astype(int)

            fold_thr.append(thr)
            fold_avg_prec.append(average_precision_score(yte, prob))
            fold_acc.append(accuracy_score(yte, pred))
            fold_prec.append(precision_score(yte, pred, zero_division=0))
            fold_rec.append(recall_score(yte, pred, zero_division=0))
            fold_f1.append(f1_score(yte, pred, zero_division=0))

            fold_y_test.append(yte)
            fold_y_pred.append(pred)

            print(
                f"[{model_name} | 폴드 {fold}] "
                f"선택 임계값={thr:.3f}  "
                f"AP={fold_avg_prec[-1]:.4f}  "
                f"Acc={fold_acc[-1]:.4f}  "
                f"P={fold_prec[-1]:.4f}  "
                f"R={fold_rec[-1]:.4f}  "
                f"F1={fold_f1[-1]:.4f}"
            )

        summary = {
            "threshold_mean": float(np.mean(fold_thr)),
            "threshold_std": float(np.std(fold_thr)),
            "avg_precision_mean": float(np.mean(fold_avg_prec)),
            "avg_precision_std": float(np.std(fold_avg_prec)),
            "accuracy_mean": float(np.mean(fold_acc)),
            "accuracy_std": float(np.std(fold_acc)),
            "precision_mean": float(np.mean(fold_prec)),
            "precision_std": float(np.std(fold_prec)),
            "recall_mean": float(np.mean(fold_rec)),
            "recall_std": float(np.std(fold_rec)),
            "f1_mean": float(np.mean(fold_f1)),
            "f1_std": float(np.std(fold_f1)),
        }

        print(f"\n[{model_name}] GroupKFold 결과 요약")
        print(f"thr: {summary['threshold_mean']:.3f} ± {summary['threshold_std']:.3f}")
        print(f"AP : {summary['avg_precision_mean']:.4f} ± {summary['avg_precision_std']:.4f}")
        print(f"Acc: {summary['accuracy_mean']:.4f} ± {summary['accuracy_std']:.4f}")
        print(f"P  : {summary['precision_mean']:.4f} ± {summary['precision_std']:.4f}")
        print(f"R  : {summary['recall_mean']:.4f} ± {summary['recall_std']:.4f}")
        print(f"F1 : {summary['f1_mean']:.4f} ± {summary['f1_std']:.4f}\n")

        final_thr = summary["threshold_mean"]

        # 최종 모델 재학습
        final_model = pickle.loads(pickle.dumps(model))
        final_model.fit(x, y)

        bundle = {
            "model": final_model,
            "threshold": final_thr,
            "meta": {
                "model_name": model_name,
                "n_splits": n_splits,
                "target_precision": target_precision,
                "min_recall_floor": min_recall_floor,
                "random_state": random_state,
                "cv_summary": summary,
            },
        }

        if save_models:
            model_path = f"{model_dir}/phishing_{model_name}.pkl"
            with open(model_path, "wb") as f:
                pickle.dump(bundle, f)
            print(f"모델 저장 완료: {model_name} + threshold → {model_path}\n")

        all_results[model_name] = {
            "cv_summary": summary,
            "fold": {
                "threshold": fold_thr,
                "avg_precision": fold_avg_prec,
                "accuracy": fold_acc,
                "precision": fold_prec,
                "recall": fold_rec,
                "f1": fold_f1,
                "y_test": fold_y_test,
                "y_pred": fold_y_pred,
            },
        }

    return all_results