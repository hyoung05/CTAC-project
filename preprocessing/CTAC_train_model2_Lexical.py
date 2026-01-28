from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, average_precision_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from preprocessing_lib_Lexical_TLD_EncodingETC import prepare_X_y_groups_from_csv
from sklearn.model_selection import GroupShuffleSplit
import pickle
import numpy as np

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from lightgbm import LGBMClassifier


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
    return a.iloc[idx] if hasattr(a, "iloc") else a[idx]


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


def run_training(
    x,
    y,
    groups,
    model_path="phishing_model_lexical.pkl",           # 저장 명칭 변경
    target_precision=0.70,
    min_recall_floor=0.20,
):
    results = []
    trained_models = {}

    # group 기반 split
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(x, y, groups))

    X_train, X_test = take_rows(x, train_idx), take_rows(x, test_idx)
    y_train, y_test = take_rows(y, train_idx), take_rows(y, test_idx)
    groups_train, groups_test = take_rows(groups, train_idx), take_rows(groups, test_idx)

    # 불균형 대응용
    pos = (y_train == 1).sum()
    neg = (y_train == 0).sum()
    scale_pos_weight = (neg / pos) if pos > 0 else 1.0

    # 모델 정의
    models = {
        "LogisticRegression": Pipeline([
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(
            max_iter=2000,
            random_state=42,
            class_weight="balanced"
        ))
        ]),
        "DecisionTree": DecisionTreeClassifier(
            random_state=42, class_weight="balanced"
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=300, random_state=42,
            n_jobs=-1, class_weight="balanced"
        ),
        "LightGBM": LGBMClassifier(
            n_estimators=2000,
            learning_rate=0.03,
            num_leaves=63,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=-1,
            scale_pos_weight=scale_pos_weight,  # 불균형 대응
        )
    }

    for name, clf in models.items():
        clf.fit(X_train, y_train)

        prob = _get_proba(clf, X_test)

        thr, p, r, f1v = choose_threshold_by_precision(
            prob, y_test,
            target_precision=target_precision,
            min_recall_floor=min_recall_floor
        )

        y_pred = (prob >= thr).astype(int)

        trained_models[name] = clf  # 🔥 저장 후보

        results.append({
            "model": name,
            "threshold": thr,
            "avg_precision": average_precision_score(y_test, prob),
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall": recall_score(y_test, y_pred, zero_division=0),
            "f1": f1_score(y_test, y_pred, zero_division=0),
            "y_test": y_test,
            "y_pred": y_pred,
        })

    # best model 선택 (F1 기준)
    results = sorted(results, key=lambda d: d["f1"], reverse=True)
    best_name = results[0]["model"]
    best_model = trained_models[best_name]

    # 모델 저장
    bundle = {
        "model": best_model,
        "threshold": float(results[0]["threshold"]),
        "meta": {
            "model_name": best_name,
            "target_precision": float(target_precision),
            "min_recall_floor": float(min_recall_floor),
            "split": "GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)",
        },
    }

    with open(model_path, "wb") as f:
        pickle.dump(bundle, f)

    print(f"모델 저장 완료(lexical): {best_name} → {model_path}")              # 출력 명칭 변경

    return results
