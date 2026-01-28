from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, average_precision_score
from sklearn.model_selection import GroupKFold
import numpy as np
import pickle


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


def _make_url_to_len_feature(X):
    # preprocessing_lib_basic.py (host-only)에서 X는 df_ready[["url"]] 형태 (문자열 1컬럼)
    # LogisticRegression이 학습 가능하도록 "길이 1개 수치 피처"로 변환
    if hasattr(X, "iloc"):
        if "url" not in X.columns:
            raise ValueError("X에는 'url' 컬럼이 있어야 합니다.")
        u = X["url"].astype(str)
        return u.str.len().to_numpy(dtype=float).reshape(-1, 1)

    arr = np.asarray(X, dtype=object)
    if arr.ndim == 2 and arr.shape[1] == 1:
        u = arr[:, 0].astype(str)
    else:
        u = arr.astype(str)
    return np.vectorize(len)(u).astype(float).reshape(-1, 1)


def run_training_groupkfold(
    x,
    y,
    groups,
    model_path="phishing_model_basic.pkl",
    n_splits=5,
    random_state=42,
    target_precision=0.70,
    min_recall_floor=0.20,
):
    results = []

    # -------------------------
    # 모델 정의 (preprocessing_lib_basic.py host-only 버전에 맞춤)
    # - url 문자열 -> 길이 1개 수치피처로 변환 후
    # - "직접 구현한 logistic(proba)"로 학습/추론
    # -------------------------

    def _fit_logistic_gd(X_num, y_num, lr=0.1, n_iter=2000, l2=1e-4):
        n, d = X_num.shape
        w = np.zeros(d, dtype=float)
        b = 0.0

        for _ in range(n_iter):
            z = X_num @ w + b
            p = 1.0 / (1.0 + np.exp(-z))
            grad_w = (X_num.T @ (p - y_num)) / n + l2 * w
            grad_b = float(np.mean(p - y_num))
            w -= lr * grad_w
            b -= lr * grad_b

        return w, b

    def _predict_proba_logistic(X_num, w, b):
        z = X_num @ w + b
        return 1.0 / (1.0 + np.exp(-z))

    gkf = GroupKFold(n_splits=n_splits)

    fold_ap, fold_acc, fold_prec, fold_rec, fold_f1, fold_thr = [], [], [], [], [], []
    fold_y_test, fold_y_pred = [], []

    for fold, (tr_idx, te_idx) in enumerate(gkf.split(x, y, groups=groups), start=1):
        X_train_raw, X_test_raw = take_rows(x, tr_idx), take_rows(x, te_idx)
        y_train, y_test = take_rows(y, tr_idx), take_rows(y, te_idx)

        X_train = _make_url_to_len_feature(X_train_raw)
        X_test = _make_url_to_len_feature(X_test_raw)

        w, b = _fit_logistic_gd(X_train, np.asarray(y_train, dtype=float))

        prob = _predict_proba_logistic(X_test, w, b)

        thr, p, r, f1v = choose_threshold_by_precision(
            prob, y_test,
            target_precision=target_precision,
            min_recall_floor=min_recall_floor
        )

        y_pred = (prob >= thr).astype(int)

        fold_thr.append(thr)
        fold_ap.append(average_precision_score(y_test, prob))
        fold_acc.append(accuracy_score(y_test, y_pred))
        fold_prec.append(precision_score(y_test, y_pred, zero_division=0))
        fold_rec.append(recall_score(y_test, y_pred, zero_division=0))
        fold_f1.append(f1_score(y_test, y_pred, zero_division=0))

        fold_y_test.append(y_test)
        fold_y_pred.append(y_pred)

        print(
            f"[LogisticRegression(Basic) | 폴드 {fold}] "
            f"선택 임계값={thr:.3f}  "
            f"AP={fold_ap[-1]:.4f}  "
            f"Acc={fold_acc[-1]:.4f}  "
            f"P={fold_prec[-1]:.4f}  "
            f"R={fold_rec[-1]:.4f}  "
            f"F1={fold_f1[-1]:.4f}"
        )

    summary = {
        "threshold_mean": float(np.mean(fold_thr)),
        "threshold_std": float(np.std(fold_thr)),
        "avg_precision_mean": float(np.mean(fold_ap)),
        "avg_precision_std": float(np.std(fold_ap)),
        "accuracy_mean": float(np.mean(fold_acc)),
        "accuracy_std": float(np.std(fold_acc)),
        "precision_mean": float(np.mean(fold_prec)),
        "precision_std": float(np.std(fold_prec)),
        "recall_mean": float(np.mean(fold_rec)),
        "recall_std": float(np.std(fold_rec)),
        "f1_mean": float(np.mean(fold_f1)),
        "f1_std": float(np.std(fold_f1)),
    }

    print(f"\n[LogisticRegression(Basic)] GroupKFold 결과 요약")
    print(f"thr: {summary['threshold_mean']:.3f} ± {summary['threshold_std']:.3f}")
    print(f"AP : {summary['avg_precision_mean']:.4f} ± {summary['avg_precision_std']:.4f}")
    print(f"Acc: {summary['accuracy_mean']:.4f} ± {summary['accuracy_std']:.4f}")
    print(f"P  : {summary['precision_mean']:.4f} ± {summary['precision_std']:.4f}")
    print(f"R  : {summary['recall_mean']:.4f} ± {summary['recall_std']:.4f}")
    print(f"F1 : {summary['f1_mean']:.4f} ± {summary['f1_std']:.4f}\n")

    results.append({
        "model": "LogisticRegression(Basic)",
        **summary,
        "y_test": fold_y_test,
        "y_pred": fold_y_pred,
    })

    # 최종 모델: 전체 데이터 재학습 + CV 평균 threshold 저장
    X_all = _make_url_to_len_feature(x)
    w_all, b_all = _fit_logistic_gd(X_all, np.asarray(y, dtype=float))

    bundle = {
        "model": {"w": w_all, "b": b_all},
        "threshold": float(summary["threshold_mean"]),
        "meta": {
            "model_name": "LogisticRegression(Basic)",
            "n_splits": n_splits,
            "target_precision": float(target_precision),
            "min_recall_floor": float(min_recall_floor),
            "random_state": random_state,
            "cv_summary": summary,
            "note": "X는 url만 포함하며, 내부적으로 url 길이(url_len) 1개 특징을 사용합니다.",
        },
    }

    with open(model_path, "wb") as f:
        pickle.dump(bundle, f)

    print(f"모델 저장 완료 (LogisticRegression(Basic), GroupKFold, threshold 포함) : LogisticRegression(Basic) → {model_path}")

    return results
