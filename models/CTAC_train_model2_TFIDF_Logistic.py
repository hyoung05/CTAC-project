# 핵심 포인트:
# GroupKFold(n_splits=5)
# LogisticRegression(solver="liblinear", max_iter=3000)
# TF-IDF는 전처리에서 이미 생성된 x(sparse) 사용
# predict_proba 기반 threshold 튜닝(정밀도 목표 + 재현율 하한)으로 fold별 지표 계산
# Accuracy 추가(holdout 코드와 비교 편의)
# fold별 y_test / y_pred 저장(필요 시 오분류 분석/혼동행렬/사례 추출)
# 최종 저장 모델은 "전체 데이터로 fit" (운영용) + 모델과 임계값(threshold) 같이 저장
# Precision 임계값 0.7 로 잡고 recall 극대화하고 있음 
# Precision = threshold 위에 있는 것들 중, 진짜 피싱은 몇 % 인지
# 단, Average Precision (평균 정밀도) : "threshold 에 구애받지 않고", 모델이 부여한 피싱 확률 점수로 URL들을 정렬했을 때, 실제 피싱 URL이 상위 구간에 얼마나 잘 집중되어 있는지를 평가해서 모델의 성능을 보여줌

import numpy as np
import pickle

from sklearn.model_selection import GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)


def choose_threshold_by_precision(prob, y_true, target_precision, min_recall_floor):
    thresholds = np.linspace(0.0, 1.0, 2001)       # 모델이 출력하는 “피싱일 확률 점수(probability)”에 대한 임계값 , 0.0부터 1.0까지 "임계값 후보"를 2001개로 균등 생성

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
    return a[idx]


def run_training(
    x,
    y,
    groups,
    model_path="phishing_logreg_tfidf.pkl",
    n_splits=5,
    target_precision=0.70,                    # 가능한 한 precision >= 0.70을 만족하도록 threshold를 찾게하였고, 이 때 recall 을 최대화 하는 방향으로 !
    min_recall_floor=0.20,
    random_state=123,
):
    gkf = GroupKFold(n_splits=n_splits)

    fold_avg_prec = []
    fold_acc = []
    fold_prec = []
    fold_rec = []
    fold_f1 = []
    fold_thr = []

    # fold별 원본 라벨/예측 저장(필요 시 오분류 분석)
    fold_y_test = []
    fold_y_pred = []

    for fold, (tr_idx, te_idx) in enumerate(gkf.split(x, y, groups=groups), start=1):
        Xtr = take_rows(x, tr_idx)
        Xte = take_rows(x, te_idx)
        ytr = take_rows(y, tr_idx)
        yte = take_rows(y, te_idx)

        clf = LogisticRegression(
            max_iter=3000,
            solver="liblinear",
            random_state=random_state,
        )

        clf.fit(Xtr, ytr)
        prob = clf.predict_proba(Xte)[:, 1]               # “피싱일 확률 점수(probability)” = 각 URL마다 “이게 피싱일 확률” 같은 숫자 '점수'를 붙여줌 -> Average Precision (평균정밀도) = 실제 피싱 URL들이, 이 정렬(점수를 상위부터 정렬함)에서 위쪽에 몰려 있나? 몰려 있으면 높은 값.

        thr, p, r, f1v = choose_threshold_by_precision(
            prob, yte,
            target_precision=target_precision,
            min_recall_floor=min_recall_floor
        )

        pred = (prob >= thr).astype(int)                     # '점수'로 줄세운 것 중 threshold 위쪽에 있는 것만 피싱으로 보려고함.

        fold_thr.append(thr)
        fold_avg_prec.append(average_precision_score(yte, prob))
        fold_acc.append(accuracy_score(yte, pred))
        fold_prec.append(precision_score(yte, pred, zero_division=0))
        fold_rec.append(recall_score(yte, pred, zero_division=0))
        fold_f1.append(f1_score(yte, pred, zero_division=0))

        # y_test / y_pred 저장
        fold_y_test.append(yte)
        fold_y_pred.append(pred)

        print(
            f"[교차검증 폴드 {fold}] "
            f"선택 임계값={thr:.3f}  "
            f"평균정밀도(Average Precision)={fold_avg_prec[-1]:.4f}  "                        # Average Precision (평균 정밀도) : 모델이 부여한 피싱 확률 점수로 URL들을 정렬했을 때, 실제 피싱 URL이 상위 구간에 얼마나 잘 집중되어 있는지를 평가한다.
            f"정확도(Accuracy)={fold_acc[-1]:.4f}  "
            f"정밀도(Precision)={fold_prec[-1]:.4f}  "
            f"재현율(Recall)={fold_rec[-1]:.4f}  "
            f"F1-점수(F1-score)={fold_f1[-1]:.4f}"
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

    print("\n[host 기반 GroupKFold 결과 요약]")
    print(f"선택 임계값(평균±표준편차): {summary['threshold_mean']:.3f} ± {summary['threshold_std']:.3f}")
    print(f"평균정밀도(Average Precision): {summary['avg_precision_mean']:.4f} ± {summary['avg_precision_std']:.4f}")
    print(f"정확도(Accuracy)        : {summary['accuracy_mean']:.4f} ± {summary['accuracy_std']:.4f}")
    print(f"정밀도(Precision)       : {summary['precision_mean']:.4f} ± {summary['precision_std']:.4f}")
    print(f"재현율(Recall)          : {summary['recall_mean']:.4f} ± {summary['recall_std']:.4f}")
    print(f"F1-점수(F1-score)       : {summary['f1_mean']:.4f} ± {summary['f1_std']:.4f}")

    final_thr = summary["threshold_mean"]

    final_model = LogisticRegression(
        max_iter=3000,
        solver="liblinear",
        random_state=random_state,
    )
    final_model.fit(x, y)

    bundle = {
        "model": final_model,
        "threshold": final_thr,
        "meta": {
            "n_splits": n_splits,
            "target_precision": target_precision,
            "min_recall_floor": min_recall_floor,
            "random_state": random_state,
            "cv_summary": summary,
        },
    }

    with open(model_path, "wb") as f:
        pickle.dump(bundle, f)

    print(f"\n모델 저장 완료: LogisticRegression(TF-IDF) + threshold → {model_path}")

    results = {
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
    return results
