# preprocessing_lib_TFIDF.py
# 전처리 담당 산출물(라이브러리)
# 목적: CSV 로드/정제/host 추출/충돌·중복 제거 + TF-IDF(문자 n-gram) 벡터 생성
# smoke_test_logistic_cv.py 와 "기본 TF-IDF 설정"을 최대한 동일하게 맞춤:
# - analyzer="char"
# - ngram_range=(3, 5)
# - min_df=2
# - max_features=200000
# 모델 학습/평가 로직은 포함하지 않음

import re
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer


# -----------------------------
# URL parsing helpers
# -----------------------------
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")


def ensure_scheme(u: str) -> str:
    u = str(u).strip()
    return u if _SCHEME_RE.match(u) else "http://" + u


def extract_host(u: str) -> str:
    try:
        return (urlsplit(u).hostname or "").lower()
    except Exception:
        return ""


def resolve_csv_path(csv_path: str) -> str:
    """
    상대경로는 preprocessing_lib_TFIDF.py 위치 기준으로 해석.
    (VS Code/노트북에서 작업 디렉터리가 달라도 동작하도록)
    """
    p = Path(csv_path)
    if p.is_absolute():
        return str(p)
    base_dir = Path(__file__).resolve().parent
    return str((base_dir / p).resolve())


# -----------------------------
# Data loading / cleaning
# -----------------------------
def load_and_filter_csv(csv_path: str) -> pd.DataFrame:
    csv_path = resolve_csv_path(csv_path)

    # url/type만 사용
    df = pd.read_csv(csv_path, usecols=["url", "type"]).copy()

    df = df.dropna(subset=["url", "type"])
    df["url"] = df["url"].astype(str).str.strip()
    df["type"] = df["type"].astype(str).str.strip().str.lower()

    df = df[(df["url"].str.len() > 0) & (df["type"].isin(["benign", "phishing"]))].copy()
    df["y"] = (df["type"] == "phishing").astype(int)

    return df.reset_index(drop=True)


def add_parsed_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["url_for_parse"] = out["url"].map(ensure_scheme)
    out["host"] = out["url_for_parse"].map(extract_host)
    out = out[out["host"].str.len() > 0].copy()
    return out.reset_index(drop=True)


def remove_conflicts_and_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    # 동일 url에 라벨이 섞여 있으면 제거
    conflict = out.groupby("url")["y"].nunique()
    conflict_urls = conflict[conflict > 1].index
    if len(conflict_urls) > 0:
        out = out[~out["url"].isin(conflict_urls)].copy()

    # (url, y, host) 기준 중복 제거
    out = out.drop_duplicates(subset=["url", "y", "host"]).reset_index(drop=True)
    return out


# -----------------------------
# TF-IDF (smoke_test와 동일 기본값)
# -----------------------------
def build_tfidf_vectorizer(
    analyzer: str = "char",
    ngram_range: tuple[int, int] = (3, 5),
    min_df: int = 2,
    max_features: int = 200_000,
) -> TfidfVectorizer:
    return TfidfVectorizer(
        analyzer=analyzer,
        ngram_range=ngram_range,
        min_df=min_df,
        max_features=max_features,
    )


def build_tfidf_matrix(
    df: pd.DataFrame,
    analyzer: str = "char",
    ngram_range: tuple[int, int] = (3, 5),
    min_df: int = 2,
    max_features: int = 200_000,
):
    """
    Returns
    -------
    X_txt : scipy.sparse matrix
    vec   : fitted TfidfVectorizer
    """
    text = df["url"].astype(str).str.strip().values
    vec = build_tfidf_vectorizer(
        analyzer=analyzer,
        ngram_range=ngram_range,
        min_df=min_df,
        max_features=max_features,
    )
    X_txt = vec.fit_transform(text)
    return X_txt, vec


# =========================================================
# 학습 코드가 기대하는 엔트리 함수
# - 사용 형태 유지:
#     df_ready, y, groups, x = prepare_X_y_groups_from_csv(csv_path)
# - TF-IDF만 반환: x는 sparse TF-IDF 행렬
# - smoke_test 기본값과 동일하게 맞춤(3~5, 200k)
# =========================================================
def prepare_X_y_groups_from_csv(
    csv_path: str,
    analyzer: str = "char",
    ngram_range: tuple[int, int] = (3, 5),
    min_df: int = 2,
    max_features: int = 200_000,
):
    """
    Returns
    -------
    df_ready : pd.DataFrame (정제/필터링/중복 제거 완료)
    y        : np.ndarray (0/1)
    groups   : np.ndarray (host string)  # GroupShuffleSplit / GroupKFold용
    x        : scipy.sparse matrix       # TF-IDF features
    """
    df = load_and_filter_csv(csv_path)
    df = add_parsed_columns(df)
    df = remove_conflicts_and_duplicates(df)

    x, _vec = build_tfidf_matrix(
        df,
        analyzer=analyzer,
        ngram_range=ngram_range,
        min_df=min_df,
        max_features=max_features,
    )

    y = df["y"].astype(int).to_numpy()
    groups = df["host"].astype(str).to_numpy()

    df_ready = df
    return df_ready, y, groups, x
