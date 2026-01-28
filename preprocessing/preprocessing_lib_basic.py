import re
import numpy as np
import pandas as pd
from urllib.parse import urlsplit

# =========================================================
# preprocessing_lib_basic.py  (CLEAN-ONLY VERSION)
# 목적
# - URL 피싱 데이터셋에서 (url, type)만 사용
# - benign/phishing만 필터링
# - 이진 라벨 y 생성 (phishing=1, benign=0)
# - URL 파싱을 통해 host 생성 (그룹 기준으로 사용 가능)
# - 라벨 충돌(동일 url에 서로 다른 y) 제거 + 중복 제거
# - (선택) 협업용 전처리 산출물 CSV 저장 가능
# =========================================================


# -------------------------
# 상수/정규식
# -------------------------
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")


# -------------------------
# URL 파싱 유틸
# -------------------------
def ensure_scheme(u: str) -> str:
    s = str(u).strip()
    return s if SCHEME_RE.match(s) else ("http://" + s)


def extract_host(u: str) -> str:
    try:
        host = urlsplit(u).hostname
        return "" if host is None else host.lower()
    except Exception:
        return ""


# -------------------------
# 데이터 로드/필터링/라벨 생성/저장
# -------------------------
def load_and_filter_csv(
    csv_path: str,
    save_filtered_csv: bool = True,
    filtered_csv_path: str = "malicious_phish_benign_phishing.csv",
) -> pd.DataFrame:
    df = pd.read_csv(csv_path)[["url", "type"]].copy()

    df = df.dropna(subset=["url", "type"])
    df["url"] = df["url"].astype(str).str.strip()
    df["type"] = df["type"].astype(str).str.strip().str.lower()

    df = df[(df["url"].str.len() > 0) & (df["type"].isin(["benign", "phishing"]))].copy()
    df["y"] = (df["type"] == "phishing").astype(int)

    if save_filtered_csv:
        df[["url", "type", "y"]].to_csv(filtered_csv_path, index=False, encoding="utf-8")

    return df.reset_index(drop=True)


def add_host_and_deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    out["url_for_parse"] = out["url"].map(ensure_scheme)
    out["host"] = out["url_for_parse"].map(extract_host)
    out = out[out["host"].str.len() > 0].copy()

    dup_label_counts = out.groupby("url")["y"].nunique()
    conflict_urls = dup_label_counts[dup_label_counts > 1].index
    if len(conflict_urls) > 0:
        out = out[~out["url"].isin(conflict_urls)].copy()

    out = out.drop_duplicates(subset=["url", "y", "host"]).reset_index(drop=True)

    out = out[["url", "type", "y", "host"]].copy()
    return out


def save_df_ready_csv(df_ready: pd.DataFrame, ready_csv_path: str) -> None:
    df_ready[["url", "type", "y", "host"]].to_csv(ready_csv_path, index=False, encoding="utf-8")


# -------------------------
# 전처리 엔트리: (1)동일 host train/test 중복 방지용 groups만 제공
# - URL 특징 계량화(X feature engineering) 제거
# - X는 "원본 url 문자열 1개 컬럼"만 반환 (host 그룹 분할만 하려는 목적)
# -------------------------
def prepare_X_y_groups_from_csv(
    csv_path: str,
    save_filtered_csv: bool = True,
    filtered_csv_path: str = "malicious_phish_benign_phishing.csv",
    save_ready_csv: bool = False,
    ready_csv_path: str = "malicious_phish_benign_phishing_with_host.csv",
):
    df = load_and_filter_csv(
        csv_path=csv_path,
        save_filtered_csv=save_filtered_csv,
        filtered_csv_path=filtered_csv_path,
    )

    df_ready = add_host_and_deduplicate(df)

    if save_ready_csv:
        save_df_ready_csv(df_ready, ready_csv_path=ready_csv_path)

    # (2) URL 특징 계량화 제거: X는 원본 url만 유지
    X = df_ready[["url"]].copy()

    y = df_ready["y"].to_numpy(dtype=int)
    groups = df_ready["host"].to_numpy(dtype=str)

    return X, y, groups
