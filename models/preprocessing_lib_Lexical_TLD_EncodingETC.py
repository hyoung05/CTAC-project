# 협업 하기 좋은 형태로 바꿈 !

# preprocessing_lib.py
# 전처리 담당 산출물 (라이브러리): 정제/필터링/host 추출/중복·충돌 제거/수치 특징/TF-IDF 입력 표준화
# 모델 학습/평가 로직 포함하지 않음

import re
import numpy as np
import pandas as pd
from urllib.parse import urlsplit

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", "payment",
    "confirm", "signin", "password", "webscr", "cmd", "admin"
]

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PCT_ENC_RE = re.compile(r"%(?:[0-9A-Fa-f]{2})")
REPEAT_SPECIAL_RE = re.compile(r"([\-_%/@\.\?&=#])\1{2,}")

SUSPICIOUS_TLDS = {
    "xyz", "top", "gq", "tk", "ml", "cf", "ga", "work", "click", "support", "info"
}


def ensure_scheme(u: str) -> str:
    # 스킴(http/https 등) 없으면 파서가 hostname을 못 잡는 경우가 있어 http:// 부착
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", u):
        return u
    return "http://" + u


def extract_host(u: str) -> str:
    # URL에서 host 추출(소문자), 실패 시 빈 문자열
    try:
        parts = urlsplit(u)
        host = parts.hostname
        return "" if host is None else host.lower()
    except Exception:
        return ""


def tld_from_host(host: str) -> str:
    # host 최상위 도메인(TLD) 추출
    h = (host or "").lower().strip(".")
    if not h:
        return ""
    return h.split(".")[-1] if "." in h else h


def count_query_params(query: str) -> int:
    # 쿼리 파라미터 개수(a=1&b=2 -> 2) 추정
    q = (query or "").strip()
    if not q:
        return 0
    parts = [p for p in q.split("&") if p]
    return sum(1 for p in parts if "=" in p)


def max_repeated_special_run(u: str) -> int:
    # 동일 특수문자 연속 반복 최대 길이(예: ///// -> 5)
    if not REPEAT_SPECIAL_RE.search(u):
        return 0
    max_len = 0
    i = 0
    special = set("-_%/@.?&=#")
    while i < len(u):
        ch = u[i]
        if ch in special:
            j = i
            while j < len(u) and u[j] == ch:
                j += 1
            max_len = max(max_len, j - i)
            i = j
        else:
            i += 1
    return max_len


def load_and_filter_csv(csv_path: str) -> pd.DataFrame:
    # CSV 로드 + (url,type)만 사용 + benign/phishing만 필터링 + 라벨 생성
    df = pd.read_csv(csv_path)[["url", "type"]].copy()

    df = df.dropna(subset=["url", "type"])
    df["url"] = df["url"].astype(str).str.strip()
    df["type"] = df["type"].astype(str).str.strip().str.lower()

    df = df[(df["url"].str.len() > 0) & (df["type"].isin(["benign", "phishing"]))].copy()
    df["y"] = (df["type"] == "phishing").astype(int)

    return df.reset_index(drop=True)


def add_parsed_columns(df: pd.DataFrame) -> pd.DataFrame:
    # 파싱용 URL 보정 + host 추출
    out = df.copy()
    out["url_for_parse"] = out["url"].map(ensure_scheme)
    out["host"] = out["url_for_parse"].map(extract_host)
    out = out[out["host"].str.len() > 0].copy()
    return out.reset_index(drop=True)


def remove_conflicts_and_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    # 라벨 충돌 URL 제거 + 중복 제거(보수적)
    out = df.copy()

    dup_label_counts = out.groupby("url")["y"].nunique()
    conflict_urls = dup_label_counts[dup_label_counts > 1].index
    if len(conflict_urls) > 0:
        out = out[~out["url"].isin(conflict_urls)].copy()

    out = out.drop_duplicates(subset=["url", "y", "host"]).reset_index(drop=True)
    return out


def build_numeric_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    # 수치 특징 생성(현재 23개)
    def numeric_features(raw_url: str) -> dict:
        u = str(raw_url).strip()
        up = urlsplit(ensure_scheme(u))
        host = (up.hostname or "").lower()
        path = up.path or ""
        query = up.query or ""

        feat = {}

        feat["len_url"] = len(u)
        feat["len_host"] = len(host)
        feat["len_path"] = len(path)
        feat["len_query"] = len(query)

        feat["cnt_dot"] = u.count(".")
        feat["cnt_hyphen"] = u.count("-")
        feat["cnt_underscore"] = u.count("_")
        feat["cnt_at"] = u.count("@")
        feat["cnt_percent"] = u.count("%")
        feat["cnt_slash"] = u.count("/")
        feat["cnt_qmark"] = u.count("?")
        feat["cnt_amp"] = u.count("&")
        feat["cnt_equal"] = u.count("=")
        feat["cnt_hash"] = u.count("#")

        feat["subdomain_cnt"] = host.count(".") if host else 0

        digits = sum(c.isdigit() for c in u)
        feat["cnt_digit"] = digits
        feat["ratio_digit"] = digits / max(1, len(u))

        low = u.lower()
        feat["has_suspicious_kw"] = int(any(k in low for k in SUSPICIOUS_KEYWORDS))
        feat["host_looks_like_ip"] = int(bool(IPV4_RE.fullmatch(host))) if host else 0

        feat["cnt_pct_enc"] = len(PCT_ENC_RE.findall(u))
        feat["max_repeat_special_run"] = max_repeated_special_run(u)
        feat["query_param_cnt"] = count_query_params(query)

        tld = tld_from_host(host)
        feat["is_suspicious_tld"] = int(tld in SUSPICIOUS_TLDS) if tld else 0

        return feat

    return df["url"].map(numeric_features).apply(pd.Series)


def prepare_X_y_groups_from_csv(csv_path: str):
    """
    end-to-end 전처리 엔트리

    반환:
    - df_ready: DataFrame (url, type, y, host)
    - y       : np.ndarray
    - groups  : np.ndarray (host)
    - X       : DataFrame (수치 특징)
    """
    df = load_and_filter_csv(csv_path)
    df = add_parsed_columns(df)
    df_ready = remove_conflicts_and_duplicates(df)

    X = build_numeric_feature_frame(df_ready)
    y = df_ready["y"].to_numpy(dtype=int)
    groups = df_ready["host"].to_numpy(dtype=str)

    return df_ready, y, groups, X
