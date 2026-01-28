from __future__ import annotations

# ============================================================
# ML 에이전트: LightGBM + 23개 수동 피처
# - MODEL_PATH(.env)에서 pickle bundle 로드
# - bundle: {"model": <estimator>, "threshold": 0.8} 형태 권장
# - UserWarning(피처명) 제거: warnings 필터로 숨김
# ============================================================

import os
import pickle
import re
import warnings
from functools import lru_cache
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from pathlib import Path

from utils import resolve_existing_path

SUSPICIOUS_KEYWORDS = [
	"login", "signin", "verify", "secure", "account", "update",
	"confirm", "banking", "password", "credential", "suspend"
]

SUSPICIOUS_TLDS = [
	"tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "cc",
	"su", "buzz", "work", "link", "click", "loan", "win"
]

def _unwrap_model(obj):
	# dict로 한 번 더 감싸진 케이스 대비
	if isinstance(obj, dict):
		for k in ("model", "clf", "estimator", "pipeline", "booster"):
			if k in obj:
				obj = obj[k]
				break

	# sklearn Pipeline 마지막 step이 dict인 경우 대비
	if hasattr(obj, "steps"):
		name, last = obj.steps[-1]
		if isinstance(last, dict):
			for k in ("model", "clf", "estimator"):
				if k in last:
					obj.steps[-1] = (name, last[k])
					break
	return obj

@lru_cache(maxsize=1)
def _load_bundle() -> Dict[str, Any]:
	raw = os.getenv("MODEL_PATH", "./data/phishing_LightGBM.pkl")
	if not raw:
		raise RuntimeError("MODEL_PATH가 비어있습니다. (.env에 MODEL_PATH를 설정하세요)")

	base_dirs = [Path(__file__).resolve().parent, Path(__file__).resolve().parent.parent]
	path = resolve_existing_path(raw, base_dirs=base_dirs)

	with open(path, "rb") as f:
		bundle = pickle.load(f)

	if not isinstance(bundle, dict):
		raise TypeError(f"모델 파일이 dict(bundle) 형식이 아닙니다: {type(bundle)}")
	if "model" not in bundle:
		raise KeyError("모델 bundle에 'model' 키가 없습니다.")
	return bundle

def _extract_features(url: str) -> List[float]:
	if "://" not in url:
		url = "https://" + url

	parsed = urlparse(url)
	host = parsed.netloc or ""
	path = parsed.path or ""
	query = parsed.query or ""

	if host.startswith("www."):
		host = host[4:]

	tld = host.split(".")[-1].lower() if "." in host else ""
	parts = host.split(".") if host else []
	subdomain_cnt = max(0, len(parts) - 2)

	query_params = parse_qs(query)
	query_param_cnt = len(query_params)

	cnt_pct_enc = len(re.findall(r"%[0-9A-Fa-f]{2}", url))
	special_runs = re.findall(r"[.\-_@%/]{2,}", url)
	max_repeat = max((len(r) for r in special_runs), default=0)

	ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
	host_looks_like_ip = 1 if re.match(ip_pattern, host) else 0

	url_lower = url.lower()
	has_suspicious_kw = 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0
	is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

	digit_cnt = sum(c.isdigit() for c in url)
	ratio_digit = digit_cnt / max(len(url), 1)

	features = {
		"len_url": len(url),
		"len_host": len(host),
		"len_path": len(path),
		"len_query": len(query),
		"cnt_dot": url.count("."),
		"cnt_hyphen": url.count("-"),
		"cnt_underscore": url.count("_"),
		"cnt_at": url.count("@"),
		"cnt_percent": url.count("%"),
		"cnt_slash": url.count("/"),
		"cnt_qmark": url.count("?"),
		"cnt_amp": url.count("&"),
		"cnt_equal": url.count("="),
		"cnt_hash": url.count("#"),
		"subdomain_cnt": subdomain_cnt,
		"cnt_digit": digit_cnt,
		"ratio_digit": ratio_digit,
		"has_suspicious_kw": has_suspicious_kw,
		"host_looks_like_ip": host_looks_like_ip,
		"cnt_pct_enc": cnt_pct_enc,
		"max_repeat_special_run": max_repeat,
		"query_param_cnt": query_param_cnt,
		"is_suspicious_tld": is_suspicious_tld,
	}

	col_order = [
		"len_url", "len_host", "len_path", "len_query",
		"cnt_dot", "cnt_hyphen", "cnt_underscore", "cnt_at",
		"cnt_percent", "cnt_slash", "cnt_qmark", "cnt_amp",
		"cnt_equal", "cnt_hash", "subdomain_cnt", "cnt_digit",
		"ratio_digit", "has_suspicious_kw", "host_looks_like_ip",
		"cnt_pct_enc", "max_repeat_special_run", "query_param_cnt",
		"is_suspicious_tld"
	]
	return [float(features[k]) for k in col_order]

def call_ml_agent(url: str) -> Dict[str, Any]:
	bundle = _load_bundle()
	model = _unwrap_model(bundle["model"])
	threshold = float(bundle.get("threshold", float(os.getenv("MODEL_THRESHOLD", "0.8"))))

	X = [_extract_features(url)]

	# 경고 제거: "X does not have valid feature names..."
	with warnings.catch_warnings():
		warnings.filterwarnings(
			"ignore",
			message=r"X does not have valid feature names.*",
			category=UserWarning
		)
		if hasattr(model, "predict_proba"):
			prob = float(model.predict_proba(X)[0][1])
		else:
			prob = float(model.predict(X)[0])

	is_phishing = bool(prob >= threshold)

	if prob >= 0.8:
		risk = "high"
	elif prob >= 0.5:
		risk = "medium"
	elif prob >= threshold:
		risk = "low"
	else:
		risk = "safe"

	return {
		"agent": "ml_agent",
		"status": "success",
		"url": url,
		"phishing_probability": round(prob, 4),
		"threshold": threshold,
		"is_phishing": is_phishing,
		"risk_level": risk,
		"vote": "phishing" if is_phishing else "safe",
	}

