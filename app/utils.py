from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


# =============================
# 공통
# =============================
def resolve_existing_path(raw: str, base_dirs: Optional[List[Path]] = None) -> Path:
	if not raw:
		raise RuntimeError("경로 환경변수가 비어있습니다.")

	p = Path(raw)

	direct = p if p.is_absolute() else (Path.cwd() / p)
	if direct.exists():
		return direct.resolve()

	base_dirs = base_dirs or []
	candidates = [direct]

	for base in base_dirs:
		cand = (base / p).resolve()
		candidates.append(cand)
		if cand.exists():
			return cand

	raise FileNotFoundError(
		"파일을 찾을 수 없습니다.\n"
		+ f"- 입력 경로: {raw}\n"
		+ "- 확인한 후보들:\n  - " + "\n  - ".join(str(c) for c in candidates)
	)


def _push_log(
	logs: List[Dict[str, Any]],
	entry: Dict[str, Any],
	log_callback: Optional[Callable[[List[Dict[str, Any]]], None]]
) -> None:
	logs.append(entry)
	if log_callback:
		log_callback(logs)


# =============================
# Main
# =============================
URL_REGEX = re.compile(
	r"(?P<url>(https?://\S+)|((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?:/\S*)?)"
)


def extract_urls_from_text(text: str, max_urls: int = 10) -> List[str]:
	if not text:
		return []
	seen = set()
	out: List[str] = []
	for match in URL_REGEX.finditer(text):
		url = (match.group("url") or "").strip().rstrip(").,;\"'")
		if not url:
			continue
		if url in seen:
			continue
		seen.add(url)
		out.append(url)
		if len(out) >= max_urls:
			break
	return out


def normalize_url(raw_url: str) -> str:
	u = (raw_url or "").strip().rstrip(").,;\"'")
	u = re.sub(r"^(https?):/([^/])", r"\1://\2", u)
	if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", u):
		u = "https://" + u
	return u


# =============================
# DB
# =============================
def get_domain_from_url(url: str) -> Optional[str]:
	try:
		from urllib.parse import urlparse
		u = (url or "").strip()
		if not u:
			return None
		if "://" not in u:
			u = "https://" + u
		p = urlparse(u)
		host = p.netloc or ""
		if not host:
			return None
		host = host.split("@")[-1]
		host = host.split(":")[0]
		host = host.lower().strip(".")
		if host.startswith("www."):
			host = host[4:]
		return host or None
	except Exception:
		return None


_TWO_LEVEL_SUFFIXES = {
	"co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr",
	"co.jp", "co.uk", "org.uk", "gov.uk", "ac.uk",
	"com.au", "net.au", "org.au",
	"com.br", "com.cn", "com.tw", "com.hk",
}


def get_registrable_domain(domain: str) -> Optional[str]:
	if not domain:
		return None
	d = domain.lower().strip(".")
	labels = [x for x in d.split(".") if x]
	if len(labels) < 2:
		return d
	suffix2 = ".".join(labels[-2:])
	if suffix2 in _TWO_LEVEL_SUFFIXES and len(labels) >= 3:
		return ".".join(labels[-3:])
	return ".".join(labels[-2:])


# =============================
# Web
# =============================
def get_openai_client() -> OpenAI:
	api_key = os.getenv("OPENAI_API_KEY")
	if not api_key:
		raise RuntimeError("OPENAI_API_KEY가 준비되어 있지 않습니다. (.env)")
	return OpenAI(api_key=api_key)


def get_model_name() -> str:
	return os.getenv("OPENAI_MODEL", "gpt-5")
