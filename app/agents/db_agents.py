import os
import re
import sqlite3
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from pathlib import Path

from utils import get_domain_from_url, get_registrable_domain, resolve_existing_path

# ============================================================
# DB 에이전트 + 유사(대칭) URL 탐색 에이전트
# - DB 에이전트(call_db_agent):
#   - 안전(benign) DB 먼저 확인
#   - 없으면 위험(phishing) DB 확인
# - 유사 URL 탐색(call_similarity_agent):
#   - 안전(benign) DB에서 유사 공식 도메인(대칭 URL) 후보 추천
# ============================================================

_BENIGN_CONN: Optional[sqlite3.Connection] = None
_PHISHING_CONN: Optional[sqlite3.Connection] = None


def _open_conn(db_path: str) -> sqlite3.Connection:
	conn = sqlite3.connect(db_path, check_same_thread=False)
	conn.execute("PRAGMA journal_mode=WAL;")
	conn.execute("PRAGMA synchronous=NORMAL;")
	return conn


def _ensure_table(conn: sqlite3.Connection) -> None:
	conn.execute("""
	CREATE TABLE IF NOT EXISTS domains (
		domain TEXT PRIMARY KEY
	);
	""")
	conn.commit()


def _get_conn(env_key: str, default_path: str) -> sqlite3.Connection:
	raw = os.getenv(env_key, default_path)
	base_dirs = [Path(__file__).resolve().parent, Path(__file__).resolve().parent.parent]
	path = resolve_existing_path(raw, base_dirs=base_dirs)
	conn = _open_conn(str(path))
	_ensure_table(conn)
	return conn


def get_benign_conn() -> sqlite3.Connection:
	global _BENIGN_CONN
	if _BENIGN_CONN is None:
		_BENIGN_CONN = _get_conn("BENIGN_DB_PATH", "./data/benign_domains.db")
	return _BENIGN_CONN


def get_phishing_conn() -> sqlite3.Connection:
	global _PHISHING_CONN
	if _PHISHING_CONN is None:
		_PHISHING_CONN = _get_conn("PHISHING_DB_PATH", "./data/phishing_domains.db")
	return _PHISHING_CONN


def _exists_domain(conn: sqlite3.Connection, domain: str) -> bool:
	row = conn.execute("SELECT 1 FROM domains WHERE domain=?;", (domain,)).fetchone()
	return row is not None


def _match_domain_suffix(conn: sqlite3.Connection, url: str) -> Optional[str]:
	host = get_domain_from_url(url)
	if not host:
		return None

	parts = host.split(".")
	if len(parts) < 2:
		return None

	# 서브도메인 suffix로 줄여가며 매칭
	for i in range(len(parts) - 1):
		cand = ".".join(parts[i:])
		if _exists_domain(conn, cand):
			return cand

	reg = get_registrable_domain(host)
	if reg and _exists_domain(conn, reg):
		return reg

	return None


# ====== benign DB 유사도 검색(대칭 URL) ======
_LEET_MAP = str.maketrans({
	"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
	"7": "t", "8": "b", "9": "g", "2": "z"
})


def _normalize_token(token: str) -> str:
	t = (token or "").lower()
	t = t.translate(_LEET_MAP)
	t = re.sub(r"[^a-z0-9]+", "", t)
	# gooooooogle 같은 반복 문자를 2개까지만 축약
	t = re.sub(r"(.)\1{2,}", r"\1\1", t)
	return t


def _levenshtein_ratio(a: str, b: str) -> float:
	a = a or ""
	b = b or ""
	if a == b:
		return 1.0
	la, lb = len(a), len(b)
	if la == 0 or lb == 0:
		return 0.0

	prev = list(range(lb + 1))
	for i in range(1, la + 1):
		cur = [i] + [0] * lb
		ca = a[i - 1]
		for j in range(1, lb + 1):
			cb = b[j - 1]
			cost = 0 if ca == cb else 1
			cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
		prev = cur

	dist = prev[lb]
	max_len = max(la, lb)
	return 1.0 - (dist / max_len)


def _domain_sld(domain: str) -> str:
	reg = get_registrable_domain(domain) or domain
	labels = reg.split(".")
	return labels[0] if len(labels) == 2 else labels[-2]


@dataclass
class OfficialCandidate:
	domain: str
	score: float


def _fetch_candidates_by_prefix(conn: sqlite3.Connection, prefixes: List[str], limit_each: int = 2000) -> List[str]:
	cands = set()
	for pref in prefixes:
		if not pref:
			continue
		cur = conn.execute("SELECT domain FROM domains WHERE domain LIKE ? LIMIT ?;", (f"{pref}%", limit_each))
		for (d,) in cur.fetchall():
			if d:
				cands.add(d)
	return list(cands)


def find_similar_official_from_benign_db(url: str, min_score: float = 0.86, max_candidates: int = 6000) -> Dict[str, Any]:
	conn = get_benign_conn()
	domain = get_domain_from_url(url)
	if not domain:
		return {"official_url": None, "similarity": None}

	needle = _normalize_token(_domain_sld(domain))
	prefixes: List[str] = []
	if len(needle) >= 4:
		prefixes.extend([needle[:4], needle[:3]])
	elif len(needle) >= 2:
		prefixes.append(needle[:2])
	elif needle:
		prefixes.append(needle[:1])

	prefixes = list(dict.fromkeys([p for p in prefixes if p]))
	limit_each = max(200, max_candidates // max(1, len(prefixes)))

	candidates = _fetch_candidates_by_prefix(conn, prefixes, limit_each=limit_each)
	if not candidates:
		return {"official_url": None, "similarity": None}

	best: Optional[OfficialCandidate] = None
	for cand in candidates:
		score = _levenshtein_ratio(needle, _normalize_token(_domain_sld(cand)))
		if best is None or score > best.score:
			best = OfficialCandidate(domain=cand, score=score)

	if not best:
		return {"official_url": None, "similarity": None}

	if best.score < float(min_score):
		return {"official_url": None, "similarity": float(best.score)}

	return {"official_url": f"https://{best.domain}", "similarity": float(best.score)}


# ====== public API ======
def call_db_agent(url: str) -> Dict[str, Any]:
	"""
	Return:
	- status: safe_db | phishing_db | unknown | error
	- matched_domain
	- (주의) official_url/similarity는 유사 탐색 에이전트(call_similarity_agent)가 담당합니다.
	"""
	domain = get_domain_from_url(url)
	if not domain:
		return {"agent": "db_agent", "status": "error", "message": "URL에서 도메인 추출 실패"}

	# 1) 안전 DB 확인
	benign = _match_domain_suffix(get_benign_conn(), url)
	if benign:
		return {
			"agent": "db_agent",
			"status": "safe_db",
			"matched_domain": benign,
			"vote": "safe",
		}

	# 2) 위험 DB 확인
	phish = _match_domain_suffix(get_phishing_conn(), url)
	if phish:
		return {
			"agent": "db_agent",
			"status": "phishing_db",
			"matched_domain": phish,
			"vote": "phishing",
		}

	return {"agent": "db_agent", "status": "unknown", "vote": "neutral", "matched_domain": None}


def call_similarity_agent(url: str, min_score: float = 0.86) -> Dict[str, Any]:
	"""
	안전(benign) DB 기반으로 유사(대칭) 공식 URL 후보 탐색
	Return:
	- official_url: https://{domain} 또는 None
	- similarity: 0~1 또는 None
	"""
	cand = find_similar_official_from_benign_db(url, min_score=min_score)
	return {
		"agent": "similarity_agent",
		"official_url": cand.get("official_url"),
		"similarity": cand.get("similarity"),
	}
