import os
import re
import sqlite3
import argparse
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse


# =========================
# URL -> domain 추출 (standalone)
# =========================
def get_domain_from_url(raw_url: str) -> Optional[str]:
	u = (raw_url or "").strip()
	if not u:
		return None

	# scheme 없으면 임의로 붙여서 urlparse가 hostname을 잡게 함
	if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", u):
		u = "http://" + u

	p = urlparse(u)
	host = p.hostname
	if not host:
		return None

	host = host.strip(".").lower()

	# IDN(한글 도메인 등) 대응: DB가 punycode로 저장된 경우 매칭 가능하게
	try:
		host = host.encode("idna").decode("ascii")
	except Exception:
		pass

	return host or None


def get_registrable_domain(host: str) -> Optional[str]:
	"""
	완전한 Public Suffix List 구현은 아니고,
	프로젝트에서 흔히 쓰는 2단계/3단계 TLD를 간단히 커버하는 휴리스틱.
	"""
	if not host:
		return None

	labels = host.split(".")
	if len(labels) < 2:
		return host

	# 자주 쓰는 2단계 TLD(예: co.kr, ac.kr, co.uk 등) 목록
	two_level_suffix = {
		"co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "mil.kr",
		"hs.kr", "ms.kr", "es.kr",
		"co.uk", "org.uk", "gov.uk", "ac.uk",
		"com.au", "net.au", "org.au", "gov.au",
	}

	last2 = ".".join(labels[-2:])
	if last2 in two_level_suffix and len(labels) >= 3:
		return ".".join(labels[-3:])

	return ".".join(labels[-2:])


# =========================
# DB 연결/경로 (standalone)
# =========================
def resolve_existing_path(raw: str, base_dirs: list[Path]) -> Path:
	p = Path(raw)
	if p.is_file():
		return p

	for b in base_dirs:
		cand = (b / raw).resolve()
		if cand.is_file():
			return cand

	# 파일이 없어도 sqlite는 새로 만들 수 있으니 그대로 반환
	return p.resolve()


def open_conn(db_path: str) -> sqlite3.Connection:
	conn = sqlite3.connect(db_path, check_same_thread=False)
	conn.execute("PRAGMA journal_mode=WAL;")
	conn.execute("PRAGMA synchronous=NORMAL;")
	return conn


def ensure_table(conn: sqlite3.Connection) -> None:
	conn.execute("""
	CREATE TABLE IF NOT EXISTS domains (
		domain TEXT PRIMARY KEY
	);
	""")
	conn.commit()


def get_conn(env_key: str, default_path: str, cli_path: Optional[str] = None) -> sqlite3.Connection:
	raw = cli_path or os.getenv(env_key, default_path)

	base_dirs = [
		Path(__file__).resolve().parent,
		Path(__file__).resolve().parent.parent,
	]
	path = resolve_existing_path(raw, base_dirs=base_dirs)

	conn = open_conn(str(path))
	ensure_table(conn)
	return conn


# =========================
# DB 검색 로직 (양쪽 DB만)
# =========================
def exists_domain(conn: sqlite3.Connection, domain: str) -> bool:
	row = conn.execute("SELECT 1 FROM domains WHERE domain=?;", (domain,)).fetchone()
	return row is not None


def match_domain_suffix(conn: sqlite3.Connection, url: str) -> Optional[str]:
	host = get_domain_from_url(url)
	if not host:
		return None

	parts = host.split(".")
	if len(parts) < 2:
		return None

	# 서브도메인 suffix로 줄여가며 매칭 (긴 것부터)
	for i in range(len(parts) - 1):
		cand = ".".join(parts[i:])
		if exists_domain(conn, cand):
			return cand

	# registrable domain도 한 번 더 확인
	reg = get_registrable_domain(host)
	if reg and exists_domain(conn, reg):
		return reg

	return None


def search_both_dbs(
	url: str,
	benign_conn: sqlite3.Connection,
	phishing_conn: sqlite3.Connection
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
	domain = get_domain_from_url(url)
	benign_match = match_domain_suffix(benign_conn, url) if domain else None
	phish_match = match_domain_suffix(phishing_conn, url) if domain else None
	return domain, benign_match, phish_match


# =========================
# CLI entry
# =========================
def db_search(url : list) -> None:
	benign_conn = get_conn("BENIGN_DB_PATH", "./data/benign_domains.db")
	phishing_conn = get_conn("PHISHING_DB_PATH", "./data/phishing_domains.db")

	try:
		for u in url:
			domain, benign_match, phish_match = search_both_dbs(u, benign_conn, phishing_conn)

			print("=" * 60)
			print(f"INPUT   : {u}")
			print(f"DOMAIN  : {domain if domain else '도메인 추출 실패'}")
			print(f"BENIGN  : {'FOUND  -> ' + benign_match if benign_match else 'NOT FOUND'}")
			print(f"PHISHING: {'FOUND  -> ' + phish_match if phish_match else 'NOT FOUND'}")
	finally:
		# 깔끔하게 종료
		try:
			benign_conn.close()
		except Exception:
			pass
		try:
			phishing_conn.close()
		except Exception:
			pass


if __name__ == "__main__":
	db_search(['https://naver.com', 'http://pks.ilogenis.com', 'google.com'])


