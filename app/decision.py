from typing import Optional, List

# =============================
# 안전 조치사항(2~6줄)
# =============================
SAFETY_BULLETS: List[str] = [
    "의심스러운 링크는 클릭하지 말고, 공식 사이트 주소를 직접 입력해 접속하세요.",
    "아이디/비밀번호, OTP, 카드정보 등 민감정보 입력은 즉시 중단하세요.",
    "이미 정보를 입력했다면 즉시 비밀번호를 변경하고, 2단계 인증(MFA)을 활성화하세요.",
    "브라우저/OS/백신을 업데이트한 후 전체 검사를 실행하세요.",
    "로그인 기록/결제 내역을 확인하고, 의심스러운 활동이 있으면 즉시 고객센터에 문의하세요.",
]

def _md_line(lines: List[str]) -> str:
    return "\n".join(lines)


# evidence 문자열 생성 고정 템플릿
def evidence_safe_db(matched):
    return f"안전 DB 확인: 안전 (도메인 일치: {matched})"

def evidence_phishing_db(matched):
    return f"위험 DB 확인: 위험 (도메인 일치: {matched})"

def evidence_ml(is_phishing, prob, thr):
    result = "위험" if is_phishing else "안전"
    return f"모델 판별 결과: {result} (p_phish={prob:.4f}, thr={thr:.2f})"

def make_phishing_message(
    evidence: str,
    suspicious_url: str,
    official_url: Optional[str] = None,
    similarity_score: Optional[float] = None
) -> str:
    lines: List[str] = []
    lines.append("\n[산출근거]")
    lines.append(evidence)
    lines.append("\n현재 입력된 URL은 의심스러운 URL입니다.")
    lines.append("")
    
    lines.append("[대칭되는 URL]")
    if official_url:
        if similarity_score is not None:
            pct = similarity_score * 100.0
            lines.append(f"대칭되는 URL : {official_url} | 유사도 : {pct:.1f}%")
        else:
            lines.append(f"대칭되는 URL : {official_url}")
    else:
        lines.append("대칭되는 URL : 해당 없음")
    lines.append("")
    
    lines.append("[안전 조치사항]")
    for b in SAFETY_BULLETS:
        lines.append(f"- {b}")
    
    return _md_line(lines)


def make_safe_message(evidence: str, url: str) -> str:
    lines: List[str] = []
    lines.append("\n[산출근거]")
    lines.append(evidence)
    lines.append("\n현재 입력된 URL은 안전한 URL로 구성되었습니다.")
    lines.append("")
    lines.append("[대칭되는 URL]")
    lines.append("대칭되는 URL : 해당 없음")
    lines.append("")
    lines.append("[안전 조치사항]")
    for b in SAFETY_BULLETS[:3]:
        lines.append(f"- {b}")
    lines.append(f"\n[확인된 URL] : {url}")
    return _md_line(lines)