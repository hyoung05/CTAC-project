import streamlit as st
from datetime import datetime

from dotenv import load_dotenv
from agents.main_agent import run_orchestrator

load_dotenv()

# Streamlit Page Config ======================================================
st.set_page_config(
	page_title="CTAC",
	page_icon="🛡️",
	layout="wide",
	initial_sidebar_state="expanded"
)

# CSS =======================================================================
st.markdown("""
<style>
.main-header {
	font-size: 2.5rem;
	font-weight: bold;
	color: #1f77b4;
	text-align: center;
	margin-bottom: 1rem;
}
.warning-box {
	background-color: #fff3cd;
	border-left: 5px solid #ffc107;
	padding: 1rem;
	margin: 1rem 0;
	border-radius: 5px;
}
.safe-box {
	background-color: #d4edda;
	border-left: 5px solid #28a745;
	padding: 1rem;
	margin: 1rem 0;
	border-radius: 5px;
}
.danger-box {
	background-color: #f8d7da;
	border-left: 5px solid #dc3545;
	padding: 1rem;
	margin: 1rem 0;
	border-radius: 5px;
}
.chat-message {
	padding: 1rem;
	margin: 0.5rem 0;
	border-radius: 10px;
}
.user-message {
	background-color: #e3f2fd;
	text-align: right;
}
.bot-message {
	background-color: #f5f5f5;
}
@media (prefers-color-scheme: dark) {
	.main-header {
		color: #4da6ff;
	}
	.user-message {
		background-color: #1e3a5f;
		color: #e3f2fd;
	}
	.bot-message {
		background-color: #2d2d2d;
		color: #f5f5f5;
	}
	.warning-box {
		background-color: #3d3419;
		color: #fff3cd;
	}
	.safe-box {
		background-color: #1a3a28;
		color: #d4edda;
	}
	.danger-box {
		background-color: #3d1a1f;
		color: #f8d7da;
	}
}
</style>
""", unsafe_allow_html=True)

# Session State ==============================================================
if "chat_history" not in st.session_state:
	st.session_state.chat_history = []
if "analysis_results" not in st.session_state:
	st.session_state.analysis_results = []
if "current_logs" not in st.session_state:
	st.session_state.current_logs = []

# Sidebar (요구사항: 메시지 지우기 기능만 유지 + 로그 출력 추가) =====================
with st.sidebar:
	st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
	st.title("🛡️ 피싱 탐지 시스템")
	st.markdown("---")
	st.subheader(" 사용 방법")
	st.markdown("""
1. URL 또는 질문을 입력하세요 (여러 URL도 가능)
2. AI가 링크를 분석하여 위험도를 알려줍니다!
""")
	# 1) 대화/분석 기록 삭제
	if st.button("🗑️ 대화 기록 삭제", type="secondary", use_container_width=True):
		st.session_state.chat_history = []
		st.session_state.analysis_results = []
		st.session_state.current_logs = []
		st.rerun()

	st.markdown("---")
	st.subheader("분석 과정")

	log_placeholder = st.empty()

	def render_logs(logs):
		with log_placeholder.container():
			if not logs:
				st.caption("URL을 분석하면 여기에 단계별 로그가 표시됩니다.")
				return

			for log in logs:
				step = log.get("step", "")
				msg = log.get("message", "")

				# 입력/URL 추출/종합
				if step in ("입력", "URL 추출", "종합"):
					st.info(f"{step}: {msg}")

				# URL 표시
				elif step == "입력 URL":
					st.markdown(f"🔗 {msg}")

				# DB 호출/결과
				elif step == "DB 에이전트 호출":
					st.write("DB 에이전트 호출")
					st.caption(f"URL: {log.get('url','')}")

				elif step == "DB 결과":
					res = log.get("result", {}) or {}
					status = res.get("status", "")
					matched = res.get("matched_domain", "-")
					if status == "safe_db":
						st.success(f"✅ 안전 DB 매칭: {matched}")
					elif status == "phishing_db":
						st.error(f"🚨 위험 DB 매칭: {matched}")
					else:
						st.warning("⚠️ DB 미매칭 (다음 단계 진행)")

				# ML 호출/결과
				elif step == "ML 에이전트 호출":
					st.write("ML 에이전트 호출")
					st.caption(f"URL: {log.get('url','')}")

				elif step == "ML 결과":
					res = log.get("result", {}) or {}
					prob = float(res.get("phishing_probability", 0) or 0)
					is_phish = bool(res.get("is_phishing", False))
					if is_phish:
						st.error(f"🚨 피싱 확률: {prob:.1%}")
					else:
						st.success(f"✅ 피싱 확률: {prob:.1%}")
					st.progress(min(max(prob, 0.0), 1.0))

				elif step == "모델 판별":
					label = int(log.get("label", 0) or 0)
					prob = float(log.get("p_phish", 0) or 0)
					thr = float(log.get("thr", 0.8) or 0.8)
					icon = "🚨" if label == 1 else "✅"
					st.markdown(f"{icon} 모델 판별: label={label}, p={prob:.4f}, thr={thr:.2f}")

				# 유사 검색 / web_search
				elif step in ("유사 검색", "유사 검색 결과", "web_search"):
					if msg:
						st.info(f"{step}: {msg}")
					else:
						st.info(step)

				# 최종 판정/완료
				elif step == "판정":
					risk = log.get("risk_level", "medium")
					if risk == "high":
						st.error(f"🚨 {msg}")
					elif risk == "low":
						st.success(f"✅ {msg}")
					else:
						st.warning(msg)

				elif step == "완료":
					risk = log.get("risk_level", "medium")
					if risk == "high":
						st.error("✅ 분석 완료")
					elif risk == "low":
						st.success("✅ 분석 완료")
					else:
						st.info("✅ 분석 완료")

				else:
					st.write(f"{step}: {msg}")

	# 최초 렌더
	render_logs(st.session_state.current_logs)

# Header ====================================================================
st.markdown('<div class="main-header">🛡️ 피싱 URL 탐지 챗봇</div>', unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #666;'>의심스러운 링크를 클릭하기 전에 안전성을 확인하세요!</p>", unsafe_allow_html=True)

# Chat History ===============================================================
st.markdown("### 💬 대화 기록")
for chat in st.session_state.chat_history:
	if chat["role"] == "user":
		st.markdown(f'<div class="chat-message user-message">👤 {chat["content"]}</div>', unsafe_allow_html=True)
	else:
		st.markdown(f'<div class="chat-message bot-message">🤖 {chat["content"]}</div>', unsafe_allow_html=True)

st.markdown("---")

# Input Form =================================================================
with st.form(key="chat_form", clear_on_submit=True):
	col1, col2 = st.columns([5, 1])
	with col1:
		user_input = st.text_input(
			"URL 또는 질문을 입력하세요",
			placeholder="예: https://naaver.com 이거 안전해? 또는 URL만 입력",
			label_visibility="collapsed"
		)
	with col2:
		submit_button = st.form_submit_button("분석 🔍", use_container_width=True)

# Submit Handling ============================================================
if submit_button and user_input:
	st.session_state.chat_history.append({
		"role": "user",
		"content": user_input,
		"timestamp": datetime.now(),
	})

	# 로그 초기화 + 사이드바에 즉시 반영
	st.session_state.current_logs = []
	render_logs(st.session_state.current_logs)

	def log_callback(logs):
		st.session_state.current_logs = logs
		render_logs(logs)

	with st.spinner("🔍 AI가 사용자의 응답을 분석중입니다..."):
		try:
			out = run_orchestrator(user_input, log_callback=log_callback)
			response = out.get("response", "")
			risk_level = out.get("risk_level", "medium")
			st.session_state.current_logs = out.get("logs", st.session_state.current_logs)
			render_logs(st.session_state.current_logs)
		except Exception as e:
			response = f"오류 발생: {type(e).__name__}: {e}"
			risk_level = "medium"
			st.session_state.current_logs = [{"step": "완료", "risk_level": "medium", "message": "오류로 인해 중단되었습니다."}]
			render_logs(st.session_state.current_logs)

	# 결과 요약 박스
	if risk_level == "high":
		box_class = "danger-box"
		bot_summary = "🚨 피싱 의심 URL이 포함되어 있습니다. 절대 클릭하지 마세요!"
	elif risk_level == "low":
		box_class = "safe-box"
		bot_summary = "✅ 입력된 URL은 안전으로 판단되었습니다."
	else:
		box_class = "warning-box"
		bot_summary = "⚠️ 판단이 애매합니다. 주의해서 접근하세요."

	st.session_state.analysis_results.append({"risk_level": risk_level, "response": response})

	st.markdown(f'<div class="{box_class}"><h4>{bot_summary}</h4></div>', unsafe_allow_html=True)
	st.markdown("#### 🤖 AI 분석 결과")
	st.markdown(response)

	st.session_state.chat_history.append({
		"role": "bot",
		"content": response,
		"timestamp": datetime.now(),
	})

	st.rerun()

# Footer =====================================================================
st.markdown("---")
st.markdown(
	"<p style='text-align: center; color: #999; font-size: 0.9rem;'>"
	"⚠️ 본 서비스는 참고용이며 법적 책임을 지지 않습니다. | "
	"Powered by OpenAI GPT-5 | "
	"CTAC"
	"</p>",
	unsafe_allow_html=True
)
