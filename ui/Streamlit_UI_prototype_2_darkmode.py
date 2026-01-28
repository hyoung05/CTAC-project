import streamlit as st
from datetime import datetime
from dotenv import load_dotenv
from main_agent import run_main_agent

load_dotenv()

st.set_page_config(
    page_title="CTAC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.html("""
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
    /* Dark Mode Handling */
    @media (prefers-color-scheme: dark) {
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
""")

if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = []

if 'current_logs' not in st.session_state:
    st.session_state.current_logs = []

# 사이드바
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
    st.title("피싱 탐지 시스템")
    st.markdown("---")
    
    # 분석 과정 로그 표시
    st.subheader("분석 과정")
    
    log_container = st.container()
    
    with log_container:
        if st.session_state.current_logs:
            for log in st.session_state.current_logs:
                step = log.get('step', '')
                
                if step == "시작":
                    st.info(f" {log['message']}")
                
                elif step == "에이전트 호출":
                    agent = log.get('agent', '')
                    args = log.get('args', {})
                    url = args.get('url', '')
                    if agent == "call_db_agent":
                        st.write(f" DB 에이전트 호출")
                        st.caption(f"URL: {url}")
                    elif agent == "call_ml_agent":
                        st.write(f" ML 에이전트 호출")
                        st.caption(f"URL: {url}")
                
                elif step == "에이전트 결과":
                    agent = log.get('agent', '')
                    result = log.get('result', {})
                    status = result.get('status', '')
                    message = result.get('message', '')
                    
                    if agent == "call_db_agent":
                        if status == "trusted":
                            st.success(f" {message}")
                        elif status == "typosquatting":
                            st.error(f"🚨 {message}")
                        else:
                            st.warning(f"{message}")
                    
                    elif agent == "call_ml_agent":
                        prob = result.get('phishing_probability', 0)
                        vote = result.get('vote', '')
                        if vote == "phishing":
                            st.error(f"🚨 피싱 확률: {prob:.1%}")
                        else:
                            st.success(f"✅ 피싱 확률: {prob:.1%}")
                        st.progress(prob)
                
                elif step == "완료":
                    st.success(f"✅ 분석 완료")
        else:
            st.caption("URL을 입력하면 분석 과정이 표시됩니다.")
    
    st.markdown("---")
    
    if st.button("대화 기록 삭제", type="secondary", use_container_width=True):
        st.session_state.chat_history = []
        st.session_state.analysis_results = []
        st.session_state.current_logs = []
        st.rerun()

# 메인 화면
st.html('<div class="main-header">🛡️ 피싱 URL 탐지 챗봇</div>')
st.html("<p style='text-align: center; color: #666;'>의심스러운 링크를 클릭하기 전에 안전성을 확인하세요!</p>")

st.markdown("### 대화 기록")

for chat in st.session_state.chat_history:
    if chat['role'] == 'user':
        st.markdown(
            f'<div class="chat-message user-message">{chat["content"]}</div>', 
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f'<div class="chat-message bot-message">{chat["content"]}</div>', 
            unsafe_allow_html=True
        )

st.markdown("---")

with st.form(key="chat_form", clear_on_submit=True):
    col1, col2 = st.columns([5, 1])
    
    with col1:
        user_input = st.text_input(
            "URL 또는 질문을 입력하세요",
            placeholder="예: https://naaver.com 이거 안전해?",
            label_visibility="collapsed"
        )
    
    with col2:
        submit_button = st.form_submit_button("분석", use_container_width=True)

if submit_button and user_input:
    st.session_state.chat_history.append({
        'role': 'user',
        'content': user_input,
        'timestamp': datetime.now()
    })
    
    # 로그 초기화
    st.session_state.current_logs = []
    
    with st.spinner('AI가 URL을 분석 중입니다...'):
        try:
            result = run_main_agent(user_input)
            response = result["response"]
            logs = result["logs"]
            st.session_state.current_logs = logs
        except Exception as e:
            response = f"오류 발생: {str(e)}"
            st.session_state.current_logs = []
    
    if "피싱" in response or "위험" in response or "의심" in response or "🚨" in response:
        risk_level = "high"
        box_class = "danger-box"
        bot_summary = "🚨 피싱 의심 URL입니다. 절대 클릭하지 마세요!"
    elif "안전" in response or "신뢰" in response or "✅" in response:
        risk_level = "low"
        box_class = "safe-box"
        bot_summary = "✅ 안전한 URL로 판단됩니다."
    else:
        risk_level = "medium"
        box_class = "warning-box"
        bot_summary = "⚠️ 주의가 필요한 URL입니다."
    
    st.session_state.analysis_results.append({
        'risk_level': risk_level,
        'response': response
    })
    
    st.html(f'<div class="{box_class}"><h4>{bot_summary}</h4></div>')
    st.markdown("#### 🤖 AI 분석 결과")
    st.markdown(response)
    
    st.session_state.chat_history.append({
        'role': 'bot',
        'content': response,
        'timestamp': datetime.now()
    })
    
    st.rerun()

st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #999; font-size: 0.9rem;'>"  
    "⚠️ 본 서비스는 참고용이며 법적 책임을 지지 않습니다. | "
    "Powered by OpenAI GPT-4 | "  
    "SK-Shieldus 30기 CTAC팀"  
    "</p>",
    unsafe_allow_html=True
)
