import streamlit as st
#import json
from datetime import datetime
from openai import OpenAI
#import re

# Streamlit Page Config Section ==============================================
# 
st.set_page_config(
    page_title="CTAC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded" # opens sidebar on the left
)

# HTML / CSS Configs ========================================================
#
st.html("""
    <style>
    /* 메인 헤더 스타일 */
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    /* 경고 박스 (중간 위험도) - 노란색 */
    .warning-box {
        background-color: #fff3cd;
        border-left: 5px solid #ffc107;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
    /* 안전 박스 (낮은 위험도) - 초록색 */
    .safe-box {
        background-color: #d4edda;
        border-left: 5px solid #28a745;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
    /* 위험 박스 (높은 위험도) - 빨간색 */
    .danger-box {
        background-color: #f8d7da;
        border-left: 5px solid #dc3545;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
    /* 채팅 메시지 기본 스타일 */
    .chat-message {
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 10px;
    }
    /* 사용자 메시지 스타일 - 오른쪽 정렬 */
    .user-message {
        background-color: #ffffff;
        text-align: right;
    }
    /* 봇 메시지 스타일 - 왼쪽 정렬 */
    .bot-message {
        background-color: #ffffff;
    }
    </style>
""")

# Session State List ========================================================
# Streamlit re-runs the code with every change, so save everything
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = []

# Main Header Section =======================================================
st.html('<div class="main-header">🛡️ 피싱 URL 탐지 챗봇</div>')
st.html("<p style='text-align: center; color: #666;'>의심스러운 링크를 클릭하기 전에 안전성을 확인하세요!</p>")

# Chat History Section ======================================================
st.markdown("### 💬 대화 기록")

# Show chat history saved in session_state
for chat in st.session_state.chat_history:
    if chat['role'] == 'user':
        st.markdown(
            f'<div class="chat-message user-message">👤 {chat["content"]}</div>', 
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f'<div class="chat-message bot-message">🤖 {chat["content"]}</div>', 
            unsafe_allow_html=True
        )
        # If results exists with the chat, show it together
        if 'result' in chat:
            placehold = 0 # placeholder for if block
            #display_analysis_result(chat['result']) #NEED UPDATE ***************************************************

st.markdown("---")

# User Input Chatbox Section =============================================
# Create chatbox, clears on submit
with st.form(key="chat_form", clear_on_submit=True):
    # 1 column for each (input box, submit button 5:1)
    col1, col2 = st.columns([5, 1])
    
    with col1:
        # input box
        user_input = st.text_input(
            "URL 또는 질문을 입력하세요",
            placeholder="예: https://naaver.com 이거 안전해? 또는 URL만 입력",
            label_visibility="collapsed" # Hide label until click
        )
    
    with col2:
        # submit button
        submit_button = st.form_submit_button("분석 🔍", use_container_width=True)

# Sidebar Settings ==========================================================
with st.sidebar:
    # Logo, title, split line
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
    st.title("🛡️ 피싱 탐지 시스템")
    st.markdown("---")
    
    # How to use section
    st.subheader("📌 사용 방법")
    st.markdown("""
    1. OpenAI API 키를 입력하세요.
    2. 질문을 입력하세요. (자연어도 가능합니다)
    4. AI가 링크를 분석하여 위험도를 알려줍니다!
    """)
    
    st.markdown("---")
    st.subheader("⚙️ OpenAI API")
    
    # OpenAI API key / entered as password for privacy
    api_key = st.text_input(
        "OpenAI API Key",
        type="password",  # shows input as asterisks
        help="OpenAI API 키를 입력하세요."
    )
    
    # Verifying key mechanism / NEED UPDATE ******************************
    if api_key:
        st.success("✅ API 키가 설정되었습니다")
    else:
        st.warning("⚠️ API 키를 입력해주세요")
    
    st.markdown("---")
    
    # Statistics Section
    st.subheader("📊 통계")
    st.metric("총 분석 횟수", len(st.session_state.analysis_results))
    
    # Show total counted num of risky URLs
    if st.session_state.analysis_results:
        danger_count = sum(1 for r in st.session_state.analysis_results if r.get('risk_level') == 'high')
        st.metric("위험 URL 탐지", danger_count)
    
    st.markdown("---")
    
    # Clear Chat History button
    if st.button("🗑️ 대화 기록 삭제", type="secondary"):
        st.session_state.chat_history = []
        st.session_state.analysis_results = []
        st.rerun()  # re-run page

# User Submission Handling Section ====================================================================
if submit_button and user_input:
    # when user actually submits something
    st.session_state.chat_history.append({
        'role': 'user',
        'content': user_input,
        'timestamp': datetime.now()
    })

    client = OpenAI(api_key=api_key)
    
    # Show loading (probably not needed thanks to fast speed)
    with st.spinner('AI가 입력된 URL을 분석 중입니다...'):
        placehold = 0
        # OpenAI API 호출하여 URL 분석
        # result = NEED UPDATE ***********************************************
    
    # System_prompt로 전달? - DB에서 찾으면 이런식으로 답변해줘 라고 할수있을지도? 
    #JSON형식으로 GPT한테 결과 받아서 처리..?
    '''
    system_prompt = f"""You are a phishing website detection expert. 
                    You analyze user provided URL to decide if it's a malicious website, 
                    then provide detailed explanation and recommended steps to take.

                    URL features:
                    - URL length: {features['url_length']}
                    - Number of special characters: {features['special_char_count']}
                    - Suspicious keywords: {', '.join(features['suspicious_keywords']) if features['suspicious_keywords'] else 'None'}
                    - Dot(.) count: {features['dot_count']}
                    - Includes IP address: {'Yes' if features['has_ip_address'] else 'No'}
                    - Includes @ symbol: {'Yes' if features['has_at_symbol'] else 'No'}

                    ONLY answer in this JSON format:
                    {{
                        "risk_level": "high/medium/low",
                        "phishing_probability": 0.0-1.0,
                        "explanation": "Analysis results explained in Korean (한국어, 최소 3-5문장)",
                        "recommendations": ["step1", "step2", "step3"],
                        "key_findings": ["finding1", "finding2"]
                    }}

                    Danger levels:
                    - high (0.7 or higher): Definately malicious
                    - medium (0.3-0.7): Could be malicious, take caution
                    - low (0.3 or lower): Looks safe / False alarm / etc
                    """
    '''

    # Send to GPT
    '''
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input}
        ]
    )
    '''
    
    # Phishing Yes/No logic section / NEED UPDATE **************************************
    result = {
        "risk_level": "high",
        "phishing_probability": 0.9,
        "explanation": "분석 결과 예시입니다.",
        "recommendations": ["step1", "step2", "step3"],
        "key_findings": ["finding1", "finding2"]
    }

    # Save result to result list
    if result and not result.get('error'):
        st.session_state.analysis_results.append(result)
        risk_level = result.get('risk_level', 'unknown')
        if risk_level == 'unknown':
            bot_msg = '⚠️ 알수없는 웹사이트이거나 URL을 분석하는데 실패하였습니다. 주의해서 접근하세요.'
            box_class = 'warning-box'
        elif risk_level == 'high':
            bot_msg = "⚠️ 위험한 URL로 판단됩니다. 절대 클릭하지 마세요!"
            box_class = 'danger-box'
        elif risk_level == 'medium':
            bot_msg = "⚠️ 의심스러운 URL입니다. 주의해서 접근하세요."
            box_class = 'warning-box'
        elif risk_level == 'low':
            bot_msg = "✅ 안전한 URL로 판단됩니다."
            box_class = 'safe-box'

    st.html(f'<div class="{box_class}"><h3>{bot_msg}</h3></div>')

    st.markdown("#### 🤖 AI 분석 결과")
    
    # Show phishing probability as progress bar
    if 'phishing_probability' in result:
        prob = result['phishing_probability']
        st.progress(prob)
        st.markdown(f"피싱 확률: {prob*100:.1f}%")

    st.markdown("#### 🔍 주요 발견사항")
    
    # Key findings
    if 'key_findings' in result and result['key_findings']:
        for finding in result['key_findings']:
            st.markdown(f"- {finding}")
    else:
        st.markdown("특이사항 없음")
    
    # Explanations
    if 'explanation' in result:
        st.markdown("#### 💬 상세 설명")
        st.markdown(result['explanation'])
    
    # Recommendations
    if 'recommendations' in result and result['recommendations']:
        st.markdown("#### 📋 권장 사항")
        for i, rec in enumerate(result['recommendations'], 1):
            st.markdown(f"{i}. {rec}")

    # Add response to chat history
    st.session_state.chat_history.append({
        'role': 'bot',
        'content': bot_msg,
        'timestamp': datetime.now()
    })
    
    # Refresh page to update history
    st.rerun()

# Disclaimer and info on the bottom of the page =================================================
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #999; font-size: 0.9rem;'>"
    "This page is a TEST, and does not take any legal responsibility. | "
    "Powered by OpenAI GPT-4 | "
    "Made for SK-Shieldus 30th by team CTAC"
    "</p>",
    unsafe_allow_html=True
)

# HOW TO RUN
# --- In terminal ---
# pip install streamlit
# pip install openai
# streamlit run {cwd}/{filename}
