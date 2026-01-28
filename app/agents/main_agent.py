import json
from typing import Any, Callable, Dict, List, Optional

from agents.db_agents import call_db_agent, call_similarity_agent
from agents.ml_agent import call_ml_agent
from agents.web_agent import call_web_agent
from decision import make_phishing_message, make_safe_message, evidence_safe_db, evidence_phishing_db, evidence_ml
from utils import _push_log, extract_urls_from_text, get_model_name, get_openai_client, normalize_url


# ============================================================
# 메인 오케스트레이터 (Function Calling 기반)
# - 다중 URL: 입력에서 URL을 여러 개 추출해 순차 처리
# - Phase A: DB/ML/유사탐색(로컬)까지 수행 (web 도구 미제공)
# - Phase B: (공식 URL 탐색이 NONE일 때만) call_web_agent를 Fn_call로 1회 수행
# - 안전성 강화:
#   1) ML 피싱 케이스에서도 similarity(%)가 출력되도록 통일
#   2) LLM이 툴 호출 없이 끝내는 경우를 대비해 결정적 보강(강제 호출) 적용
# ============================================================


# Phase A: DB / ML / Similarity(로컬)
TOOLS_PHASE_A = [
	{
		"type": "function",
		"function": {
			"name": "call_db_agent",
			"description": "URL의 도메인을 안전 DB와 위험 DB에서 조회",
			"parameters": {
				"type": "object",
				"properties": {
					"url": {"type": "string", "description": "검사할 URL"}
				},
				"required": ["url"]
			}
		}
	},
	{
		"type": "function",
		"function": {
			"name": "call_ml_agent",
			"description": "ML 모델로 피싱 확률 예측 (DB 미확인 시)",
			"parameters": {
				"type": "object",
				"properties": {
					"url": {"type": "string", "description": "검사할 URL"}
				},
				"required": ["url"]
			}
		}
	},
	{
		"type": "function",
		"function": {
			"name": "call_similarity_agent",
			"description": "안전 DB 기반으로 유사(대칭) 공식 URL 후보를 탐색 (로컬)",
			"parameters": {
				"type": "object",
				"properties": {
					"url": {"type": "string", "description": "검사할 URL"}
				},
				"required": ["url"]
			}
		}
	},
]

# Phase B: Web(공식 URL 검색)
TOOLS_PHASE_B = [
	{
		"type": "function",
		"function": {
			"name": "call_web_agent",
			"description": "피싱 URL의 공식 URL을 웹검색",
			"parameters": {
				"type": "object",
				"properties": {
					"url": {"type": "string", "description": "피싱 의심 URL"}
				},
				"required": ["url"]
			}
		}
	},
]


def _call_tool(name, args, logs, log_callback):
	url = args.get("url", "")

	if name == "call_db_agent":
		_push_log(logs, {"step": "DB 에이전트 호출", "url": url}, log_callback)
		res = call_db_agent(url)
		_push_log(logs, {"step": "DB 결과", "url": url, "result": res}, log_callback)
		return res

	if name == "call_ml_agent":
		_push_log(logs, {"step": "ML 에이전트 호출", "url": url}, log_callback)
		res = call_ml_agent(url)
		_push_log(logs, {"step": "ML 결과", "url": url, "result": res}, log_callback)
		return res

	if name == "call_similarity_agent":
		_push_log(logs, {"step": "유사 검색", "url": url, "message": "안전 DB 기반으로 유사 공식 URL을 탐색합니다."}, log_callback)
		res = call_similarity_agent(url)
		msg = "유사 공식 URL 후보를 찾았습니다." if res.get("official_url") else "유사 공식 URL 후보를 찾지 못했습니다."
		_push_log(logs, {"step": "유사 검색 결과", "url": url, "message": msg, "result": res}, log_callback)
		return res

	if name == "call_web_agent":
		_push_log(logs, {"step": "Web 에이전트 호출", "url": url}, log_callback)
		official = call_web_agent(url, logs=logs, log_callback=log_callback)
		return {"official_url": official}

	return {"error": "unknown tool"}


def _run_phase(
	client,
	model: str,
	prompt: str,
	tools: List[Dict[str, Any]],
	tool_results: Dict[str, Dict[str, Any]],
	logs: List[Dict[str, Any]],
	log_callback: Optional[Callable[[List[Dict[str, Any]]], None]],
	max_turns: int = 5
) -> None:
	messages = [{"role": "user", "content": prompt}]

	for _ in range(max_turns):
		resp = client.chat.completions.create(
			model=model,
			messages=messages,
			tools=tools,
			tool_choice="auto"
		)
		msg = resp.choices[0].message
		messages.append(msg)

		if not msg.tool_calls:
			break

		for tc in msg.tool_calls:
			fn_name = tc.function.name
			fn_args = json.loads(tc.function.arguments or "{}")

			_push_log(logs, {"step": "에이전트 호출", "agent": fn_name, "args": fn_args}, log_callback)
			result = _call_tool(fn_name, fn_args, logs, log_callback)

			# 결과 저장(동일 툴이 여러 번 호출되면 마지막 결과가 남음)
			tool_results[fn_name] = result

			messages.append({
				"role": "tool",
				"tool_call_id": tc.id,
				"content": json.dumps(result, ensure_ascii=False)
			})


def _make_response(url, db_res, ml_res, sim_res, web_res):
	status = (db_res or {}).get("status", "unknown")

	if status == "safe_db":
		ev = evidence_safe_db((db_res or {}).get("matched_domain", "-"))
		return {"risk_level": "low", "text": make_safe_message(ev, url)}

	# DB에서 위험으로 확정된 경우
	if status == "phishing_db":
		ev = evidence_phishing_db((db_res or {}).get("matched_domain", "-"))
		official = (sim_res or {}).get("official_url") or (web_res or {}).get("official_url")
		sim = (sim_res or {}).get("similarity")
		return {"risk_level": "high", "text": make_phishing_message(ev, url, official, sim)}

	# DB unknown -> ML 기준
	prob = float((ml_res or {}).get("phishing_probability", 0) or 0)
	thr = float((ml_res or {}).get("threshold", 0.8) or 0.8)
	is_phish = bool((ml_res or {}).get("is_phishing", False))
	if ml_res:
		ev = evidence_ml(is_phish, prob, thr)
	else:
		ev = evidence_ml(False, 0.0, thr)

	if is_phish:
		official = (sim_res or {}).get("official_url") or (web_res or {}).get("official_url")
		sim = (sim_res or {}).get("similarity")
		return {"risk_level": "high", "text": make_phishing_message(ev, url, official, sim)}

	return {"risk_level": "low", "text": make_safe_message(ev, url)}


def _classify_one(url, logs, log_callback, idx, total):
	norm = normalize_url(url)
	client = get_openai_client()
	model = get_model_name()

	_push_log(logs, {"step": "입력 URL", "message": f"[{idx}/{total}] {norm}"}, log_callback)

	# tool 결과 저장소 (Fn name -> result dict)
	phase_a_results: Dict[str, Dict[str, Any]] = {}
	phase_b_results: Dict[str, Dict[str, Any]] = {}

	# ------------------------------------------------------------
	# Phase A: DB/ML/유사탐색(로컬)까지 수행 (web 도구는 제공하지 않음)
	# ------------------------------------------------------------
	prompt_a = f"""피싱 URL 탐지를 수행합니다.
[규칙]
- 반드시 1→2→3 순서대로 도구를 호출하세요.
- 1) call_db_agent(url)
	- status가 safe_db이면 즉시 done
	- status가 phishing_db이면 3)으로 이동
	- status가 unknown이면 2)로 이동
- 2) call_ml_agent(url) (DB가 unknown일 때만)
	- is_phishing=False이면 즉시 done
	- is_phishing=True이면 3)으로 이동
- 3) call_similarity_agent(url) (피싱 판정일 때만)
	- official_url이 있으면 done
	- official_url이 None이면 공식 URL 탐색 결과를 NONE으로 두고 done
주의: 이 단계에서는 call_web_agent를 호출하지 마세요.

[분석 URL] {norm}
완료되면 "done"이라고만 답하세요."""

	_run_phase(client, model, prompt_a, TOOLS_PHASE_A, phase_a_results, logs, log_callback, max_turns=5)

	db_res: Dict[str, Any] = phase_a_results.get("call_db_agent", {}) or {}
	ml_res: Dict[str, Any] = phase_a_results.get("call_ml_agent", {}) or {}
	sim_res: Dict[str, Any] = phase_a_results.get("call_similarity_agent", {}) or {}
	web_res: Dict[str, Any] = {}

	# ------------------------------------------------------------
	# 결정적 보강(안정성):
	# - LLM이 툴 호출 없이 종료하더라도 DB/ML/유사탐색 결과를 확보
	# ------------------------------------------------------------
	# 1) DB 결과 보강
	if not db_res:
		db_res = _call_tool("call_db_agent", {"url": norm}, logs, log_callback)

	status = db_res.get("status", "unknown")

	# 2) ML 결과 보강 (DB unknown일 때만)
	if status == "unknown" and not ml_res:
		ml_res = _call_tool("call_ml_agent", {"url": norm}, logs, log_callback)

	# 3) 피싱 판정이면 유사탐색 보강
	is_phish = False
	if status == "phishing_db":
		is_phish = True
	elif status == "unknown":
		is_phish = bool(ml_res.get("is_phishing", False))

	if is_phish and not sim_res:
		sim_res = _call_tool("call_similarity_agent", {"url": norm}, logs, log_callback)

	# ------------------------------------------------------------
	# Phase B: (공식 URL 탐색이 NONE일 때만) web_search를 Fn_call로 수행
	# ------------------------------------------------------------
	need_web = False
	if is_phish:
		need_web = not bool(sim_res.get("official_url"))

	if need_web:
		prompt_b = f"""공식 URL 탐색(웹검색)을 수행합니다.
[조건]
- 로컬 유사 탐색 결과 official_url이 NONE입니다.
[규칙]
- 반드시 call_web_agent(url)을 1회 호출하여 공식 URL 1개를 찾아주세요.
- 찾지 못하면 도구 결과 official_url이 None이 되도록 하세요.

[분석 URL] {norm}
완료되면 "done"이라고만 답하세요."""

		_run_phase(client, model, prompt_b, TOOLS_PHASE_B, phase_b_results, logs, log_callback, max_turns=3)

		web_res = phase_b_results.get("call_web_agent", {}) or {}

		# Phase B도 툴 호출 없이 끝낼 수 있으니 보강
		if not web_res:
			web_res = _call_tool("call_web_agent", {"url": norm}, logs, log_callback)

	final = _make_response(norm, db_res, ml_res, sim_res, web_res)

	log_msg = "피싱 URL로 판정되었습니다." if final["risk_level"] == "high" else "안전한 URL로 판정되었습니다."
	_push_log(logs, {"step": "판정", "url": norm, "risk_level": final["risk_level"], "message": log_msg}, log_callback)

	return {"label": 1 if final["risk_level"] == "high" else 0, **final}


def run_orchestrator(user_input, log_callback=None):
	logs = []

	_push_log(logs, {"step": "입력", "message": "입력을 수신했습니다."}, log_callback)

	urls = extract_urls_from_text(user_input, max_urls=10)
	_push_log(logs, {"step": "URL 추출", "message": f"추출된 URL 개수: {len(urls)}", "urls": urls}, log_callback)

	if not urls:
		_push_log(logs, {"step": "일반 질의", "message": "URL이 없어 일반 질의로 처리합니다."}, log_callback)
		client = get_openai_client()
		model = get_model_name()
		resp = client.responses.create(
			model=model,
			instructions="You are a helpful assistant. Answer in Korean unless the user asks otherwise.",
			input=user_input
		)
		_push_log(logs, {"step": "완료", "message": "일반 응답 완료", "risk_level": "medium"}, log_callback)
		return {"response": (resp.output_text or "").strip(), "risk_level": "medium", "logs": logs}

	results = []
	for i, u in enumerate(urls, 1):
		results.append(_classify_one(u, logs, log_callback, i, len(urls)))

	overall = "high" if any(r["risk_level"] == "high" for r in results) else "low"
	_push_log(logs, {"step": "종합", "message": f"종합 위험도: {overall}", "risk_level": overall}, log_callback)

	if len(results) == 1:
		blocks = [results[0]["text"]]
	else:
		blocks = [f"**URL {i}**\n{r['text']}" for i, r in enumerate(results, 1)]

	_push_log(logs, {"step": "완료", "message": "전체 분석 완료", "risk_level": overall}, log_callback)
	return {"response": "\n\n---\n\n".join(blocks), "risk_level": overall, "logs": logs}
