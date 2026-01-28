import re
from typing import Any, Callable, Dict, List, Optional

from utils import _push_log, get_model_name, get_openai_client


def call_web_agent(
	query_url: str,
	logs: Optional[List[Dict[str, Any]]] = None,
	log_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None
) -> Optional[str]:
	if logs is not None:
		_push_log(logs, {"step": "web_search", "message": "공식 URL 1개를 검색합니다.", "url": query_url}, log_callback)

	client = get_openai_client()
	model = get_model_name()

	prompt = (
		"다음 URL이 피싱으로 의심됩니다. 사용자에게 안내할 수 있도록,\n"
		"가장 공식적인(공식 홈페이지로 보이는) 대체 URL을 1개만 찾아주세요.\n"
		"답변은 URL 1개만 출력하세요.\n"
		"찾지 못하면 'NONE'만 출력하세요.\n\n"
		f"의심 URL: {query_url}"
	)

	resp = client.responses.create(
		model=model,
		tools=[{"type": "web_search"}],
		input=prompt
	)

	text = (resp.output_text or "").strip()
	if not text or text.upper() == "NONE":
		if logs is not None:
			_push_log(logs, {"step": "web_search", "message": "공식 URL을 찾지 못했습니다.", "result": "NONE"}, log_callback)
		return None

	m = re.search(r"(https?://\S+)", text)
	if m:
		url = m.group(1).strip().rstrip(").,;\"'")
		if logs is not None:
			_push_log(logs, {"step": "web_search", "message": "공식 URL 후보를 찾았습니다.", "result": url}, log_callback)
		return url

	if logs is not None:
		_push_log(logs, {"step": "web_search", "message": "응답에서 URL을 추출하지 못했습니다.", "result": text[:200]}, log_callback)
	return None
