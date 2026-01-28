import re
from openai import OpenAI

def web_search(query_url: str):

	client = OpenAI(api_key=)
	model = 'gpt-5'

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
		return None

	m = re.search(r"(https?://\S+)", text)
	if m:
		url = m.group(1).strip().rstrip(").,;\"'")
		return url

	return None


if __name__ == "__main__":
	print(f'대칭되는 URL :{web_search('http://pks.ilogenis.com')}')
