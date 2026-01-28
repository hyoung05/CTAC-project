
# Web Search

### 피싱이라 판단된 URL의 대칭되는 공식 URL을 찾기위한 OPENAPI Web Search 호스팅 툴을 이용한 검색 처리

### 프롬프트
	` prompt = (
		"다음 URL이 피싱으로 의심됩니다. 사용자에게 안내할 수 있도록,\n"
		"가장 공식적인(공식 홈페이지로 보이는) 대체 URL을 1개만 찾아주세요.\n"
		"답변은 URL 1개만 출력하세요.\n"
		"찾지 못하면 'NONE'만 출력하세요.\n\n"
		f"의심 URL: {query_url}"
	) `


  
  
