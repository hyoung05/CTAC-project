
# DB Search

입력 URL을 URL DB를 통한 일치 검사

## 구성 파일


- **split_urls.ipynb**
  - 흩어져있는 URL들을 정상 / 비정상으로 분류
  - 분류된 URL을 각각의 csv로 변환

- **createdb.ipynb**
  - 전처리된 URL csv를 DB화

- **db_search.py**
  - 입력으로 들어온 URL 파싱
  - 각 DB에서 일치하는 URL 검색

