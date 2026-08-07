# idp-review-agent

Agent rà soát thiết kế kiến trúc hệ thống, chạy trên LangGraph. Đọc `catalog.yaml`
để dựng đồ thị phụ thuộc, chạy scanner tất định trên code và cấu hình, rồi dùng LLM
để diễn giải và xếp ưu tiên — kèm bộ benchmark đo xem model bắt được bao nhiêu lỗi.

## Chạy nhanh

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env                 # điền OPENAI_API_KEY và OPENAI_MODEL
pytest -q                            # 27 test, không cần mạng

python benchmark/run_eval.py --dataset smoke --no-llm      # đường cơ sở, offline
python benchmark/run_eval.py --dataset payment-system --runs 3   # đo model thật
```

## Hai repo, không phải một

| Repo | Nội dung | Vì sao tách |
|------|----------|-------------|
| `idp-review-agent` (repo này) | Engine: graph, client, scanner, eval runner | Code đổi liên tục |
| `idp-sample-services` | Data benchmark + ground truth | Pin được theo commit SHA |

Ground truth (`.idp-review/expected.yaml`) nằm **trong repo data**, không phải ở
đây. Nhãn mô tả đúng một ảnh chụp của data; để hai bên ở hai repo khác nhau thì
sớm muộn chúng lệch nhau và bạn đo sai mà không biết. Sửa một service và cập nhật
nhãn nằm trong cùng một commit.

Khai báo data trong `datasets.yaml`:

```yaml
- name: payment-system
  url: https://github.com/<user>/idp-sample-services.git
  ref: 670acc2         # commit SHA, KHÔNG phải "main"
```

Mỗi lần chạy eval đều in ra `PHIÊN BẢN` của data. Ghi số đó vào báo cáo cùng với
recall — hai lần đo trên hai phiên bản data khác nhau thì không so sánh được.

Dataset `smoke` (2 service, 9 lỗi) đi kèm engine để `pytest` và CI chạy được
offline. Nó chỉ kiểm tra engine chạy đúng, không dùng để đánh giá model.

## Đọc kết quả eval thế nào

Đây là phần quan trọng nhất của repo, nên đọc kỹ trước khi báo cáo con số nào.

```
DATASET  : payment-system
PHIÊN BẢN: 670acc2511ed

Recall tổng      : 67%
Cơ chế        Bắt/Tổng    Recall   Bỏ sót
graph_rule       4.0/4     100%   —
scanner          6.0/6     100%   —
llm              0.0/5       0%   D06, D07, D12, D13, D14
```

Kết quả trên chạy với `--no-llm`, tức là **không có model nào tham gia**, mà recall
tổng vẫn 67%. Nếu bạn chỉ báo cáo con số tổng, bạn đang báo cáo điểm của regex
scanner chứ không phải của model. Con số nói về chất lượng model chỉ nằm ở dòng
`llm`, và nó đo trên 5 lỗi mà tầng tất định cố ý không bắt được:

| Lỗi | Vì sao chỉ LLM bắt được |
|-----|--------------------------|
| D06 | Gọi HTTP không timeout — cần hiểu ngữ nghĩa lời gọi thư viện |
| D07 | Vòng retry vô hạn không backoff — cần hiểu luồng điều khiển |
| D12 | `curl … \| sh` trong Dockerfile — cần hiểu vì sao mẫu này nguy hiểm |
| D13 | `privileged: true` — viết được thành luật, nhưng cố ý để trống làm phép thử |
| D14 | Cấp 8 CPU cho một service — cần so sánh với nhu cầu thực tế |

Khi bạn viết thêm luật cho scanner, hãy **chuyển defect đó sang `detectable_by:
scanner`** trong `expected.yaml` của repo data. Nếu không, recall của LLM sẽ tăng
ảo vì nó được tính công cho thứ mà regex làm.

Ba chỉ số nữa cần nhìn cùng lúc:

- **Tỉ lệ bịa** — số finding bị node `verify` loại vì viện dẫn bằng chứng hoặc
  nguyên tắc không tồn tại, chia cho tổng số finding LLM sinh ra. Recall cao mà
  tỉ lệ bịa cao thì model đang đoán bừa và thỉnh thoảng đoán trúng.
- **Finding ngoài ground truth** — không đồng nghĩa với sai. Có thể là lỗi thật
  chưa được gán nhãn. Đọc tay rồi bổ sung vào `expected.yaml` nếu đúng.
- **Dao động giữa các lần chạy** — luôn chạy `--runs 3` trở lên. Nếu khoảng dao
  động rộng hơn mức cải thiện bạn đang đo thì bạn chưa đo được gì.

## Cấu trúc

```
src/idp_review/
  state.py              Evidence, Finding, ReviewState
  deps.py               Protocol cho mọi phụ thuộc ngoài (seam để test)
  graph.py              12 node LangGraph
  checkpoint.py         checkpointer có allowlist msgpack tường minh
  clients/
    openai_llm.py       LLMClient dùng strict json_schema
    prompts.py          prompt tách riêng để version qua git
    repo.py             đọc từ thư mục local hoặc clone từ git URL
    scanner.py          luật regex tất định (thay bằng semgrep/trivy khi lên prod)
    principles.py       nguyên tắc nội bộ từ YAML
    sink.py             ghi kết quả
benchmark/
  dataset.py            nạp data từ thư mục local hoặc git URL, pin theo SHA
  matcher.py            đối chiếu finding với ground truth (tất định, không dùng LLM judge)
  run_eval.py           chạy benchmark, in bảng recall
datasets.yaml           đăng ký dataset: tên -> path hoặc url + ref
principles/             nguyên tắc kiến trúc nội bộ, mỗi mục có id ổn định
tests/
  fixtures/smoke-system/   dataset nhỏ đi kèm để CI chạy offline
  test_review.py           27 test
```

## Nguyên tắc thiết kế

1. **Node tất định phát hiện, node LLM diễn giải.** Đồ thị `networkx` tìm SPOF
   (articulation point), chu trình gọi đồng bộ, shared database. Scanner tìm lỗi
   cấu hình. LLM chỉ nhận kết quả đó và xếp ưu tiên. Bắt LLM tự tìm lỗ hổng trong
   một đống code là công thức tạo hallucination nghe thuyết phục.

2. **Quyền chốt ở node đầu, hai mức tách biệt.** `scope` cho phép xem metadata
   (cần để tính blast radius), `code_readable` cho phép đọc source. Dev thấy
   service hàng xóm trên đồ thị nhưng không đọc được code của nó. Gộp hai mức làm
   một sẽ hoặc rò rỉ code, hoặc làm hỏng phân tích kiến trúc.

3. **Finding không neo được thì bị loại, không được sửa cho hợp lệ.** Node `verify`
   kiểm tra `evidence_ids` và `principle_ids` có thật không. Đây là cơ chế duy
   nhất khiến "agent trông đáng tin" trở thành "agent kiểm chứng được".

4. **Xếp ưu tiên bằng số học.** `priority = severity × (1 + blast_radius) ×
   confidence`. LLM chỉ đóng góp `severity` và `confidence`; `blast_radius` do
   `networkx.ancestors` tính. Cùng input phải cho cùng thứ tự.

5. **Mọi phụ thuộc ngoài đi qua `Deps`.** Không có seam này thì mọi test đều phải
   chạm mạng.

## Chạy trên repo thật

```bash
python benchmark/run_eval.py --url https://gitlab.corp/team/services.git --ref <sha>
```

Repo cần bố cục mỗi service một thư mục con có `catalog.yaml` ở gốc, và
`.idp-review/expected.yaml` nếu muốn đo recall. Không có ground truth thì engine
báo lỗi rõ ràng thay vì chạy rồi cho ra số vô nghĩa.

Repo được clone nông vào `.cache/datasets/` và tái dùng; thêm `--refresh` để
clone lại.

Khi lên production, thay `LocalRepoClient` bằng client gọi GitLab API **bằng chính
token OAuth của người dùng đang đăng nhập** — lúc đó GitLab tự thực thi quyền và
bạn không phải tự viết authz. Đây là lý do `RepoClient` nhận `token` ở mọi method.

## Việc còn phải làm

- Thay `RegexScanner` bằng `ProcessScanner` gọi semgrep / trivy / hadolint / kube-score.
- Thay `FilePrincipleStore` bằng vector DB **chỉ khi** tập nguyên tắc lớn tới mức
  keyword bắt đầu bỏ sót. Đừng thêm embedding vì nó nghe hiện đại hơn.
- Viết nguyên tắc biểu diễn được thành luật máy sang OPA/Conftest (Rego) thay vì
  để trong RAG. Luật tất định không bao giờ bịa.
- Thêm dataset thứ hai với hệ thống lớn hơn để kiểm tra khả năng mở rộng của
  vòng lặp thu thập bằng chứng. Mỗi dataset là một repo riêng, thêm một dòng vào
  `datasets.yaml`.
- `PostgresSaver(serde=make_serde())` thay `InMemorySaver` cho HITL kéo dài nhiều ngày.
