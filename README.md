# Actionability Suricata v2.2.2

Một phòng lab có thể tái lập để chạy Suricata trên PCAP, tương quan các EVE event và đánh giá riêng:

- **Actionability Score**: cảnh báo có đủ ngữ cảnh/bằng chứng để analyst hành động hay chưa.
- **Risk Score**: mức độ nghiêm trọng và khả năng hoạt động đã thành công.
- **Outcome confidence**: bằng chứng về kết quả của request mạnh đến đâu.

> Đây là công cụ nghiên cứu/demo chạy offline, không phải IDS production và các điểm số không phải xác suất bị xâm nhập.

## Các khả năng chính

1. Tương quan `alert`, `http` và `flow` bằng `flow_id` + `tx_id`.
2. Giữ nguyên IP nguồn/đích của packet nhưng bổ sung `client/server`, `to_server/to_client` và attacker/victim candidate.
3. Tách Actionability Score khỏi Risk Score; HTTP 403 có bằng chứng kết quả mạnh nhưng likelihood thấp.
4. Phân biệt `missing` với `not_applicable`, ví dụ rule scan chung không bị trừ điểm vì không có CVE.
5. Metadata được kiểm tra kiểu dữ liệu, SID/revision, severity, MITRE ID và HTTP status.
6. Response guidance được chấm theo các phase `validate`, `scope`, `contain` và bằng chứng liên quan, không theo số câu.
7. Ghi CSV/JSONL theo streaming, tạo `summary.json`, báo malformed JSON và chất lượng SID lookup.
8. Có ground truth, regression test và GitHub Actions.
9. Mỗi record JSONL có `score_breakdown`, gồm điểm, trọng số và contribution của từng tiêu chí.
10. Thí nghiệm hậu cảnh báo tạo 500 presentation từ 10 seed Suricata, 5 bối cảnh outcome và 10 hồ sơ evidence.
11. Ghi riêng `seed_id`, `base_context_id` và `presentation_id` để không xem các biến thể là alert độc lập.
12. Sinh bảng, ablation, weight sensitivity và biểu đồ PNG/PDF theo cả hai trục thực nghiệm.
13. Tạo gói chấm mù cân bằng 300 presentation, ba rating slot mỗi mẫu, theo tiêu chí outline nghiên cứu.
14. Có adapter AIT-ADS và công cụ gom alert lặp thành archetype để tránh pseudo-replication.

## Bổ sung kiểm chứng cho paper

Bản bổ sung chuẩn bị pilot **3 người × cùng 30 mục**, chạy thêm **shaw, wardbeck,
santos** cùng cấu hình với russellmitchell, và đo wall time / CPU time / peak RSS
qua các process độc lập. Rating của con người vẫn để trống, cần thu thập thật.

- Kết quả: [paper_extension_results_vi.md](docs/paper_extension_results_vi.md).
- Tái lập và phân tích rating: [paper_extension_reproduction.md](docs/paper_extension_reproduction.md).
- Hướng dẫn người chấm: [human30_protocol_vi.md](docs/human30_protocol_vi.md).
- Công cụ mới: `as_engine.human_study`, `as_engine.external_validation`, `as_engine.benchmark`.
- Đo riêng quá trình tạo 500 presentation: `python scripts/benchmark_controlled.py`.

## Pipeline

```text
Synthetic HTTP scenarios
  -> Scapy PCAP
  -> Suricata 7 offline + improved.rules
  -> eve.json
  -> flow/HTTP correlation
  -> SID metadata enrichment
  -> evidence extraction
  -> Actionability + Risk scoring
  -> CSV + JSONL + summary
  -> ground-truth validation
  -> controlled post-alert presentations
  -> blinded analyst annotation pack
```

## Chạy nhanh bằng Docker

Yêu cầu: Docker, Docker Compose và `jq`.

Các script tự truyền UID/GID hiện tại vào container. Vì vậy PCAP, log, bảng và
figure sinh trên bind mount sẽ thuộc người chạy lệnh thay vì `root`.

```bash
./scripts/run_all.sh
```

Nếu đã từng chạy một bản cũ và Git báo `Permission denied` với file trong
`runs/`, sửa quyền một lần trước khi chạy lại:

```bash
sudo chown -R "$(id -u):$(id -g)" runs logs/suricata pcaps
sudo chmod -R u+rwX runs logs/suricata pcaps
```

Pipeline sẽ:

1. Build image tạo PCAP và image scoring.
2. Tạo `pcaps/generated_official_payloads.pcap`.
3. Chạy Suricata offline.
4. Chấm điểm cảnh báo.
5. Đối chiếu kết quả với ground truth.
6. Chạy thí nghiệm 500 presentation và sinh bảng/biểu đồ thực nghiệm.
7. Chuẩn bị 300 mẫu chấm mù với 900 dòng rating trống.

Kết quả:

```text
logs/suricata/eve.json
runs/improved/scores.jsonl
runs/improved/scores.csv
runs/improved/summary.json
runs/experiments/controlled/experiment_summary.json
runs/experiments/controlled/figures/
runs/experiments/controlled/annotation/
```

Xem bảng rút gọn:

```bash
./scripts/show_results.sh
```

Giải thích một alert theo từng tiêu chí (có thể dùng một trong hai lệnh):

```bash
./scripts/show_results.sh 2025756
./scripts/explain_alert.sh 2025756
```

Output trình bày riêng `score`, `weight` và `contribution`. Ví dụ,
`investigation_evidence = 0.68`, trọng số `0.25`, nên đóng góp `0.17` vào
Actionability Score. Các evidence còn thiếu được liệt kê ngay trên cùng hàng.

## Chạy riêng scoring engine không cần Docker

Repo đã chứa một `eve.json` mẫu để kiểm thử:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

PYTHONPATH=src python -m as_engine.cli \
  --eve logs/suricata/eve.json \
  --rules rules/rule_metadata.yaml \
  --scoring config/scoring-v2.yaml \
  --out-jsonl runs/improved/scores.jsonl \
  --out-csv runs/improved/scores.csv \
  --out-summary runs/improved/summary.json \
  --fail-on-malformed
```

Chọn profile khác:

```bash
PYTHONPATH=src python -m as_engine.cli \
  --eve logs/suricata/eve.json \
  --rules rules/rule_metadata.yaml \
  --scoring config/scoring-v2.yaml \
  --profile equal_weight \
  --out-jsonl /tmp/scores.jsonl \
  --out-csv /tmp/scores.csv \
  --out-summary /tmp/summary.json
```

## Công thức đề xuất mặc định

Actionability:

```text
0.25 * entity_completeness
+ 0.20 * attack_context
+ 0.15 * outcome_evidence
+ 0.25 * investigation_evidence
+ 0.15 * recommended_response
```

Risk:

```text
0.60 * severity_impact
+ 0.40 * outcome_likelihood
```

Profile mặc định có tên `proposed_default`. Tên này nhấn mạnh rằng trọng số là
giả thuyết nghiên cứu minh bạch, chưa phải trọng số học từ đánh giá của analyst.
Các trọng số và threshold nằm trong `config/scoring-v2.yaml`.

## Thí nghiệm hậu cảnh báo có kiểm soát

Chạy bằng Docker nếu Docker Compose khả dụng; nếu không, script dùng Python hiện tại:

```bash
pip install -r requirements-experiments.txt
./scripts/run_experiments.sh
```

Thiết kế là phép lai hai yếu tố, áp dụng sau khi Suricata đã phát alert:

```text
10 observed Suricata seeds
x 5 controlled outcome contexts
= 50 base-context vignettes

50 base-context vignettes
x 10 evidence profiles
= 500 alert presentations
```

Năm context gồm kết quả quan sát được, HTTP 200 kèm success marker, HTTP 200 kèm
failure marker, HTTP 403 và HTTP 302. Mười evidence profile gồm evidence gốc,
evidence đầy đủ, các ablation theo trường, thiếu metadata và alert tối thiểu.
Hai trục được khai báo riêng trong `config/context_variants.yaml` và
`config/controlled_variants.yaml`.

Ba định danh bắt buộc ngăn diễn giải sai đơn vị:

- `seed_id`: một trong 10 alert Suricata quan sát được.
- `base_context_id`: một trong 50 vignette seed--outcome.
- `presentation_id`: một trong 500 cách trình bày bằng chứng cho analyst.

Kết quả được ghi tại:

```text
runs/experiments/controlled/
  controlled_cases.csv
  controlled_cases.jsonl
  variant_summary.csv
  context_summary.csv
  context_profile_summary.csv
  comparators.csv
  ablation.csv
  sensitivity.csv
  experiment_summary.json
  annotation/annotation_items.csv
  annotation/annotation_items.jsonl
  annotation/annotation_key.csv
  annotation/annotation_responses_template.csv
  annotation/annotation_summary.json
  figures/*.png
  figures/*.pdf
```

Ranh giới diễn giải được lưu ngay trong `experiment_summary.json`: 500 presentation
không phải 500 cuộc tấn công, 500 production alert hay 500 đánh giá của analyst.
Chúng kiểm tra hành vi của pipeline và công thức trong một thiết kế có kiểm soát.
Mười EVE seed vẫn là đơn vị quan sát kỹ thuật ban đầu.

Kết quả theo evidence profile:

| Evidence profile | Số presentation | Actionability trung bình | Risk trung bình |
|---|---:|---:|---:|
| Complete evidence | 50 | 0.970 | 0.573 |
| Native evidence | 50 | 0.930 | 0.573 |
| No Community ID | 50 | 0.940 | 0.573 |
| No payload | 50 | 0.896 | 0.589 |
| No flow identity | 50 | 0.8725 | 0.573 |
| No role resolution | 50 | 0.820 | 0.573 |
| No outcome evidence | 50 | 0.770 | 0.525 |
| Unknown SID metadata | 50 | 0.676 | 0.739 |
| No HTTP context | 50 | 0.6225 | 0.525 |
| Minimal alert | 50 | 0.105 | 0.675 |

Toàn bộ 500 presentation có Actionability trung bình `0.7602`, khoảng
`0.105--1.000`. Risk trung bình là `0.5918`, khoảng `0.340--0.840`. Outcome gồm
110 `possibly_successful`, 50 `success_evidenced`, 120 `failure_evidenced` và
220 `unknown`. Failure marker được ưu tiên hơn HTTP 200, nên trang lỗi tùy chỉnh
không bị hiểu nhầm là dấu hiệu thành công.

Phân tích ablation dùng `complete` làm đối chứng. Mức giảm Actionability trung
bình lớn nhất là thiếu HTTP context (`0.3475`), thiếu metadata (`0.2940`) và
thiếu outcome (`0.2000`). Khi tăng hoặc giảm riêng một trọng số 10--30%, Kendall
tau-b nhỏ nhất là `0.940671`; top-20% overlap nhỏ nhất là `0.90`. Đây chỉ là
robustness nội tại trên các presentation có kiểm soát.

So với hai baseline minh bạch, Kendall tau-b là `0.910370` cho equal-weight và
`0.808418` cho đếm field. Top-20% overlap lần lượt là `1.00` và `0.53`. Các số
này chỉ mô tả mức khác nhau giữa công thức; chưa chứng minh công thức nào phù hợp
với analyst hơn khi chưa có rating độc lập.

### Gói đánh giá analyst

Mỗi lần chạy thí nghiệm, pipeline lấy mẫu xác định 300/500 presentation. Mẫu cân
bằng chính xác: 60 mẫu cho mỗi outcome context, 30 mẫu cho mỗi evidence profile,
6 mẫu cho mỗi ô context--profile và 30 mẫu cho mỗi SID. File analyst nhìn thấy
không chứa automated score, profile hay outcome label. `annotation_key.csv` phải
được giữ kín đến khi đóng băng toàn bộ rating.

Ba rating slot cho mỗi mẫu tạo 900 dòng trống. Các tiêu chí gồm Likert 1--5,
actionable/non-actionable/unsure, hiểu event, hiểu outcome, biết next action, cần
pivot ngoài, next action tự do, confidence và decision time. Chi tiết nằm trong
`docs/annotation_protocol.md`. Gói trống này là giao thức nghiên cứu, không phải
bằng chứng rằng nghiên cứu analyst đã hoàn tất.

Sau khi rating đã hoàn tất và được đóng băng, chạy analyzer:

```bash
PYTHONPATH=src python -m as_engine.annotation_analysis \
  --key runs/experiments/controlled/annotation/annotation_key.csv \
  --responses /path/to/frozen_annotation_responses.csv \
  --output runs/experiments/controlled/annotation/annotation_analysis.json
```

Analyzer kiểm tra schema, tính Krippendorff alpha, Fleiss kappa, AUPRC cho ba
phương án scoring và confidence interval bằng bootstrap theo `seed_id`. Template
đang để trống có chủ đích; repo không kèm kết quả analyst giả lập.

## Dữ liệu ngoài AIT-ADS và alert archetype

Repo không kèm AIT-ADS. Tải dữ liệu và label từ Zenodo theo hướng dẫn chính thức,
sau đó chạy một scenario:

```bash
./scripts/import_ait_ads.sh \
  russellmitchell \
  /path/to/russellmitchell_wazuh.json \
  /path/to/russellmitchell_alerts.txt
```

`labels.csv` ở gốc bản phát hành Zenodo chỉ chứa khoảng thời gian của phase và
không phải đối số thứ ba ở trên. Hãy dùng file per-alert
`alerts_csv/<scenario>_alerts.txt` từ repository phân tích chính thức. Kết quả
pilot có nhãn cho `russellmitchell`, checksum nguồn và ranh giới diễn giải nằm
trong `docs/ait_ads_pilot.md`. Bản tóm tắt thay đổi đối với paper nằm trong
`docs/paper_revision_summary_vi.md`.

Nếu chưa có file label, bỏ đối số thứ ba. Adapter chỉ lấy record có prefix
`Suricata:` trong Wazuh export, bảo toàn các trường bị thiếu và không tự tạo
`flow_id`, `tx_id`, payload hoặc outcome. SID không có trong catalog được ghi là
`unknown_sid`, không được gắn metadata giả.

Mặc định, script lấy mẫu cân bằng 25% số archetype. Có thể đổi tỷ lệ:

```bash
AIT_SAMPLE_FRACTION=0.30 ./scripts/import_ait_ads.sh \
  fox /path/to/fox_wazuh.json /path/to/fox_alerts.txt
```

Archetype được định nghĩa bằng dataset, scenario, label, SID/signature, protocol,
direction, outcome class và missing-evidence profile. Raw alert count chỉ dùng
mô tả tần suất; phân tích thống kê nên dùng archetype, flow hoặc incident độc lập.

### Outcome được biểu diễn thế nào?

| Trạng thái | Outcome evidence | Outcome likelihood |
|---|---:|---:|
| Payload chứa configured success marker | 1.00 | 0.90 |
| Payload chứa configured failure marker | 1.00 | 0.10 |
| HTTP 400/401/403/404/500 | 1.00 | 0.10 |
| HTTP 200/201/202 | 0.60 | 0.60 |
| Status không quyết định | 0.40 | 0.40 |
| Không có outcome | 0.00 | 0.30 |

HTTP 200 chỉ được ghi là `possibly_successful`; nó không chứng minh exploit đã thành công.

## Packet direction và attribution

Các rule response-side có thể tạo alert trên packet từ server về client. Vì vậy v2 xuất cả hai nhóm trường:

```text
packet_src_ip / packet_dest_ip     # đúng chiều packet tạo alert
client_ip / server_ip              # vai trò đã tương quan theo flow
alert_direction                    # to_server, to_client, unknown
attacker_candidate / victim_candidate
attribution_confidence             # high, medium, unknown
```

`attacker_candidate` là giả thuyết từ metadata rule, không phải kết luận pháp y.

## Metadata v2

`rules/rule_metadata.yaml` hỗ trợ:

```yaml
cve_applicable: false
mitre_applicable: true
attacker_role: client

recommended_actions:
  - phase: validate
    action: "Inspect the request."
    evidence: ["http.url", "payload_printable"]
```

SID lookup có ba kết quả chính:

- `exact`: SID và revision khớp.
- `sid_fallback`: SID khớp nhưng revision lệch; output luôn có warning.
- `unknown_sid`: không có metadata.

## Kiểm thử

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Kiểm tra output bằng ground truth:

```bash
PYTHONPATH=src python -m as_engine.validation \
  --scores runs/improved/scores.csv \
  --truth config/ground_truth.yaml
```

Regression suite hiện có 15 test, kiểm tra:

- Response-side alert không đảo attacker/victim.
- Correlation vẫn hoạt động khi flow event xuất hiện sau alert.
- Port heuristic khi EVE thiếu flow event.
- SID exact/fallback/unknown.
- Metadata lỗi bị từ chối.
- CVE không áp dụng không làm giảm điểm.
- Failure có evidence cao nhưng likelihood thấp.
- Toàn bộ 10 alert mẫu khớp ground truth.
- Score breakdown cộng lại đúng tổng điểm.
- Phép lai 10 x 5 x 10 tạo đúng 500 presentation.
- Failure/success marker ưu tiên hơn suy luận chỉ dựa trên HTTP status.
- Lấy mẫu chấm mù 300 item cân bằng, xác định theo seed và không lộ score.
- Phân tích agreement, AUPRC và bootstrap theo cluster trên rating hoàn chỉnh.
- Chuyển đổi Wazuh-embedded Suricata từ AIT-ADS mà không tạo evidence giả.
- Gom alert lặp thành archetype và lấy mẫu xác định bằng seed.
- Không chấp nhận figure PNG/PDF rỗng hoặc sai signature khi tái tạo artifact.

## Cấu trúc chính

```text
config/
  scoring-v2.yaml       scoring profiles và thresholds
  ground_truth.yaml     kết quả mong đợi cho fixture
  context_variants.yaml     5 bối cảnh outcome
  controlled_variants.yaml  10 hồ sơ evidence
docs/
  annotation_protocol.md    hướng dẫn chấm mù và ranh giới claim
rules/
  improved.rules        tập con rule HTTP upstream
  rule_metadata.yaml    metadata và response playbook
src/as_engine/
  parser.py             EVE correlation + role normalization
  rule_catalog.py       metadata validation và SID lookup
  evidence.py           evidence extraction
  scoring.py            Actionability/Risk scoring
  cli.py                streaming output + summary
  validation.py         ground-truth validator
  explain.py            giải thích score theo từng contribution
  experiment.py         controlled variants, ablation, sensitivity, figures
  annotation.py         balanced blinded sample và rating templates
  annotation_analysis.py agreement, criterion validity và grouped bootstrap
  ait_ads.py            adapter AIT-ADS sang EVE-like JSONL
  archetypes.py         aggregation và balanced sampling
tests/                   unit và regression tests
runs/experiments/        kết quả và biểu đồ thực nghiệm
```

## Giới hạn còn lại

- PCAP demo vẫn là traffic tổng hợp, không đại diện đầy đủ traffic thực tế.
- Attribution chỉ là candidate dựa trên vai trò protocol và metadata rule.
- HTTP status không đủ để xác nhận compromise; production cần application, endpoint và identity telemetry.
- Parser hiện tối ưu cho HTTP; protocol khác cần extractor riêng.
- Bộ rule là tập con upstream. Xem `THIRD_PARTY_NOTICES.md` trước khi phân phối tiếp.
- Controlled variants kiểm tra tính nhạy của scoring, không thay thế external validation hoặc analyst study.
- AIT-ADS Wazuh export có thể không chứa raw EVE flow/HTTP evidence; cần báo cáo field coverage khi sử dụng.

## Nguồn rule

`rules/improved.rules` là tập con HTTP từ:

```text
https://github.com/Koen1999/ruling-the-unruly
```

Script `scripts/fetch_full_upstream_rules.sh` có thể tải bản đầy đủ, nhưng bản đầy đủ chứa rule phụ thuộc Lua và không được load mặc định.
