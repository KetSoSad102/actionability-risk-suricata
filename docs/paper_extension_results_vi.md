# Bổ sung thực nghiệm cho Actionability Suricata

Đã thực hiện kiểm tra thêm ba scenario AIT-ADS và đo chi phí thực tế. Nghiên cứu với người đọc alert mới hoàn tất khâu chuẩn bị; chưa có rating thật nên chưa thể kết luận score phù hợp với đánh giá của con người.

## 1. Pilot với ba người đọc alert

Bộ chấm gồm cùng 30 presentation cho ba người: 90 dòng rating trống, thứ tự riêng cho mỗi người, trang HTML đọc alert và giao thức tiếng Việt. Bộ mẫu cân bằng 3 mục/seed, 3 mục/evidence profile, 6 mục/outcome context, gồm 30 base context khác nhau. Chỉ bao phủ 30/50 ô context–profile; đây là pilot có kiểm soát từ 10 seed, không phải 30 sự cố độc lập.

Analyzer yêu cầu đúng ba người, mỗi người chấm toàn bộ 30 mục. Phân tích chính: Spearman giữa actionability và median Likert, CI 95% với 2.000 bootstrap theo seed_id. Báo cáo thêm alpha ordinal, Fleiss kappa, và AUPRC theo majority class. Ordinal alpha đã được sửa để dùng khoảng cách dựa trên tần suất category; tương quan không xác định trả về null trong công cụ pilot. Các trường flow_id, tx_id và Community ID được hiển thị để analyst nhìn thấy các loại evidence mà công thức chấm.

**Việc cần dữ liệu thật:** tuyển ba người có kinh nghiệm, ghi hồ sơ kinh nghiệm, cho chấm độc lập, đóng băng ba file responses.csv rồi chạy analyzer. Không có kết quả human agreement hoặc correlation được tạo giả.

## 2. Kiểm tra phụ thuộc scenario

Chọn shaw, wardbeck và santos trước khi xem score, theo ba Wazuh export nhỏ nhất còn lại; giữ russellmitchell làm đối chiếu. Cả bốn dùng nguyên scoring-v2.yaml, rule_metadata.yaml, proposed_default và cùng adapter. Không bổ sung metadata để cải thiện riêng scenario nào. Hash cấu hình và đầu vào nằm trong manifest.json.

| Scenario | Alert | Archetype | Mean A theo archetype | Role resolved | HTTP context | Outcome quyết định | SID metadata |
|---|---:|---:|---:|---:|---:|---:|---:|
| russellmitchell | 9,186 | 31 | 0.3709 | 99.37% | 3.88% | 0.39% | 0.29% |
| shaw | 16,692 | 19 | 0.3749 | 99.14% | 3.12% | 0.00% | 0.00% |
| wardbeck | 24,510 | 42 | 0.3593 | 99.39% | 1.91% | 0.03% | 0.04% |
| santos | 44,112 | 58 | 0.3677 | 41.38% | 0.88% | 0.03% | 0.03% |

Tổng 94,500 alert, 150 archetype theo định nghĩa chứa scenario. Các tỷ lệ coverage dùng mẫu số raw alert; mean A cho mỗi scenario cho mỗi archetype trọng số bằng nhau. Trung bình macro theo scenario là 0.3682. Khi bỏ từng scenario, macro mean còn lại dao động 0.3660–0.3712.

Riêng santos chỉ có 41,38% alert phân giải được role, so với hơn 99% ở ba scenario còn lại. Vì vậy mean actionability gần nhau có thể che khuất khác biệt về coverage; kết quả hỗ trợ sự ổn định mô tả của mean trên bốn tập đã chọn, không hỗ trợ khẳng định mọi thành phần đều ổn định.

**Diễn giải:** xem khoảng biến thiên thực tế và coverage để đánh giá độ ổn định. Đây là kiểm tra mô tả trên bốn scenario đã chọn, không phải kiểm định tương đương hoặc bằng chứng khái quát cho mọi scenario. Archetype giảm ảnh hưởng alert lặp nhưng không đảm bảo độc lập. Nhãn là time-phase join, không phải ground truth xác minh tấn công cho từng alert; actionability không phải điểm phân loại maliciousness.

## 3. Chi phí xử lý offline

Đơn vị: giây và MiB. Mỗi stage có một lần warmup và năm lần đo trong process mới. Bảng ghi median; thời gian scoring có thêm min–max. Peak RSS là high-water mark của hệ điều hành cho process con, bao gồm Python runtime. Không xóa disk cache giữa các lần.

| Scenario | Adapter (s) | Scoring median [min–max] (s) | Gom archetype (s) | Alert/s scoring | Peak RSS scoring (MiB) |
|---|---:|---:|---:|---:|---:|
| russellmitchell | 0.932 | 3.047 [2.995–3.357] | 0.458 | 3,015 | 25.72 |
| shaw | 1.275 | 5.253 [5.231–5.381] | 0.662 | 3,178 | 25.88 |
| wardbeck | 1.662 | 7.864 [7.577–8.096] | 0.916 | 3,117 | 25.87 |
| santos | 2.515 | 57.644 [14.653–72.414] | 8.416 | 765 | 25.96 |

Fixture EVE 10 alert: scoring median 1.152 s, peak RSS median 25.39 MiB. Tạo 500 controlled presentation cùng bảng/sensitivity/gói annotation, không vẽ figure: median 1.301 s, peak RSS median 32.81 MiB. Chi phí tạo thí nghiệm không phải throughput chấm 500 alert độc lập.

Môi trường: Windows-10-10.0.26100-SP0; Python 3.11.9; Intel64 Family 6 Model 186 Stepping 2, GenuineIntel; 10 nhân vật lý/16 CPU logic; RAM 15.71 GiB. Thời gian phụ thuộc máy, trạng thái cache, tải hệ thống và nội dung dữ liệu; không dùng một con số throughput để suy ra tuyến tính cho mọi tập.

Wall time bao gồm khởi động process, đọc và ghi kết quả. CPU time, từng lần đo, peak memory của adapter và aggregation đều được lưu trong benchmark.json. Đây là chi phí pipeline offline sau khi đã có alert; chưa đo Suricata phát hiện traffic, vận hành SOC liên tục, retention dài hạn, công lao động analyst hoặc tiền thuê máy. Không cộng RSS các stage tuần tự; tổng median thời gian các stage cũng không phải latency end-to-end đo trực tiếp.

## Đo kiểm tra lại: giữ riêng hai lượt

Lượt đầu dao động mạnh ở santos, nên thực hiện một lượt kiểm tra lại cho cả bốn scenario với cùng giao thức. Hai lượt được giữ nguyên, không loại bỏ lượt chậm hoặc gộp thành một con số duy nhất. Máy cá nhân không được kiểm soát tải nền, trạng thái năng lượng hay nhiệt độ; không thể quy toàn bộ chênh lệch tốc độ cho scenario. Các số đo này là quan sát trên máy hiện tại, chưa phải benchmark hiệu năng production đã kiểm soát.

| Scenario | Lượt đầu scoring median (s) | Kiểm tra lại median [min–max] (s) | Kiểm tra lại RSS median (MiB) |
|---|---:|---:|---:|
| russellmitchell | 3.047 | 10.045 [9.831–10.528] | 24.82 |
| shaw | 5.253 | 17.624 [16.053–18.093] | 24.83 |
| wardbeck | 7.864 | 28.492 [26.833–33.034] | 25.04 |
| santos | 57.644 | 55.974 [16.734–62.989] | 24.95 |

Lượt đầu: runs/paper_extension/external. Lượt kiểm tra lại: runs/paper_extension/external_recheck. Kiểm tra hash và số liệu giữa các lượt được lưu trong verification.json.

## Cách dùng và nguồn

Xem docs/paper_extension_reproduction.md để tái lập; docs/human30_protocol_vi.md để tổ chức chấm. Chỉ phát thư mục rater_N cho người chấm, giữ coordinator riêng. File test_results.txt ghi kết quả kiểm thử.

[AIT-ADS trên Zenodo](https://zenodo.org/records/8263181), archive MD5 `43db6b1f0996e0024befd617706c50e9`. [Repository nhãn chính thức](https://github.com/ait-aecid/alert-data-set), commit `ce927ddaeaa674f6909e1de676fa7dc293e393bd`; các file nhãn nằm trong `alerts_csv/alerts_csv.zip`. Các input được tải và kiểm tra trước khi đo. Không tái tạo lưu lượng tấn công.

## Đoạn tiếng Anh để đưa vào paper

We extended the offline evaluation from russellmitchell to shaw, wardbeck, and santos while retaining the same scoring configuration and metadata catalog. Across the four scenarios, 94,500 Suricata alerts were aggregated into 150 scenario-specific archetypes. Scenario-level mean actionability ranged from 0.3593 to 0.3749. These descriptive results characterize evidence readiness under the available Wazuh export; they do not establish classifier performance, statistical equivalence across scenarios, or agreement with human analysts. We also measured offline adaptation, scoring and aggregation using one warmup and five fresh-process repetitions per stage, recording wall time, CPU time and OS peak resident memory. A separate blinded 30-item, three-rater pilot has been prepared; human criterion validity remains unassessed pending completion of the independent ratings.
