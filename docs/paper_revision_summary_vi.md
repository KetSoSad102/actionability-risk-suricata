# Tóm tắt cải thiện paper: AIT-ADS pilot

## Mục tiêu

Thực hiện góp ý của giảng viên: chạy adapter AIT-ADS trên một tập con có nhãn
và bổ sung một bảng kết quả nhỏ vào Section IV, thay vì mở rộng paper bằng một
analyst study chưa thể hoàn thành và kiểm chứng ngay.

## Thực nghiệm đã chạy

- Nguồn: AIT Alert Data Set, Zenodo record 8263181.
- Tập con: scenario `russellmitchell`, scenario nhỏ nhất trong tám scenario.
- Nhãn: file per-alert chính thức
  `alerts_csv/russellmitchell_alerts.txt`; không dùng nhầm `labels.csv` chứa
  khoảng thời gian phase.
- Đầu vào: 41.488 AIT-ADS source records.
- Alert Suricata được adapter giữ lại: 9.186; không có JSON lỗi hoặc SID thiếu.
- Đơn vị mô tả sau khi chống lặp: 31 deterministic archetype, gồm 18
  attack-phase và 13 false-positive archetype.
- Kết quả tổng: 99,4% alert phân giải được vai trò, 3,9% có HTTP context, 0,3%
  match catalog metadata; actionability trung bình theo archetype là 0,371.

Các tỷ lệ raw alert chỉ mô tả độ phủ trường. So sánh actionability dùng mỗi
archetype một trọng số để tránh coi hàng nghìn alert lặp là quan sát độc lập.
Actionability không được diễn giải như bộ phân loại attack/false positive.

## Cải thiện artifact

AIT-ADS phân phối alert Suricata bên trong `<scenario>_wazuh.json`; artifact chỉ
lọc các record có prefix `Suricata:`. Không có Wazuh server, agent, dependency
hoặc thành phần kiến trúc mới nào được thêm vào repo.

Lần chạy đầu phát hiện `flow_id` được AIT-ADS ghi dưới dạng chuỗi số nguyên có
hậu tố `.000000`. Adapter cũ dùng `int(string)` nên làm mất trường này. Bản sửa
dùng `Decimal` để chuyển đổi chính xác và từ chối giá trị không nguyên, kèm
regression test bảo vệ một flow ID lớn khỏi mất độ chính xác.

## Cải thiện paper

- Thêm đúng một subsection ngắn và Table V trong Section IV.
- Bảng báo cáo riêng attack phase, false positive và tổng theo số alert,
  archetype, role coverage, HTTP coverage, metadata coverage và actionability
  trung bình theo archetype.
- Giữ phần diễn giải ngắn và giới hạn claim ở adapter portability/evidence
  coverage, không tuyên bố detection hoặc classification performance.
- Cập nhật Threats to Validity: pilot mới chỉ dùng một trong tám scenario và
  catalog hiện chỉ phủ một trong 13 SID.
- Sửa các câu liên quan để không còn nói external validation hoàn toàn là
  future work; future work hiện là mở rộng sang bảy scenario còn lại.

## Kiểm tra

- 15/15 unit và regression test pass.
- Paper compile thành công, không có undefined reference hoặc duplicate label.
- PDF có 7 trang khi build bằng Tectonic 0.17.0.
- Table V nằm ngay sau tiêu đề subsection, không tràn cột; các hình và thứ tự
  Section IV vẫn được giữ nguyên.

## Việc tác giả còn phải xác nhận

- Điền tên, cơ quan và email trong author block; source hiện vẫn là placeholder.
- Xác nhận giới hạn trang chính thức của kỳ hội nghị. Comment đầu source ghi
  `<= 6 pages`, trong khi bản build hiện tại có 7 trang và PDF tác giả gửi ban
  đầu có 8 trang.
- Analyst validation vẫn là future work; không tạo rating giả.

Chi tiết nguồn, checksum, lệnh tái lập và ranh giới diễn giải nằm trong
`docs/ait_ads_pilot.md`.
