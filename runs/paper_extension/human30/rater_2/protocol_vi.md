# Giao thức pilot: ba người, cùng 30 mục

Trạng thái: chưa thu thập rating. Tuyệt đối không điền rating bằng mô hình hoặc suy ra từ score.

Người điều phối tuyển ba người đã thực sự đọc/triage alert. Ghi mã R1–R3, số năm kinh nghiệm, tần suất đọc alert, công cụ từng dùng và quan hệ với tác giả trong hồ sơ riêng. Báo cáo tiêu chí tuyển và kinh nghiệm thực tế; không tự gọi họ là chuyên gia nếu chưa xác minh.

Chỉ gửi thư mục rater tương ứng và hướng dẫn này cho từng người. Không gửi coordinator, source code, paper có công thức, score hay annotation key. Ba người làm độc lập, không trao đổi trước khi nộp. Cùng 30 mục nhưng thứ tự khác nhau. Có thể hướng dẫn thử bằng một ví dụ không thuộc bộ 30 trước khi bắt đầu.

Định nghĩa actionability: mức độ bằng chứng hiện có giúp xác định một bước xử lý tiếp theo cụ thể, hợp lý và có thể thực hiện. Không chấm mức độ nguy hiểm hoặc khả năng alert là tấn công. Việc cần xác minh thêm vẫn có thể là một next action; không tự suy ra rằng HTTP 200 chứng minh thành công.

Mở items.html bằng trình duyệt, rồi điền responses.csv theo item_id; giữ nguyên item_id và rater_slot. Dùng một rater_id cố định cho tất cả 30 dòng. Các chuỗi lựa chọn phải đúng như bên dưới. Nếu mở bằng Excel, giữ item_id ở dạng text và lưu CSV UTF-8.

- actionability_likert_1_5: 1 = chưa biết làm gì; 2 = chỉ có hướng chung, thiếu nhiều dữ kiện; 3 = có bước tiếp theo nhưng cần pivot đáng kể; 4 = bước tiếp theo cụ thể, chỉ cần xác minh hạn chế; 5 = bằng chứng đủ rõ để thực hiện bước tiếp theo có căn cứ.
- actionability_class: actionable / non_actionable / unsure. Chọn theo đánh giá của bạn, không bắt buộc chuyển từ Likert theo ngưỡng.
- understands_event_1_5, understands_outcome_1_5, knows_next_action_1_5: 1 = hoàn toàn không rõ, 5 = rất rõ; 2–4 biểu thị mức trung gian. Outcome không được ghi nhận có thể là lý do chấm thấp về độ rõ của outcome.
- additional_pivot_required: yes / no / unsure; có cần tìm dữ liệu ngoài phần được cung cấp để quyết định bước tiếp theo không?
- proposed_next_action: viết ngắn bước xử lý cụ thể, hoặc lý do chưa thể quyết định. Không thực thi hành động trên hệ thống thật.
- confidence_1_5: độ tự tin vào đánh giá, từ 1 đến 5.
- decision_seconds: số giây thực tế từ bắt đầu đọc mục đến chốt đánh giá, không tính thời gian nghỉ; số hữu hạn lớn hơn 0.
- comments: tùy chọn, ghi điểm mơ hồ và gián đoạn.

Mỗi người chấm cả 30 mục. Người điều phối chỉ kiểm tra thiếu trường/giá trị sai, không sửa nội dung thay người chấm. Đóng băng ba file, ghi ngày nhận và checksum trước khi mở key. Không thay mục hoặc điều chỉnh trọng số sau khi thấy rating.

Phân tích chính đã định trước: Spearman giữa score và median Likert của ba người; CI 95% bootstrap 2.000 lần theo seed_id (10 cluster). Báo cáo Krippendorff alpha ordinal và Fleiss kappa để phân biệt mức đồng thuận giữa người chấm với mức phù hợp của score. AUPRC với majority class là phân tích phụ, loại unsure và báo số mục còn lại, prevalence. Không báo 90 rating như 90 alert độc lập.

Đây là pilot trên presentation có kiểm soát, không phải đánh giá analyst trên AIT-ADS hoặc SOC thực tế. Thiết kế cân bằng biên (3 mục/seed, 3/profile, 6/context) nhưng chỉ phủ 30/50 ô context–profile; không đủ để ước lượng mọi tương tác. CI với 10 cluster có thể rộng, cần công bố cả giới hạn này và không chọn ngưỡng kết luận sau khi xem kết quả.
