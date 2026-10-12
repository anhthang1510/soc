# Biên bản kiểm thử module

## Phạm vi đã thực hiện

Chạy trên Python 3.12.14 bằng thư viện chuẩn; kiểm tra đơn vị, trạng thái SQLite và gọi HTTP thật giữa ba dịch vụ trên localhost. `verification/unit-tests.txt` chứa stdout/stderr và exit code của lần chạy bàn giao. `verification/demo-execute.jsonl` và `demo-dry-run.jsonl` là đầu ra demo thực tế.

Lệnh tái lập:

```bash
python -m unittest discover -s tests -v
python demo.py --execute-mock
python demo.py
```

## Các nhóm kiểm thử

| Nhóm | Tiêu chí |
|---|---|
| Quyết định | Sự kiện nguy cơ cao đủ điều kiện được chặn mock; sự kiện bình thường được quan sát |
| Bảo vệ IP | Quản trị/server/gateway và IP đặc biệt không bị chặn, kể cả khi gọi trực tiếp mock firewall |
| Enforcement scope | Máy nội bộ ngoài phạm vi firewall biên chuyển REVIEW |
| Ngưỡng | Kiểm tra hai phía ngưỡng risk, ngưỡng AI và mức severity tối thiểu |
| Loại sự kiện | FIM không tự bị biến thành hành động block IP |
| Dry-run | Có quyết định nhưng bảng chặn không thay đổi |
| Dedup | Gửi trùng, gửi đồng thời và khởi động lại không tạo thêm block/gia hạn TTL |
| ID conflict | Cùng ID với nội dung khác bị từ chối |
| Vòng đời | Hết hạn, gỡ thủ công nhiều lần, restart và replay sau hết hạn |
| Lỗi AI | Offline, điểm NaN/âm/boolean, sai event ID, chiều điểm hoặc phiên bản bị từ chối |
| Lỗi firewall | ACK sai không được ghi thành công; mất ACK sau commit retry không kéo dài TTL |
| Dữ liệu đầu vào | Thiếu nguồn, IP/CIDR/hostname sai, feature sai kiểu, thời gian cũ/tương lai |
| Policy | Policy trống bị từ chối; đổi phiên bản khi pending chuyển REVIEW; giới hạn IP và TTL |
| HTTP | Luồng đủ ba dịch vụ qua HTTP, token sai và JSON không hợp lệ |

Kiểm tra TTL trong unit test dùng đồng hồ giả lập để đi qua mốc hết hạn chính xác, không đợi 300 giây thực. Test HTTP dùng socket localhost thật. Các test có nhiều subcase nhưng unittest báo theo số phương thức test; không diễn giải số test thành số tấn công thực nghiệm.

## Chưa xác minh

- Build và chạy Docker/Compose.
- Cấu hình EVE-NG, thông lượng SPAN, CARP/pfsync, packet drop thực tế, DHCP/WiFi.
- Contract API thật của Minh và Nam; preprocessing, log thật, Wazuh Active Response.
- Đồng bộ alias trên HA, timeout/reconcile của OPNsense thật.
- Precision/Recall/F1/FPR của mô hình AI, MTTD/MTTR thực tế và tải lớn.

Kết luận phù hợp: **bộ mock và logic automation đã được kiểm thử độc lập**. Không dùng kết quả này để khẳng định SOC toàn hệ thống đã hoạt động hoặc mô hình AI có độ chính xác cao.

## Chứng cứ nhóm nên chụp khi nghiệm thu trên máy mình

1. Terminal ba service hoặc `docker compose ps`.
2. Event tấn công → kết quả BLOCK/mock_applied và `/blocks` có đúng một IP.
3. Event IP quản trị/server có điểm cao → REVIEW, `/blocks` không thêm IP đó.
4. Gửi trùng giữ nguyên `expires_at`; quá TTL hoặc unblock thì IP biến mất.
5. Kết quả unittest không lỗi.

Chỉ cập nhật trạng thái các việc 55–59 trong bảng chung sau khi nhóm đã chạy lại và chấp nhận cấu hình/contract. Các đầu việc integration 60–65 cần nghiệm thu riêng.
