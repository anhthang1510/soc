# Hợp đồng API v1 – module độc lập

Các endpoint dưới đây thuộc **mock của nhóm**, không phải tên endpoint OPNsense. Mọi endpoint ngoài `GET /health` yêu cầu `Authorization: Bearer <service-token>`. POST dùng `Content-Type: application/json`, tối đa 64 KiB. Mỗi service có token riêng cấu hình qua biến môi trường.

## Event chuẩn: POST automation:8000/events

```json
{
  "event_id": "suricata-sensor01-flow123-alert456",
  "timestamp": "2026-10-12T06:00:00Z",
  "source": "suricata",
  "src_ip": "198.51.100.23",
  "dst_ip": "10.10.20.10",
  "severity": 12,
  "event_type": "brute_force",
  "features": {
    "failed_logins_60s": 30,
    "unique_dst_ports_60s": 1
  }
}
```

Thay timestamp bằng thời gian hiện tại khi thử trực tiếp. `dst_ip` là trường tùy chọn; còn lại bắt buộc. Không nhận trường ngoài schema này. `source`: wazuh/suricata/test; `event_type`: brute_force/port_scan/fim/other. `event_id` dài 1–128 ký tự; timestamp có múi giờ; severity là số nguyên 0–15; hai feature là số nguyên không âm ≤ 1.000.000.

Feature phải được upstream tính trong cửa sổ 60 giây theo IP nguồn, không suy ra hai giá trị này từ một log đơn lẻ. Chốt với Minh quy tắc cửa sổ trượt/tumbling, thời điểm sự kiện, dedup, missing value và preprocessing trước khi ghép API thật. Các giá trị 0 trong ví dụ là số đo giả lập bằng 0, không có nghĩa là tùy ý thay dữ liệu thiếu bằng 0.

Một event được coi là mới nếu không cũ quá 300 giây và không vượt tương lai quá 30 giây. Đồng bộ thời gian trên các máy trước integration. Response HTTP 200 có:

| Trường | Ý nghĩa |
|---|---|
| decision | OBSERVE, REVIEW hoặc BLOCK |
| execution | none, dry_run, mock_applied hoặc mock_expired |
| risk_score | Điểm tổng hợp 0–100, chỉ làm tròn khi xuất |
| reason | Lý do quyết định: protected_ip, outside_enforcement_scope, combined_thresholds_met… |
| anomaly_score, model_version, policy_version | Truy vết mô hình và chính sách |
| event_id, src_ip, processed_at | Sự kiện, đối tượng và thời gian xử lý dạng Unix seconds |
| replayed | true nếu đây là trả lại kết quả đã xử lý |
| firewall | Chỉ có khi nhận được xác nhận mock firewall hợp lệ |

`BLOCK` chỉ là quyết định. Phải xem `execution` và `/blocks` để phân biệt dry-run, kết quả lịch sử, IP còn hiệu lực hay đã hết hạn. Nếu lỗi HTTP thì response là `{error, service}`, không được diễn giải là chặn thành công.

## Mock AI: POST ai:8001/predict

Nhận cùng event chuẩn. Trả về:

```json
{
  "event_id": "suricata-sensor01-flow123-alert456",
  "anomaly_score": 0.99,
  "score_semantics": "higher_is_more_anomalous_0_1",
  "model_version": "mock-deterministic-v1",
  "is_mock": true
}
```

Automation xác minh event ID, score hữu hạn trong [0,1], chiều điểm và model_version. Không cho caller gửi điểm AI trong event để tự quyết định việc chặn.

## Mock firewall

`POST :8002/block`:

```json
{"request_id":"soc-example-unique-id","ip":"198.51.100.23","ttl_seconds":300}
```

Trả `{mode:"mock", status:"blocked" hoặc "already_blocked", ip, request_id, expires_at, replayed}`. TTL là số nguyên 1 đến TTL tối đa policy. `expires_at` là Unix seconds. Request ID giữ nguyên khi retry; cùng ID khác IP/TTL bị từ chối. Retry sau khi hết hạn trả xác nhận lịch sử nhưng **không chặn lại**.

`POST :8002/unblock`: `{"ip":"198.51.100.23"}`. Gọi nhiều lần vẫn trả `unblocked`. `GET :8002/blocks` trả danh sách IP còn thời hạn. Không nhận tham số endpoint firewall từ event.

`GET :8000/audit` trả 100 quyết định/lỗi xử lý mới nhất. Lỗi parse/xác thực bị từ chối ở HTTP layer chưa được ghi vào bảng audit nghiệp vụ; khi tích hợp cần bổ sung access log phù hợp.

## Mã lỗi

| HTTP | Nghĩa |
|---|---|
| 400 | JSON hoặc Content-Length sai; Transfer-Encoding không được hỗ trợ |
| 401 | Sai/thiếu token |
| 403 | Mock firewall từ chối IP được bảo vệ/ngoài phạm vi |
| 404 | Sai endpoint |
| 409 | Tái dùng ID với nội dung khác |
| 413 / 415 | Body quá lớn/rỗng hoặc sai Content-Type |
| 422 | Sai schema, IP, TTL, dữ liệu số hoặc thời gian |
| 429 | Mock firewall đã đạt giới hạn IP đang bị chặn |
| 502 | Upstream trả HTTP lỗi hoặc dữ liệu xác nhận không đúng |
| 503 | Upstream timeout, không truy cập được hoặc JSON không đọc được |

Tại API automation, lỗi HTTP của downstream được bọc thành 502; ví dụ firewall trả 403/429 sẽ không tự động giữ nguyên mã này ở phía automation. Không retry lỗi schema/401/409 một cách mù quáng. Với 502/503 cần kiểm tra upstream và dùng cùng ID/nội dung nếu retry. Bản lab chưa có hàng đợi retry tự động hoặc API quản trị pending.
