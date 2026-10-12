

API viết bằng thư viện chuẩn Python để chạy ngay, không phải cài thêm gói. Dịch vụ AI của Minh có thể dùng FastAPI; việc ghép nối phụ thuộc hợp đồng JSON, không phụ thuộc framework của mock.

## 2. Chạy ngay trên Windows hoặc Linux

Yêu cầu Python 3.12. Giải nén, mở terminal **trong thư mục có `demo.py`**.

```bash
python demo.py --execute-mock
```

Trên Windows nếu chưa nhận lệnh `python`, dùng `py -3.12 demo.py --execute-mock`. Có thể chạy `RUN_DEMO.bat`.

Lệnh này khởi động ba HTTP API nội bộ ở cổng tự chọn, gửi năm tình huống, thử gửi trùng và in danh sách IP chặn mô phỏng. Kết thúc thì dừng các dịch vụ và xóa dữ liệu demo tạm. Không cần EVE-NG, Docker, Internet hoặc quyền quản trị.

| Tình huống | Điểm rủi ro dự kiến | Kết quả |
|---|---:|---|
| Brute force từ `198.51.100.23` | 93,30 | BLOCK; `mock_applied` |
| Hoạt động bình thường | 11,00 | OBSERVE |
| Quét cổng từ IP quản trị `10.10.99.10` | 99,30 | REVIEW; `protected_ip` |
| Sự kiện điểm cao từ server `10.10.30.20` | 99,30 | REVIEW; `protected_ip` |
| Quét cổng từ máy nội bộ `10.10.40.25` | 99,30 | REVIEW; `outside_enforcement_scope` |
| Gửi lại sự kiện đầu | Giữ kết quả cũ | `replayed=true`, không chặn lần nữa, không gia hạn TTL |

**Các IP trên là giả định phục vụ demo**, không được đọc ra từ sơ đồ. `198.51.100.0/24` dùng làm tập IP giả lập nguồn tấn công. Không cần gán các địa chỉ này lên card mạng.

Chỉ xem quyết định, không thêm IP vào mock firewall:

```bash
python demo.py
```

Chạy toàn bộ kiểm thử:

```bash
python -m unittest discover -s tests -v
```

## 3. Chạy ba dịch vụ riêng để trình diễn

Mở ba terminal tại cùng thư mục, mỗi terminal chạy một lệnh:

```bash
python -m soclab ai
python -m soclab firewall
python -m soclab automation
```

Địa chỉ lần lượt: AI `127.0.0.1:8001`, firewall `127.0.0.1:8002`, automation `127.0.0.1:8000`. Dữ liệu của dịch vụ riêng lưu tại `data/*.sqlite3` và còn sau khởi động lại.

Automation mặc định `SOC_DRY_RUN=true`. Để thực thi **trên mock**, đặt biến này trước khi khởi động terminal thứ ba:

PowerShell:

```powershell
$env:SOC_DRY_RUN="false"
python -m soclab automation
```

Bash:

```bash
SOC_DRY_RUN=false python -m soclab automation
```

Gửi sự kiện ở terminal thứ tư:

```bash
python send_event.py examples/01_bruteforce.json
python send_event.py examples/03_management.json
```

`send_event.py` tự tạo ID và thời gian mới. Để kiểm tra gửi trùng thủ công, gửi đúng cùng JSON, cùng ID và timestamp; `--keep-id --keep-time` giữ nguyên cả hai. JSON mẫu chứa ngày cố định nên nếu dùng các cờ này cần sửa timestamp cho còn hiệu lực. Một event đã được xử lý dry-run sẽ trả kết quả cũ nếu gửi lại cùng ID; dùng ID mới khi đổi chế độ.

Xem trạng thái bằng curl (Windows có thể dùng `curl.exe`):

```bash
curl http://127.0.0.1:8002/blocks -H "Authorization: Bearer demo-firewall-token"
curl http://127.0.0.1:8000/audit -H "Authorization: Bearer demo-automation-token"
```

`/audit` trả 100 bản ghi gần nhất; toàn bộ vẫn nằm trong SQLite. Firewall có bảng audit riêng với BLOCK, UNBLOCK và EXPIRE. `/health` chỉ cho biết tiến trình sống, không chứng minh các dịch vụ phụ thuộc đã sẵn sàng.

## 4. Docker Compose

Có `Dockerfile` và `compose.yaml`. Không cần Logstash/ELK để chạy năm việc độc lập này. Máy chạy Docker cần có image Python hoặc truy cập được registry.

Sao chép `.env.example` thành `.env`, chọn `SOC_DRY_RUN=false` nếu muốn chặn mô phỏng, sau đó:

```bash
docker compose up --build -d
python send_event.py examples/01_bruteforce.json
docker compose logs automation
docker compose down
```

Compose giữ dữ liệu trong hai volume. `depends_on` chỉ quy định thứ tự khởi động; nếu dịch vụ chưa sẵn sàng, đợi `/health` rồi gửi lại cùng sự kiện. Mặc định các cổng publish chỉ trên localhost. Khi sửa policy, tăng `version`, rồi restart automation và firewall để cùng nạp bản mới. Chỉ chạy một instance automation với một DB trong bản lab này.

Docker chưa được build/chạy trong môi trường bàn giao; phần kiểm thử đã chạy là Python và HTTP local. `.env` được Compose đọc; chạy Python trực tiếp thì phải đặt biến môi trường trong terminal, không tự đọc `.env`.

## 5. Logic quyết định

Điểm AI chuẩn hóa `A` nằm trong [0,1], **càng cao càng bất thường**. Severity `S` nằm trong [0,15].

```text
Risk = 100 × (0,70 × A + 0,30 × S/15)
```

| Điều kiện | Quyết định |
|---|---|
| Risk < 50 | OBSERVE, lưu kết quả |
| Risk ≥ 50 nhưng chưa đủ điều kiện chặn | REVIEW, lưu để người trực SOC xem xét |
| Risk ≥ 80 và A ≥ 0,85 và S ≥ 10, loại brute_force/port_scan, IP không được bảo vệ, IP thuộc phạm vi cho phép | BLOCK |

Whitelist và phạm vi cưỡng chế có quyền ưu tiên cao hơn điểm. IP được bảo vệ có điểm cao vẫn phát sinh REVIEW, không bỏ qua cảnh báo. REVIEW trong bản này là một trạng thái trả về/audit, chưa có màn hình phê duyệt hoặc chức năng gửi thông báo.

Đây là **chính sách đề xuất cho demo**, không phải các ngưỡng đã được nhóm kiểm chứng. 70/30 là trọng số kỹ thuật minh họa, không phải xác suất tấn công. Không dùng số lượng test phần mềm để suy ra Precision/Recall/F1 của AI.

Mock AI tính `min(0.99, max(0.10, failed_logins_60s/20, unique_dst_ports_60s/50))`. Đây là công thức giả lập dễ tái lập, không phải Isolation Forest hay LSTM. Xem thêm `docs/BAN_GIAO.md` để ghép mô hình thật.

## 6. Cơ chế chống chặn nhầm và phục hồi

- `src_ip` là IP nguồn đáng ngờ đã được parser xác định; không lấy `agent.ip`, IP manager, đích bị tấn công hoặc nội dung text bất kỳ làm IP cần chặn.
- Mẫu bảo vệ toàn VLAN 99, Data Center, DMZ và một số gateway; địa chỉ thật phải do Nam cung cấp. Whitelist toàn vùng là lựa chọn thận trọng giai đoạn đầu, cần thu hẹp bằng inventory khi triển khai.
- Chỉ chấp nhận một IP host hợp lệ; không nhận CIDR, hostname, shell command; chuẩn hóa IPv4-mapped IPv6 trước khi kiểm tra.
- Bảo vệ ở automation và mock firewall. Chặn trực tiếp bằng token firewall vẫn phải qua policy.
- Có TTL 300 giây, tối đa 20 IP chặn đồng thời; cùng IP đang bị chặn không được tự kéo dài TTL vì sự kiện khác.
- Worker firewall dọn IP hết hạn định kỳ; lần truy cập và khởi động chạy lại cũng kiểm tra thời hạn. TTL và trạng thái lưu bền trong SQLite.
- Event ID gắn với nội dung. Gửi trùng trả kết quả lịch sử; cùng ID nhưng đổi nội dung trả 409. `/blocks` là nơi xem trạng thái chặn **hiện tại**.
- Automation lưu ý định trước khi gọi firewall. Nếu firewall đã xử lý nhưng phản hồi bị mất, lần gửi lại dùng cùng request ID để không chặn/gia hạn lần nữa. Lỗi HTTP không được ghi là thành công.
- Khi API AI lỗi hoặc trả sai định dạng/chiều điểm, dừng hành động và ghi lỗi. Khi firewall timeout, trạng thái có thể chưa biết; cần gửi lại cùng sự kiện trong cửa sổ 300 giây hoặc kiểm tra `/blocks`.
- Không có worker tự gửi lại pending trong bản này. Bên gửi phải retry; sự kiện quá cũ sẽ bị từ chối để tránh chặn muộn. Một yêu cầu pending tồn đọng cần được người vận hành kiểm tra; mock block nếu có vẫn tự hết TTL.
- Token demo chỉ dành localhost. HTTP server thư viện chuẩn là máy chủ lab, chưa phải dịch vụ production có TLS, rate limiting, phân quyền người dùng, hàng đợi bền và giám sát đầy đủ.

## 7. Tài liệu đi kèm

- `docs/API.md`: hợp đồng JSON, endpoint và mã lỗi.
- `docs/BAN_GIAO.md`: diễn giải từng việc, giả định IP, việc phối hợp Nam/Tùng/Minh và lưu ý topology.
- `docs/KIEM_THU.md`: phạm vi, cách tái lập và giới hạn kiểm thử.
- `tests/test_soc.py`: các ca kiểm thử chạy được.
- `verification/`: kết quả kiểm thử và demo đã chạy lúc bàn giao.
# soc
