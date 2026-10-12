# Bàn giao phần Automation / Integration của Thắng

## A. Căn cứ và phạm vi

Nguồn: ảnh năm đầu việc 55–59; ảnh topology EVE-NG; mô tả của nhóm; sheet TO-DO, dòng 59–63. Workbook cho thấy nhóm đã đánh dấu hoàn thành thiết kế workflow, điều kiện block, whitelist, timeout và Logstash của Thắng. Tuy nhiên nội dung chi tiết các chính sách này không có trong tệp đính kèm. Bản mã này dùng **đề xuất cấu hình có thể thay thế**, không khẳng định khớp tuyệt đối với tài liệu M1 chưa cung cấp.

Phần năm việc hiện tại chạy độc lập. Các việc 60–65 (ghép API thật, Wazuh/Suricata thật, OPNsense thật, end-to-end và thực nghiệm) vẫn là giai đoạn tiếp theo. Không đánh dấu hoàn thành triển khai trên EVE-NG chỉ dựa vào mock.

## B. Diễn giải năm việc để đưa vào báo cáo

### 55. Xây dựng mock API AI

Mục đích là cho phép phát triển automation trong lúc chuẩn hóa dữ liệu và ghép mô hình thật chưa hoàn tất. Endpoint `/predict` nhận sự kiện chuẩn và trả anomaly score, mã sự kiện, chiều điểm và phiên bản mô hình. Điểm được tính theo công thức giả lập cố định, giúp cùng đầu vào luôn có cùng kết quả và dễ kiểm tra ngưỡng.

Kết quả bàn giao: API chạy độc lập trên cổng 8001, có xác thực token, từ chối dữ liệu sai và ví dụ request/response. Mock không chứng minh năng lực phát hiện bất thường của Isolation Forest hay LSTM.

### 56. Xây dựng mock API firewall

Mục đích là thử hành động chặn/gỡ chặn khi cụm OPNsense chưa sẵn sàng. API quản lý một bảng địa chỉ mô phỏng trong SQLite; không gửi lệnh tới OPNsense hay hệ điều hành. Mỗi lệnh gắn request ID, IP và TTL. Dịch vụ hỗ trợ chặn, xem danh sách, gỡ thủ công, tự gỡ khi hết hạn, giới hạn số IP và chống lặp lệnh.

Kết quả bàn giao: service cổng 8002, lưu bền trạng thái, kiểm tra whitelist độc lập. Thành công tại đây chỉ có nghĩa alias **mô phỏng** đã cập nhật; không có gói tin nào bị chặn trong topology.

### 57. Viết automation script

Luồng xử lý: nhận event đã chuẩn hóa → kiểm tra dữ liệu và thời gian → kiểm tra trùng → gọi AI → kiểm tra output AI → tính rủi ro và policy → gửi hành động nếu đủ điều kiện → kiểm tra xác nhận → ghi kết quả. Endpoint `/events` chạy ở cổng 8000.

Khi HTTP tới firewall bị mất phản hồi, một lệnh có thể đã thực hiện. Automation lưu ý định trước lần gọi để retry cùng ID, thay vì phát sinh lệnh mới hoặc khẳng định thất bại/chặn thành công không có căn cứ. Các quyết định và lỗi nghiệp vụ được ghi vào SQLite phục vụ kiểm tra.

### 58. Xây dựng logic threshold/risk score

Kết hợp điểm AI với mức độ nghiêm trọng của rule: `Risk=100×(0,7A+0,3S/15)`. Tự động chặn chỉ khi đồng thời thỏa Risk≥80, A≥0,85, S≥10, loại sự kiện cho phép, IP thuộc phạm vi cưỡng chế và không có trong danh sách bảo vệ. Các trường hợp nghi ngờ nhưng thiếu điều kiện được chuyển REVIEW.

Trọng số/ngưỡng này để demo hành vi. Khi có dữ liệu gán nhãn, Minh và Thắng cần hiệu chỉnh trên tập validation tách biệt; báo cáo kết quả trên test set giữ nguyên. Không điều chỉnh ngưỡng bằng test set. Thêm đánh giá tỷ lệ chặn nhầm và độ trễ từ sự kiện tới hành động, ngoài các chỉ số nhận diện AI.

### 59. Chống block nhầm IP quản trị/server

Chính sách bảo vệ dùng CIDR/host, kiểm tra trước lệnh chặn tại cả automation và mock firewall. Chỉ nguồn sự kiện đã chuẩn hóa mới là ứng viên hành động. FIM không tự bị suy diễn thành một cuộc tấn công mạng có IP nguồn; nếu không có nguồn đáng tin cậy, không gửi vào API chặn IP này. Bảo vệ IP không đồng nghĩa bỏ qua cảnh báo: sự kiện điểm cao vẫn đi REVIEW để điều tra.

Kết quả bàn giao: chống chặn subnet quản trị/server mẫu, gateway mẫu, địa chỉ loopback/link-local/multicast/unspecified, địa chỉ mạng/broadcast trong scope IPv4; chuẩn hóa IPv4-mapped IPv6. Phạm vi IPv6 tự chặn chưa được cấu hình; sự kiện IPv6 ngoài scope được REVIEW/OBSERVE.

## C. Bảng địa chỉ giả định cần thay bằng thiết kế của Nam

| Thành phần | Cấu hình mẫu | Mục đích |
|---|---|---|
| VLAN 99 – Management/SOC | 10.10.99.0/24 | Bảo vệ manager, collector, AI, log store, máy quản trị |
| VLAN 30 – Data Center | 10.10.30.0/24 | Bảo vệ AAA, database, file server |
| DMZ | 10.10.20.0/24 | Giả định riêng, ảnh chưa có VLAN/subnet của DMZ |
| Gateway Employee/Guest | 10.10.40.1/32, 10.10.50.1/32 | Chỉ là địa chỉ ví dụ |
| IP công cộng dịch vụ | 192.0.2.10/32 | Ví dụ IP/VIP/NAT phải đưa vào inventory bảo vệ |
| ULA IPv6 | fc00::/7 | Bảo vệ thận trọng trong demo |
| Nguồn được phép chặn trong mock | 198.51.100.0/24 | Dải giả lập; không cho chặn mọi IP theo mặc định |

Cần bổ sung địa chỉ thực của từng OPNsense node, CARP VIP ở các interface, gateway/SVI, switch management, DNS/NTP/DHCP, máy vận hành, SIEM và NAT public tương ứng. Một inventory thiếu có thể làm whitelist thiếu; không lấy bảng này làm sơ đồ IP thật.

## D. Phối hợp với từng thành viên

| Người | Thông tin cần nhận | Việc ghép nối tiếp theo |
|---|---|---|
| Nam | Bảng IP/VLAN, đường đi packet, vị trí rule, phiên bản OPNsense, cơ chế alias và quyền API | Viết adapter OPNsense thật; kiểm tra TTL, đồng bộ hai node và failover |
| Tùng | Một JSON Wazuh, một EVE JSON Suricata, mapping severity/type/src_ip, cách cấp event_id ổn định | Chuẩn hóa event, tính feature cửa sổ, gửi `/events`, đưa response/audit lên dashboard |
| Minh | Hợp đồng `/predict`, tên/thứ tự feature, preprocessing, kiểu điểm, model version, calibration | Thay mock AI, kiểm tra score semantics và hiệu chỉnh ngưỡng trên validation |
| Thắng | Policy được nhóm chốt, IP inventory, quy trình REVIEW và timeout | Cập nhật cấu hình, adapter, retry/pending, chứng cứ kiểm thử integration |

Một phương án luồng integration: log thô → parser/aggregation của Tùng và Logstash → automation `/events` → AI `/predict` → policy → adapter firewall → audit/dashboard. Tránh vừa để Wazuh Active Response vừa để automation xử lý cùng sự kiện nếu chưa có cơ chế phân quyền sở hữu và dedup chung. Script ở đây là dịch vụ HTTP riêng, **không phải executable Wazuh Active Response** có thể chép thẳng vào `active-response/bin`.

## E. Những điểm cần chỉnh theo topology

1. **Đường đi inter-VLAN:** nếu Core L3 định tuyến trực tiếp, lưu lượng east–west có thể không qua OPNsense. Chặn ở firewall biên chỉ tác động lưu lượng đi qua nó. Muốn cô lập máy nội bộ phải chọn điểm cưỡng chế như host firewall/Wazuh Active Response, ACL Core, hoặc thiết kế lại đường đi qua firewall. Vì chưa có adapter nội bộ, bản này chuyển nguồn nội bộ ngoài scope sang REVIEW.
2. **OPNsense số 3 ở DMZ:** ảnh có OPNsense_3 ngoài hai node OPNsense_1/2. Cần xác nhận thiết bị nào thực sự nằm trên đường vào DMZ; chặn nhầm cụm có thể không tác dụng. Chưa có cấu hình để kết luận cả ba thuộc một cụm HA.
3. **API alias không tự tạo hiệu lực chặn:** với OPNsense thật cần alias và rule tham chiếu alias đặt đúng interface/chiều/thứ tự. API cập nhật alias thành công chưa chứng minh packet bị drop. Kết nối đã có state cũng cần kiểm tra riêng; không xóa toàn bộ state table để demo.
4. **HA:** CARP, pfsync và config sync phục vụ các chức năng khác nhau. Không mặc định một cập nhật alias động qua API trên primary đã có trên secondary. Cần kiểm tra trạng thái alias, block/unblock và TTL sau chuyển vai trò; nhóm phải có cơ chế reconcile nếu cần.
5. **Thu lưu lượng:** chỉ nối thêm NIC vào SIEM/NIDS chưa chứng minh SPAN đầy đủ. Kiểm tra nguồn mirror ở cả hai core, chiều RX/TX, khả năng hỗ trợ của image EVE-NG và gói trùng. NIC sniffing nên tách khỏi NIC quản trị; đo mất gói thực tế khi tăng tải.
6. **Liên kết dự phòng:** nhiều đường nối qua hai core không tự tạo HA. Xác nhận STP, LACP và khả năng multi-chassis theo đúng image; tránh giả định một port-channel có thể kết thúc trên hai switch độc lập bất kỳ.
7. **Wazuh/ELK:** Wazuh hiện có các thành phần server, indexer, dashboard. Nếu nhóm dùng thêm Elasticsearch/Kibana, cần chỉ rõ đường xuất dữ liệu và phiên bản tương thích; không giả định Kibana là dashboard mặc định của mọi bản Wazuh. Bản mock không phụ thuộc lựa chọn này.

Các mục topology là điểm cần xác minh từ thiết kế đã cung cấp, không phải kết luận đã thử trên EVE-NG.

## F. Hướng chuyển sang OPNsense thật

Tài liệu OPNsense có endpoint `POST /api/firewall/alias_util/add/{alias}` và `delete/{alias}`. Trong giai đoạn tiếp theo, viết adapter riêng chuyển hợp đồng `/block` của nhóm sang API thực tế, kiểm tra request/response đúng phiên bản. Không đổi `SOC_FIREWALL_URL` sang firewall thật rồi giữ nguyên `/block` và coi như đã tích hợp.

Vòng đời TTL ở mock do SQLite/worker quản lý. TTL thật cần bộ điều phối bền, retry, reconcile khi restart, xác minh xóa alias thành công và thử failover; alias API không tự mang toàn bộ semantics `/block` của bản này. Tránh thêm adapter thật trước khi xác minh IP plan, quyền API, TLS và đường đi traffic.

## G. Nguồn kỹ thuật chính thức

Các nguồn dùng để đối chiếu thiết kế tích hợp; số liệu/ngưỡng mock là đề xuất riêng, không lấy từ tài liệu này.

1. OPNsense. *Firewall API*. Endpoint alias_util và API firewall: https://docs.opnsense.org/development/api/core/firewall.html
2. OPNsense. *Aliases*. Cách alias được dùng trong rule: https://docs.opnsense.org/manual/aliases.html
3. Wazuh. *Custom active response scripts*. Hợp đồng và vòng đời custom Active Response: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
4. Wazuh. *Components*. Server, indexer, dashboard: https://documentation.wazuh.com/current/getting-started/components/index.html
5. scikit-learn. *IsolationForest*. `decision_function`/`score_samples` có chiều thấp hơn là bất thường hơn: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html

Vì chiều raw score Isolation Forest khác hợp đồng mock, Minh phải cung cấp adapter chuẩn hóa/calibration có phiên bản, không đưa raw `decision_function` vào ngưỡng 0,85. Với LSTM reconstruction error cũng cần quy ước scale được fit trên dữ liệu train/validation, không mặc định đó là xác suất hay đã trong [0,1].
