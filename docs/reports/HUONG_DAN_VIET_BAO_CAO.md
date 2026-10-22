# Hướng dẫn viết và trình bày báo cáo SeedFuz

Tài liệu này đi từ kiến thức nền tảng → thiết kế → thực nghiệm → demo, kèm dàn ý chương và checklist. Yêu cầu chính thức nằm ở `docs/university/`; nếu có mâu thuẫn, **đề cương của trường là chuẩn**.

---

## Phần A. Kiến thức nền tảng (đọc/viết trước khi nói về project)

### A1. IoT và vì sao phải kiểm thử bảo mật
- Thiết bị IoT (router, camera) có CPU/RAM nhỏ, firmware ít cập nhật, parser giao thức viết bằng C → dễ lỗi bộ nhớ (buffer overflow, integer overflow, null deref).
- Hậu quả: treo, reboot, rò rỉ bộ nhớ, thậm chí thực thi mã từ xa. Lỗi thường kích hoạt bằng **gói tin dị dạng**.

### A2. Fuzzing là gì
- Gửi lượng lớn input bất thường vào mục tiêu và quan sát phản ứng (crash, treo, lỗi).
- Phân loại:
  | Tiêu chí | Loại | Ghi chú |
  |---|---|---|
  | Cách sinh input | **Mutation-based** (SeedFuz) vs Generation-based (Boofuzz thuần) | Mutation: biến đổi dữ liệu thật có sẵn |
  | Hiểu mục tiêu | Black-box (SeedFuz) / Grey / White | Black-box: chỉ thấy phản hồi từ ngoài |
  | Hiểu giao thức | Dumb vs **State-aware** (SeedFuz) | Biết thứ tự/trạng thái hội thoại |

### A3. Mạng và giao thức cần nắm
- Mô hình Ethernet → IP → TCP/UDP → payload ứng dụng (HTTP, v.v.).
- PCAP/PCAPNG: định dạng file bắt gói; Wireshark là công cụ thu.
- **Payload** = phần ứng dụng; đây là thứ SeedFuz đột biến. Header Ethernet/IP/TCP do hệ điều hành dựng lại khi gửi.
- TCP: có kết nối, có trạng thái; UDP: không kết nối.

### A4. Các khái niệm cốt lõi của đề tài
| Khái niệm | Giải thích ngắn |
|---|---|
| **Seed** | Payload hợp lệ lấy từ PCAP, làm gốc để đột biến |
| **Bit flipping** | Đảo ngẫu nhiên 1+ bit trong seed |
| **Byte mutation** | Thay/chèn/xoá byte (ví dụ giá trị biên 0x00, 0xFF) |
| **Dữ liệu “nửa đúng nửa sai”** | Đủ hợp lệ để qua bước parse đầu, đủ sai để chạm đường code hiếm |
| **Trường nhạy cảm** | Header, delimiter, trường độ dài, giá trị biên — nơi lỗi parser hay xảy ra |
| **Smart seed selection** | Ưu tiên đột biến các trường nhạy cảm thay vì đột biến đều toàn gói |
| **State machine** | Đồ thị trạng thái suy ra từ chuỗi gói (ví dụ: kết nối → xác thực → lệnh) |
| **Black-box monitoring** | Phát hiện crash qua ping / TCP connect / HTTP 5xx |
| **Reproducibility** | Cùng `random_seed` + cùng PCAP → cùng chuỗi test case |

### A5. Chỉ số đánh giá
- **Tốc độ fuzzing** (packet/giây).
- **Số crash** và **thời gian đến crash đầu tiên**.
- **Crash duy nhất** (loại trùng theo payload).
- **Xu hướng bộ nhớ** (dấu hiệu rò rỉ; cần thiết bị có telemetry).
- **Độ phủ trường nhạy cảm**.

---

## Phần B. Thiết kế hệ thống (mô tả trong báo cáo)

### B1. Kiến trúc tổng quan
Dùng sơ đồ trong `README.md` (PCAP → parser → seed → state graph → mutator → transport → monitor → SQLite → dashboard/CSV/PDF). Mỗi khối ứng với một module:

| Khối | Module | Việc cần mô tả trong báo cáo |
|---|---|---|
| Phân tích PCAP | `pcap.py` | Giải mã Ethernet/VLAN/IPv4/IPv6/TCP/UDP, tách payload, loại seed trùng |
| State machine | `state_machine.py` | Cách suy luận chuyển trạng thái từ chuỗi gói |
| Đột biến | `mutation.py` | Bit/Byte/Smart-field; tính tái lập bằng `random_seed` |
| Điều phối | `campaign.py` | Vòng lặp case, đo tốc độ, phát hiện crash, tự khôi phục |
| Truyền | `transport.py` | dry-run / TCP / UDP |
| Giám sát | `monitor.py` | Ping, TCP, HTTP 5xx, memory probe |
| Lưu trữ | `storage.py` | Schema SQLite |
| Giao diện | `api.py` + `static/` | REST + dashboard |
| Báo cáo | `reporting.py` | CSV/PDF kèm hex payload |
| Boofuzz | `boofuzz_adapter.py` | Tích hợp theo đề cương; campaign mặc định dùng mutator riêng để đo được thuật toán |

### B2. Luồng một campaign (nên vẽ sequence diagram)
1. Nạp cấu hình (`experiments/*.json`) và kiểm tra an toàn (`authorized`, chặn IP public).
2. Parse PCAP → seeds + state graph.
3. Lặp: chọn seed (có/không smart) → đột biến → gửi → ghi kết quả.
4. Mỗi `monitor_interval` kiểm tra sống/chết; vượt `crash_threshold` → ghi crash + hex payload → khôi phục.
5. Kết thúc → lưu SQLite → xuất CSV/PDF.

### B3. Điểm cải tiến cần nhấn mạnh (đóng góp của đề tài)
1. Chọn seed/trường thông minh thay vì đột biến mù.
2. Nhận biết trạng thái (`state_aware`) và giữ phiên (`preserve_session`).
3. Tái lập kết quả + ghi payload gây crash.
4. Cảnh báo an ninh trên dashboard.

---

## Phần C. Thiết kế thí nghiệm

### C1. Giả thuyết
> Smart selection cho tốc độ phát hiện lỗi (thời gian đến crash đầu tiên / số crash duy nhất) tốt hơn đột biến ngẫu nhiên ở cùng số case.

**Không** viết “nhanh hơn 2–3 lần” nếu chưa có số liệu đủ mạnh (README đã cảnh báo). Chỉ báo cáo những gì đo được.

### C2. Hai nhóm so sánh
| Nhóm | `smart_selection` | Còn lại |
|---|---|---|
| Baseline | `false` | Cùng PCAP, `max_cases`, delay, thiết bị |
| SeedFuz | `true` | Giống hệt baseline |

Chạy **nhiều lần** (ví dụ ≥5 lần mỗi nhóm, `random_seed` khác nhau), khôi phục thiết bị về trạng thái ban đầu giữa các lần.

### C3. Bảng kết quả mẫu
| Chỉ số | Baseline (TB ± độ lệch) | SeedFuz (TB ± độ lệch) | Nhận xét |
|---|---|---|---|
| Packet/giây | | | |
| Thời gian đến crash đầu tiên | | | |
| Crash duy nhất | | | |
| Độ dốc bộ nhớ | | | |

Dữ liệu lấy từ `results/seedfuz.db`, `seedfuz report <id> --format csv|pdf`.

### C4. Mối đe dọa tính hợp lệ (phải nêu)
- Ping thất bại ≠ chắc chắn crash (firewall chặn ICMP).
- Bộ nhớ chỉ đo được khi thiết bị có telemetry.
- State graph là mô hình suy luận chung, chưa tinh chỉnh theo giao thức cụ thể.
- Chưa chạy trên thiết bị thật thì **chỉ** được nói là kết quả dry-run/mô phỏng.

---

## Phần D. Kịch bản demo (5–7 phút)

Chuẩn bị trước: venv đã cài, `datasets/sample_http.pcap` có sẵn, dashboard chạy thử một lần.

| Bước | Lệnh / thao tác | Điều cần nói |
|---|---|---|
| 1 | `python scripts/generate_sample_pcap.py` | Seed lấy từ lưu lượng thật (ở đây là mẫu) |
| 2 | `seedfuz analyze datasets/sample_http.pcap --json` | Số packet, seed, state, trường nhạy cảm |
| 3 | `seedfuz run experiments/dry_run.example.json` | Dry-run an toàn, không gửi ra mạng; ghi lại `campaign_id` |
| 4 | `seedfuz serve --host 127.0.0.1 --port 8000` | Mở dashboard: upload PCAP, chạy campaign |
| 5 | Xem dashboard | Case, packet/giây, crash, memory trend, bảng cảnh báo |
| 6 | `seedfuz report <id> --format pdf` | Báo cáo kèm payload để tái lập |
| 7 | `python -m pytest` | Tự động kiểm thử (README ghi 13 test, coverage 63% tại thời điểm viết) |
| 8 (nếu có thiết bị) | Dùng `experiments/hardware.example.json`, `authorized: true`, mạng lab cô lập | So sánh baseline vs smart |

Mẹo: quay video dự phòng; nếu không có thiết bị thật, nói rõ demo là dry-run và đưa kế hoạch thực nghiệm (Phần C).

---

## Phần E. Dàn ý báo cáo đề xuất

1. **Mở đầu**: bối cảnh IoT, vấn đề, mục tiêu, phạm vi, đối tượng.
2. **Cơ sở lý thuyết**: Phần A (fuzzing, PCAP, giao thức, state machine, Boofuzz).
3. **Khảo sát liên quan**: bài báo trong `papers/`, so sánh Boofuzz/AFL/… (lưu ghi chú ở `docs/research/`).
4. **Phân tích yêu cầu**: ánh xạ yêu cầu CLO/đề cương → module (bảng “yêu cầu — chức năng — file — test”).
5. **Thiết kế & cài đặt**: Phần B, sơ đồ, thuật toán smart selection.
6. **Thực nghiệm**: môi trường lab (sơ đồ mạng, `docs/HUONG_DAN_ROUTER_WIFI.md`), phương pháp Phần C, kết quả, biểu đồ.
7. **Thảo luận**: ưu/nhược, mối đe dọa tính hợp lệ, giới hạn.
8. **Kết luận & hướng phát triển**: adapter giao thức cụ thể, TLS/phiên dài, đăng nhập dashboard.
9. **Phụ lục**: cấu hình campaign, lệnh chạy, ảnh dashboard, đoạn mã chính, đạo đức & an toàn.

### Mục “Đạo đức & an toàn” (bắt buộc có)
Chỉ thiết bị sở hữu/được cấp phép, mạng cô lập, không commit PCAP nhạy cảm/IP public, giữ PCAP gốc nguyên vẹn (AGENTS.md).

---

## Phần F. Checklist trước khi nộp
- [ ] Mọi số liệu truy ngược được tới campaign ID/CSV.
- [ ] Nêu rõ cái gì chạy trên thiết bị thật, cái gì chỉ dry-run.
- [ ] Có hình: kiến trúc, state graph, dashboard, biểu đồ so sánh.
- [ ] Bảng ánh xạ yêu cầu trường ↔ code ↔ test.
- [ ] Lệnh tái lập kết quả (random_seed, file cấu hình) trong phụ lục.
- [ ] Trích dẫn tài liệu tham khảo đầy đủ.
- [ ] Không có thông tin nhạy cảm (IP thật, mật khẩu, PCAP riêng tư).
- [ ] Số liệu test/coverage cập nhật bằng cách chạy lại `python -m pytest --cov=seedfuz` ngay trước khi nộp.

## Câu hỏi hội đồng thường gặp
1. *Khác Boofuzz ở đâu?* → Mutation từ PCAP thật + smart field + state-aware; Boofuzz là generation-based.
2. *Làm sao biết thiết bị crash?* → Black-box heartbeat; nêu giới hạn ping.
3. *Kết quả có tái lập không?* → `random_seed` + payload hex được lưu.
4. *Vì sao không dùng Boofuzz làm engine chính?* → Cần đo và giải thích độc lập thuật toán smart selection.
5. *Hạn chế lớn nhất?* → Chưa tinh chỉnh state graph theo giao thức thật; chưa có số liệu thiết bị thật (nếu đúng thực tế).
