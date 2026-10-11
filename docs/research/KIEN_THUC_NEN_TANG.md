# Kiến thức nền tảng của SeedFuz

Tài liệu giải thích các khái niệm cần hiểu để nắm project, mỗi phần kèm vị trí trong code (`src/seedfuz/`). Nội dung phần "Trong SeedFuz" được đối chiếu với mã nguồn tại thời điểm viết; nếu code đổi, hãy cập nhật lại.

Đọc theo thứ tự: 1 → 8. Hướng dẫn viết báo cáo nằm ở `docs/reports/HUONG_DAN_VIET_BAO_CAO.md`.

---

## 1. Bối cảnh: IoT và lỗ hổng phần mềm

**IoT (Internet of Things)**: thiết bị nhỏ có kết nối mạng như router, camera, ổ cắm thông minh. Đặc điểm khiến chúng dễ bị tấn công:
- Tài nguyên (CPU, RAM) hạn chế, firmware viết bằng C/C++ nên không có bảo vệ bộ nhớ tự động.
- Firmware ít được cập nhật.
- Phải tự phân tích dữ liệu mạng nhận vào (HTTP, UPnP, giao thức riêng...) nên parser là điểm yếu.

**Các lỗi điển hình khi parser xử lý dữ liệu dị dạng:**
| Lỗi | Ví dụ | Hậu quả |
|---|---|---|
| Buffer overflow | Trường độ dài khai báo lớn hơn bộ đệm | Treo, ghi đè bộ nhớ, thực thi mã |
| Integer overflow | Độ dài `0xFFFF` cộng thêm làm tràn số | Cấp phát sai kích thước |
| Null dereference | Thiếu trường bắt buộc | Crash tiến trình |
| Memory leak | Gói lỗi không giải phóng bộ nhớ | RAM tăng dần, thiết bị chậm rồi treo |

Mục tiêu của đề tài: **tự động tìm** các lỗi này bằng cách gửi dữ liệu biến dạng và quan sát thiết bị.

---

## 2. Fuzzing

**Fuzzing** = gửi lượng lớn input bất thường vào chương trình/thiết bị, theo dõi crash, treo hoặc hành vi lạ.

### 2.1 Phân loại
| Trục | Lựa chọn | SeedFuz |
|---|---|---|
| Cách sinh input | *Generation-based*: dựng từ mô tả giao thức (Boofuzz thuần). *Mutation-based*: biến đổi dữ liệu mẫu có sẵn | **Mutation-based** |
| Mức hiểu mục tiêu | *Black-box*: chỉ nhìn từ ngoài. *Grey/White-box*: có instrumentation, mã nguồn | **Black-box** |
| Mức hiểu giao thức | *Dumb*: không biết cấu trúc. *Smart/state-aware*: biết cấu trúc/trạng thái | **Smart** (một phần) |

### 2.2 Vòng lặp fuzzing
```
seed hợp lệ → đột biến → gửi → quan sát phản ứng → ghi nhận bất thường → lặp lại
```
Trong code, vòng lặp này là `CampaignRunner.run()` ở `campaign.py`.

### 2.3 Vì sao mutation từ dữ liệu thật?
Dữ liệu hoàn toàn ngẫu nhiên thường bị thiết bị loại ngay ở bước kiểm tra đầu (sai định dạng). Dữ liệu **“nửa đúng nửa sai”** (đúng gần hết, sai ở vài chỗ) vượt qua kiểm tra bề mặt và chạm vào code xử lý sâu hơn, nơi lỗi hay nằm.

### 2.4 Boofuzz
Framework fuzzing giao thức mạng bằng Python (generation-based, có web UI riêng, lưu kết quả vào SQLite). SeedFuz dùng đúng phiên bản trong `requirements.txt`.
- Trong code: `boofuzz_adapter.py` → `build_boofuzz_session()` dựng một `Session` từ chuỗi seed, **chưa chạy** (để người vận hành duyệt trước).
- **Campaign mặc định không dùng Boofuzz** mà dùng mutator riêng (`mutation.py`) để đo và giải thích độc lập thuật toán chọn thông minh của đề tài.

---

## 3. Mạng máy tính cần biết

### 3.1 Các tầng gói tin
```
Ethernet (14 byte, +4 nếu VLAN 802.1Q)
 └─ IP (IPv4 ≥20 byte | IPv6 40 byte + extension header)
     └─ TCP (≥20 byte) | UDP (8 byte)
         └─ Payload ứng dụng  ← SeedFuz đột biến phần này
```
Header các tầng do hệ điều hành dựng lại khi gửi, nên SeedFuz chỉ lấy **payload**.

### 3.2 TCP và UDP
| | TCP | UDP |
|---|---|---|
| Kết nối | Có (bắt tay 3 bước SYN, SYN-ACK, ACK) | Không |
| Trạng thái | Có (cờ SYN, ACK, FIN, RST) | Không |
| Ví dụ | HTTP, quản trị web router | DNS, SSDP/UPnP |

Cờ TCP (`tcp_flags`): `FIN=0x01`, `SYN=0x02`, `RST=0x04`, `ACK=0x10`.

### 3.3 PCAP và PCAPNG
- File ghi lại gói tin bắt được (Wireshark, tcpdump).
- **Classic PCAP**: header 24 byte (magic number xác định thứ tự byte và độ phân giải thời gian) + chuỗi (header gói 16 byte + dữ liệu).
- **PCAPNG**: định dạng mới theo block (Section Header, Interface Description, Enhanced/Simple Packet).
- Trong code: `pcap.py` → `read_pcap()` đọc cả hai loại, tự cài đặt parser bằng `struct`, không dùng thư viện ngoài. `_decode()` bóc Ethernet → VLAN → IPv4/IPv6 → TCP/UDP và trả về `PacketRecord` (`models.py`).
- Giới hạn: chỉ giải mã link-type Ethernet; PCAP phải có payload ứng dụng không rỗng.

---

## 4. Seed và trích xuất seed

**Seed** là payload hợp lệ, dùng làm gốc để đột biến.

- Trong code: `usable_seeds()` (`pcap.py`) lấy payload **không rỗng**, **loại trùng**, **giữ thứ tự xuất hiện**.
- Vì sao giữ thứ tự: thứ tự các gói phản ánh luồng hội thoại thật (ví dụ đăng nhập trước, gửi lệnh sau).
- Quy tắc dự án: giữ nguyên PCAP gốc, mutation và kết quả ghi ra nơi khác.

---

## 5. State machine (máy trạng thái giao thức)

**Ý tưởng**: giao thức có thứ tự. Gửi lệnh “điều khiển” trước khi “đăng nhập” có thể bị từ chối ngay; fuzzer hiểu thứ tự sẽ đưa thiết bị vào đúng trạng thái trước khi tấn công.

**Trong SeedFuz** (`state_machine.py`):
- `packet_state()` gán mỗi gói một nhãn từ cờ TCP/payload: `syn-sent`, `syn-ack`, `established`, `application-data`, `closing`, `reset`, `datagram` (UDP), `idle`...
- `infer_state_graph()` duyệt chuỗi gói, đếm số lần chuyển `trạng thái trước → trạng thái sau` thành `StateGraph` (đồ thị có trọng số, bắt đầu từ `start`, kết thúc ở `end`).
- Ví dụ: `start → syn-sent → syn-ack → established → application-data → closing → end`.

**Hạn chế (nên nêu thẳng trong báo cáo)**: đây là mô hình *suy luận chung ở mức TCP*, chưa hiểu logic ứng dụng (đăng nhập, lệnh...). Muốn chính xác hơn cần tinh chỉnh theo giao thức thật.

**Cờ `state_aware` trong campaign** (`campaign.py`): khi bật, seed được chọn **tuần tự theo thứ tự trong PCAP** (`(case-1) % số seed`), tái hiện luồng hội thoại. Khi tắt, seed được chọn ngẫu nhiên.

**`preserve_session`**: dịch vụ có đăng nhập cần giữ nguyên Cookie/Authorization/token, nếu đột biến cả chúng thì mọi gói bị từ chối ở cổng xác thực. `session_token_ranges()` tìm các đoạn byte đó (header `Cookie:`, `Set-Cookie:`, `Authorization:` và tham số `token=`, `session=`, `sid=`, `csrf=`, `auth=`) để mutator bỏ qua.

---

## 6. Đột biến (mutation)

Toàn bộ nằm trong `mutation.py`, lớp `Mutator`.

### 6.1 Tính tái lập
`Mutator` dùng `random.Random(random_seed)`. Cùng PCAP + cùng `random_seed` + cùng cấu hình → cùng chuỗi test case. Đây là cơ sở để so sánh công bằng giữa các thí nghiệm.

### 6.2 Ba toán tử
| Toán tử | Hành vi | Hàm |
|---|---|---|
| **Bit flipping** | Đảo 1 bit ngẫu nhiên: `byte ^= (1 << bit)` | `bit_flip` |
| **Byte mutation** | Thay một byte bằng giá trị biên khác: `0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF` | `byte_mutation` |
| **Smart-field** | Thay cả trường nhạy cảm bằng toàn bit 1 (ví dụ trường 2 byte → `0xFFFF`) | `length_mutation` |

**Vì sao giá trị biên?** Lỗi số học thường xảy ra ở 0, 1, 127, 128, 254, 255 (tràn, âm khi ép kiểu, chia 0).

### 6.3 Cách xoay vòng (`mutate(seed, index)`)
- `index % 3 == 0` → bit flip.
- `index % 3 == 1` → byte mutation.
- `index % 3 == 2` và có trường nhạy cảm (khi `smart_selection` bật) → smart-field, lần lượt qua danh sách trường; nếu không có trường thì rơi về byte mutation.

Vậy khi bật smart selection, khoảng **1/3 test case** nhắm vào trường nhạy cảm; khi tắt thì chỉ còn bit flip và byte mutation (baseline).

### 6.4 Trường nhạy cảm (`detect_sensitive_fields` trong `pcap.py`)
Mỗi byte/cặp byte được chấm điểm theo các dấu hiệu, điểm cộng dồn:
| Lý do | Điểm | Ý nghĩa |
|---|---|---|
| `header` | +1.0 | 8 byte đầu của payload (thường là magic/loại bản tin) |
| `boundary-value` | +1.5 | Byte là 0, 1, 0x7F, 0x80, 0xFE, 0xFF |
| `delimiter` | +1.2 | Byte là `= : ; , \| & ?` (ranh giới tham số) |
| `probable-length` | +2.5 | Byte bằng độ dài payload (hoặc phần còn lại) |
| `probable-16bit-length` | +3.0 | Cặp byte (big-endian) bằng độ dài payload |

Kết quả sắp xếp điểm giảm dần. Đây là **heuristic**, không phải chứng minh: một byte có thể bị gán nhãn “độ dài” chỉ do trùng hợp.

### 6.5 Độ phủ trường nhạy cảm
`campaign.py` đếm số trường `(seed, offset, length)` đã bị đột biến, lưu vào `sensitive_fields_covered`. Chỉ số này dùng để so sánh baseline với smart selection.

---

## 7. Giám sát thiết bị và phát hiện crash

Fuzzer black-box không thấy bên trong thiết bị nên suy ra “crash” từ việc **thiết bị ngừng phản hồi**. Trong `monitor.py`, `DeviceMonitor.sample()` dùng một trong ba cách, ưu tiên `http_url` > `tcp_port` > ping:

| Cách | Coi là “sống” khi | Ghi chú |
|---|---|---|
| HTTP | Mã trả về `< 500` | Router treo thường trả 5xx hoặc không trả lời |
| TCP connect | Kết nối thành công | Cổng đóng đột ngột là dấu hiệu tiến trình chết |
| Ping (ICMP) | `ping` thành công | Có thể sai nếu firewall chặn ICMP |

**Quy tắc ghi crash** (`campaign.py`): thất bại **liên tiếp** `crash_threshold` lần (mặc định 2) mới tính là crash, nhằm giảm báo động giả do mất gói đơn lẻ. Khi đó hệ thống:
1. Tăng `crashes`, đặt `security_status = "vulnerable"`.
2. Ghi sự kiện `target-crash` và `security-alert` kèm số case, thời điểm, **payload hex** (tối đa 4096 ký tự hex) để tái lập.
3. Gọi `_recover()`: chạy `recovery_command` (ví dụ ngắt/cấp điện qua ổ cắm thông minh) rồi thăm dò đến khi thiết bị sống lại hoặc hết `recovery_wait_seconds`.

**Trạng thái an ninh** (`security_status`): `pending` → `secure` / `unreachable` / `vulnerable`; `not-monitored` nếu không có monitor.

**Rò rỉ bộ nhớ**: nếu thiết bị có endpoint JSON trả `memory_percent` (cấu hình `memory_probe_url`), `memory_leak_rate()` tính **hệ số góc hồi quy tuyến tính (bình phương tối thiểu)** của bộ nhớ theo số mẫu, đơn vị *điểm phần trăm / mẫu*. Dốc dương kéo dài gợi ý rò rỉ. Router thương mại thường **không** cung cấp telemetry này nên chỉ số sẽ là `None`.

> Lưu ý quan trọng: ping/TCP thất bại **không chứng minh** có lỗ hổng; chỉ là tín hiệu để người vận hành kiểm tra thủ công bằng payload đã lưu.

---

## 8. Thực thi, lưu trữ, giao diện, an toàn

### 8.1 Chạy tập lệnh
`transport.py`:
- `DryRunTransport`: giả vờ gửi, không chạm mạng (an toàn để thử).
- `SocketTransport`: TCP (**mở kết nối mới cho mỗi test case**) hoặc UDP, có timeout, đọc phản hồi nếu có.

### 8.2 Chỉ số một campaign (`models.CampaignMetrics`)
Số case, đã gửi, lỗi gửi, byte gửi, packets/giây, số crash, số trường nhạy cảm đã phủ, số lần dùng từng toán tử, tốc độ rò rỉ bộ nhớ, trạng thái an ninh.

### 8.3 Lưu trữ và báo cáo
- `storage.py`: SQLite (`results/seedfuz.db`) lưu campaign, case, sự kiện, mẫu sức khỏe.
- `reporting.py`: xuất CSV/PDF.
- `api.py` + `static/`: REST API (FastAPI) và dashboard web; `cli.py`: lệnh `seedfuz analyze|run|report|serve|monitor`.

### 8.4 An toàn và đạo đức (bắt buộc hiểu)
`CampaignConfig.validate()` (`config.py`) cưỡng chế:
- Chế độ mạng cần `authorized = true`.
- `target_host` phải là **địa chỉ IP tường minh**; IP không thuộc dải private/loopback/link-local bị chặn trừ khi đặt `allow_public_target` (không nên dùng trong học tập).
- Giới hạn `max_cases` từ 1 đến 1.000.000.

Quy tắc: chỉ kiểm thử thiết bị **của mình hoặc được cấp phép**, trên **mạng cô lập**; fuzzing có thể làm treo, mất cấu hình hoặc hỏng thiết bị. Dashboard chưa có đăng nhập, chỉ chạy trên `127.0.0.1` hoặc mạng lab.

---

## 9. Bảng thuật ngữ Anh – Việt

| Anh | Việt / giải thích |
|---|---|
| Fuzzing | Kiểm thử bằng dữ liệu bất thường tự động |
| Mutation-based | Sinh input bằng cách biến đổi dữ liệu mẫu |
| Seed | Hạt giống: payload gốc hợp lệ |
| Payload | Phần dữ liệu tầng ứng dụng |
| Black-box | Hộp đen: không biết cấu trúc bên trong |
| State machine | Máy trạng thái |
| Bit flipping | Đảo bit |
| Boundary value | Giá trị biên |
| Sensitive field | Trường nhạy cảm (header, độ dài, delimiter...) |
| Crash | Sập/treo thiết bị |
| Heartbeat | Kiểm tra sống định kỳ |
| Memory leak | Rò rỉ bộ nhớ |
| Reproducibility | Khả năng tái lập |
| Baseline | Nhóm đối chứng (không dùng cải tiến) |
| Dry-run | Chạy thử không gửi ra mạng |

## 10. Tự kiểm tra (nếu trả lời được là đã nắm nền tảng)
1. Vì sao SeedFuz chỉ đột biến payload mà không đột biến header TCP/IP?
2. Một seed 20 byte có hai byte đầu là `0x00 0x14`. Heuristic nào gán điểm cho vị trí đó và vì sao?
3. `state_aware=false` khác `true` ở điểm nào trong chọn seed? Có phải “state-aware” theo nghĩa hiểu giao thức ứng dụng không?
4. Vì sao cần `crash_threshold` ≥ 2?
5. Vì sao `preserve_session` cần thiết khi fuzz trang quản trị có đăng nhập?
6. Tại sao nói kết quả ping thất bại chưa đủ kết luận có lỗ hổng?
7. Làm sao chứng minh hai lần chạy cho cùng một chuỗi test case?

---

# Phần bổ sung: ứng dụng, dữ liệu, kiểm thử và yêu cầu của trường

## 11. Yêu cầu chính thức (đề cương ATTT_009, năm học 2025–2026)

**Đề tài:** *Nghiên cứu Tối ưu hóa Kỹ thuật Mutational Fuzzing với Cơ chế Chọn Hạt giống Thông minh trong Dò quét Lỗ hổng IoT.* GVHD: Đinh Huy Hoàng. Định hướng nghiên cứu, nhóm tối đa 3 sinh viên, 12 tuần, gặp GVHD ít nhất 1 lần/tuần.

**Ba loại dữ liệu theo đề cương:**
| Loại | Nội dung | Nơi lưu trong project |
|---|---|---|
| Seed (đầu vào) | PCAP bắt từ lưu lượng bình thường của thiết bị | `datasets/` |
| Trung gian | Hàng ngàn gói “nửa đúng nửa sai” do hệ thống sinh | bảng `test_cases` (SQLite) |
| Đầu ra | Log thời điểm crash, tốc độ gửi, số liệu bộ nhớ | `results/`, CSV/PDF |

**Kế hoạch tuần:** 1 dựng Linux và chọn thiết bị; 2 bắt PCAP; 3 phân tích Header/Payload và state machine; 4 Boofuzz; 5 bit/byte mutation; 6–7 smart seed selection; 8 script ping; 9–10 chạy chiến dịch thật và đo; 11 đo rò rỉ bộ nhớ, đối chiếu “nhanh gấp 2–3 lần”; 12 báo cáo, slide, nộp.

**Thang điểm (10 điểm)** – dùng để quyết định báo cáo nên dành bao nhiêu trang cho mục nào:
| Mục | Điểm | Ghi chú |
|---|---|---|
| Tổng quan (lý do, mục tiêu, khảo sát liên quan, đối tượng/phương pháp/độ đo) | 0.75 | CLO1.1 |
| Kế hoạch và phân công | 0.25 | CLO6 |
| Khái niệm liên quan + ví dụ | 0.75 | CLO1.2 |
| Mô tả thuật toán: các bước, ưu/nhược | 0.50 | CLO2.1 |
| Mô tả bộ dữ liệu thực nghiệm | 0.50 | CLO2.2 |
| **Cài đặt thuật toán và ứng dụng (10 hạng mục × 0.5)** | **4.50** | CLO3 – phần nặng nhất |
| Triển khai trên **dữ liệu thực tế** | 0.75 | CLO4 |
| Nội dung báo cáo / hình thức | 0.5 + 0.5 | CLO5.1 |
| Thái độ làm việc | 0.5 | CLO6 |
| Phong cách báo cáo, slide | 0.5 | CLO5.2 |
| Cộng khuyến khích (NCKH, bài báo) | tối đa +1.0 mỗi mục | Tổng không vượt 10 |

**10 hạng mục CLO3** (mỗi hạng mục 0.5 điểm) và nơi cài đặt tương ứng:
| # | Hạng mục | Trong project |
|---|---|---|
| 1 | Wireshark bắt PCAP làm seed | `docs/HUONG_DAN_*`, `datasets/` |
| 2 | Cấu hình Boofuzz | `boofuzz_adapter.py` |
| 3 | Bit flipping + byte mutation + state graph | `mutation.py`, `state_machine.py` |
| 4 | Smart seed selection | `pcap.detect_sensitive_fields`, `Mutator.mutate` |
| 5 | Chạy chiến dịch vào IP thiết bị | `campaign.py`, `transport.py` |
| 6 | Script ping giám sát crash | `monitor.py`, lệnh `seedfuz monitor` |
| 7 | Đo tốc độ, crash, rò rỉ bộ nhớ | `CampaignMetrics` |
| 8 | Dashboard + SQLite | `api.py`, `static/`, `storage.py` |
| 9 | Pipeline upload PCAP, thanh tiến trình, báo cáo | `/api/pcaps`, `/api/campaigns`, `reporting.py` |
| 10 | Giám sát từ xa và cảnh báo an ninh | `/api/security`, sự kiện `security-alert` |

> Điểm cần cẩn trọng: đề cương ghi mục tiêu “nhanh gấp 2–3 lần”. Đây là **kỳ vọng**, không phải kết quả đã chứng minh. Báo cáo chỉ được khẳng định nếu có số liệu đo lặp lại.

**Tài liệu tham khảo đề cương đã nêu:** Boofuzz (Pereyda); AFLnet (Pham, Böhme, Roychoudhury, ICST 2020 – fuzzing giao thức mạng, greybox); Wireshark Network Analysis (Wright, Chappell); *Fuzzing: Hack, Art, and Science* (Godefroid, CACM 2012); OWASP IoT Top 10 (2023); *Coverage-based Greybox Fuzzing as Markov Chain* (Böhme, TSE 2019). Thư mục `papers/` hiện trống, nên chưa có bản tải về.

**So với fuzzing có phản hồi độ phủ (AFL, AFLnet):** các công cụ đó dùng độ phủ code để quyết định seed nào đáng đột biến tiếp. Router/camera thương mại không cho instrument firmware, nên SeedFuz phải dùng heuristic bề mặt (vị trí byte, giá trị biên, delimiter, độ dài). Đây là lý do và cũng là hạn chế của cách chọn “thông minh”.

## 12. Lớp ứng dụng: API, CLI, dashboard

### 12.1 Dòng dữ liệu
```
Trình duyệt ──POST /api/pcaps──► lưu datasets/uploads, phân tích sơ bộ
          ──POST /api/campaigns──► CampaignRunner chạy trên thread nền
          ◄──GET /api/campaigns/{id}── metrics + 100 sự kiện + 500 mẫu health
```

### 12.2 REST API (`api.py`)
| Endpoint | Việc làm |
|---|---|
| `GET /api/health` | Kiểm tra dịch vụ |
| `POST /api/pcaps` | Nhận `.pcap/.cap/.pcapng`, ≤100 MiB, đọc tối đa 100.000 gói; trả số gói, số seed, giao thức, state graph, 20 trường nhạy cảm đầu của seed đầu tiên |
| `POST /api/campaigns` | Nhận `config_json` (form), tạo campaign, chạy thread nền |
| `GET /api/campaigns`, `/{id}` | Danh sách / chi tiết |
| `GET /api/campaigns/{id}/events?after=` | Lấy sự kiện mới (thăm dò định kỳ) |
| `POST /api/campaigns/{id}/stop` | Đặt cờ dừng; 409 nếu không đang chạy |
| `GET /api/security` | Tổng hợp thiết bị `vulnerable`/`unreachable` và 50 cảnh báo gần nhất |
| `GET .../report.csv`, `report.pdf` | Xuất báo cáo |

**Ràng buộc an toàn trong API:** tên file upload được lọc ký tự (`_safe_name`); `seed_path` bắt buộc nằm trong thư mục upload (chặn đọc file tuỳ ý); sai định dạng thì xoá file đã lưu; lỗi campaign được lưu vào DB, không làm sập server.

**Thread nền:** `RunnerRegistry` giữ runner và thread (daemon), `stop()` gọi `runner.stop()` (đặt `threading.Event`). Campaign chỉ kiểm tra cờ dừng ở đầu mỗi test case.

### 12.3 CLI (`cli.py`, lệnh `seedfuz`)
| Lệnh | Việc làm |
|---|---|
| `analyze <pcap> [--json]` | Số gói, seed, giao thức, state graph, trường nhạy cảm |
| `run <config.json> [--database]` | Chạy campaign, in `campaign_id` và metrics |
| `report <id> --format csv\|pdf` | Xuất báo cáo vào `results/<id>.<ext>` |
| `serve [--host --port]` | Chạy API + dashboard (uvicorn) |
| `monitor --host ... [--tcp-port\|--http-url] [--interval --count]` | Heartbeat độc lập, in `UP`/`DOWN` kèm mili-giây từ lúc bắt đầu, báo thời điểm xuống/lên lại. **Chính là “script ping” theo đề cương** |

Khác biệt: `run` qua CLI chạy đồng bộ ở foreground; qua API thì chạy thread nền.

### 12.4 Dashboard (`static/index.html`, `app.js`, `styles.css`)
Trang tĩnh phục vụ ở `/`: upload PCAP, cấu hình và chạy campaign, hiển thị tiến trình, tốc độ, crash, xu hướng bộ nhớ, bảng cảnh báo, lịch sử có lọc, tải CSV/PDF. Dữ liệu cập nhật qua việc gọi API định kỳ (polling), không dùng WebSocket.

## 13. Mô hình dữ liệu và lưu trữ

### 13.1 SQLite (`storage.py`) – 4 bảng
| Bảng | Khoá/cột chính | Dùng để |
|---|---|---|
| `campaigns` | `id`, `status`, `config_json`, `metrics_json`, `error`, thời gian | Cấu hình và chỉ số cuối/đang chạy |
| `test_cases` | `campaign_id`+`case_number` (duy nhất), `seed_index`, `operator`, `offsets_json`, `payload_hex`, `response_hex`, `outcome`, `duration_ms` | Từng gói đã gửi, đủ để **tái lập** |
| `health_samples` | `alive`, `latency_ms`, `memory_percent`, `detail` | Chuỗi thời gian sức khỏe thiết bị |
| `events` | `level`, `kind`, `message`, `data_json` | Nhật ký: `campaign-started`, `send-error`, `target-crash`, `security-alert`, `target-recovered`, `recovery-timeout`... |

Xoá campaign kéo theo xoá dữ liệu con (`ON DELETE CASCADE`). Mỗi campaign dùng id sinh ngẫu nhiên.

### 13.2 Vòng đời trạng thái campaign
`created → running → completed | stopped | failed` (`CampaignStatus`).

### 13.3 Xuất báo cáo (`reporting.py`)
- **CSV:** mỗi dòng một test case với các cột `case_number, seed_index, operator, offsets_json, bytes_sent, outcome, duration_ms, created_at, payload_hex, response_hex`. Đủ để phân tích bằng Excel/pandas và tái lập từng gói.
- **PDF (ReportLab):** tiêu đề, tên campaign, bảng chỉ số, danh sách sự kiện đã ghi.

## 14. Dữ liệu mẫu và kiểm thử

### 14.1 PCAP mẫu
`scripts/generate_sample_pcap.py` tự dựng bằng `struct` một PCAP cổ điển với IP nguồn `192.168.1.2` → đích `192.168.1.50`, cổng `50000` → `8080`, payload giả lập HTTP (`GET /status ...`) và `SET name=device&id=1`. Dùng cho dry-run và demo, **không** phải dữ liệu thiết bị thật.

### 14.2 Bộ test (pytest, 9 file trong `tests/`)
| File | Kiểm tra |
|---|---|
| `test_pcap.py` | Đọc TCP, PCAPNG, IPv6; từ chối file không phải PCAP; header/delimiter được chấm điểm cao |
| `test_mutation.py` | Bit flip đổi đúng 1 bit; có smart mutation trong vòng xoay; tái lập; `preserve_session` giữ nguyên token |
| `test_state_machine.py` | Chuyển trạng thái đúng thứ tự; tìm được dải cookie/token |
| `test_config.py` | Dry-run không cần `authorized`; mạng cần `authorized`; chặn IP public |
| `test_campaign.py` | Dry-run đầu-cuối; smart selection phủ trường nhạy cảm; crash ghi payload và hồi phục |
| `test_monitor.py` | Dò cổng TCP mở/đóng; HTTP 5xx coi là down; CLI `monitor`; hồi quy bộ nhớ phát hiện tăng |
| `test_api.py` | Upload pcap/pcapng, `/api/security` |
| `test_storage.py` | Lưu campaign, case, sự kiện |

Chạy: `python -m pytest`. Test cần phần cứng phải gắn `@pytest.mark.hardware` và không chạy mặc định.

**Chưa có test riêng cho:** `reporting.py` (PDF), `boofuzz_adapter.py`, nhánh `SocketTransport` với thiết bị thật, `recovery_command`. Đây là phần nên nêu khi báo cáo “giới hạn kiểm thử”.

## 15. Những chỗ dễ hiểu sai (đối chiếu giữa đề cương và code)
1. **“Dùng Boofuzz”** (đề cương) nhưng campaign chạy bằng mutator riêng; Boofuzz chỉ là adapter dựng session. Phải giải thích rõ trong báo cáo.
2. **“Đồ thị trạng thái”**: chỉ suy luận từ cờ TCP, chưa theo logic giao thức ứng dụng.
3. **“Tham số nhạy cảm (độ dài, ID)”**: code chấm điểm theo heuristic byte; không hiểu ID là gì. ID/độ dài chỉ được nhận ra nếu trùng mẫu giá trị.
4. **“Thiết bị crash ở giây thứ mấy”**: có timestamp của mẫu health đầu tiên thất bại thứ `crash_threshold`, độ phân giải bằng chu kỳ `monitor_interval`; chưa phải mili-giây chính xác của lúc crash thật. Lệnh `seedfuz monitor` độc lập cho độ phân giải tốt hơn.
5. **Giám sát chỉ chạy khi có mạng** (`protocol != dry-run`); chế độ dry-run không có monitor nên `security_status = "not-monitored"`.
6. **TCP**: mỗi test case mở một kết nối mới, không giữ phiên; không hỗ trợ TLS.

## 16. Việc còn thiếu để đủ bằng chứng cho báo cáo
- PCAP từ router/camera thật và kết quả chạy phần cứng (CLO4: 0.75 điểm).
- Số liệu so sánh baseline với smart selection, lặp nhiều lần.
- Khảo sát công trình liên quan (CLO1.1) và nội dung `papers/`.
- Kế hoạch và phân công nhóm (CLO6) – chưa thấy trong repo.

---

# Phần rà soát lần 2: kiến thức còn thiếu đã bổ sung

## 17. Hướng dẫn của GVHD cho giai đoạn phần cứng (từ báo cáo tuần 1, mục 8)

1. **Mạng lab cô lập hoàn toàn** khỏi Internet.
2. **Hai nhánh thiết bị:**
   - Router/camera thương mại: “hộp đen”, thường không có shell nên **không lấy được RAM/CPU**. Chỉ dựa vào ping, cổng TCP, mã HTTP 5xx.
   - Bo mạch nhúng (ESP32, Raspberry Pi) nạp firmware có lỗ hổng chủ đích: lấy log, telemetry bộ nhớ qua Serial/SSH, xác định chính xác crash hoặc tràn bộ đệm. Đây là nhánh duy nhất đo được rò rỉ bộ nhớ một cách đáng tin.
3. **Xác định bề mặt tấn công bằng Nmap** (`nmap -sV <IP>`): liệt kê cổng mở.
4. **Ưu tiên dịch vụ không cần đăng nhập trước** (UPnP, DHCP, DNS) để kiểm chứng pipeline; sau đó mới sang Web Admin (cần `preserve_session`).
5. **Lọc PCAP** bằng filter Wireshark: bỏ ARP/broadcast, chỉ giữ luồng TCP/UDP của dịch vụ mục tiêu.
6. **Khôi phục khi treo:** khởi động lại (thủ công hoặc ổ cắm thông minh qua `recovery_command`) rồi tiếp tục.
7. **Đối chứng A/B:** cùng số gói, `smart_selection` false so với true.

| Cổng | Dịch vụ | Cần đăng nhập? | Ghi chú |
|---|---|---|---|
| 80/443 | Web Admin | Thường có | Cần giữ cookie/token |
| 53 | DNS | Thường không | Thử sớm |
| 1900 | UPnP/SSDP (UDP) | Thường không | Thử sớm |
| 67/68 | DHCP (UDP) | Không | Thử sớm |

> Báo cáo tuần 1 viết “chưa hỗ trợ PCAPNG và IPv6”. Thông tin này đã **lỗi thời**: code hiện đọc được cả hai (mục 3.3).

## 18. Quy trình vận hành an toàn trên thiết bị thật (từ `HUONG_DAN_CHAY_VA_TEST.md` mục 11–14)

**Cổng kiểm soát trước khi gửi:** `ping`, `nc -vz`, `seedfuz analyze`, kiểm tra JSON cấu hình; cổng WAN trống hoặc bị chặn; IP đúng mục tiêu; có người sẵn sàng ngắt nguồn; thiết bị không chứa dữ liệu thật.

**Bậc thang tăng tải:**
1. Dry-run với PCAP thật (`max_cases` ≈ 50).
2. Smoke 10–50 case, delay 0.5–1.0 s.
3. 100–500 case, delay 0.1–0.5 s.
4. Chiến dịch dài, có người giám sát. Mỗi lần chỉ đổi **một nhóm biến**.

**Phân loại sự cố:** dừng gửi → ghi giờ, case, campaign ID → kiểm tra ICMP hay dịch vụ mất (`nc -vz`) → chờ hồi phục → power-cycle → factory reset chỉ khi bắt buộc. **Crash đáng tin cần ≥2 tín hiệu** (mất ping và mất dịch vụ, hoặc log watchdog); không kết luận từ một lần timeout.

**Dừng khẩn cấp:** CLI `run` dừng bằng `Ctrl+C`. API có `POST /stop` nhưng **dashboard chưa có nút dừng**.

**Endpoint telemetry bộ nhớ:** HTTP GET trả JSON `{"memory_percent": 42.5}` (số trong 0–100), chỉ tồn tại trong lab. Không có endpoint thì chỉ số hiển thị `—`; **không được suy ra “không rò rỉ”**.

**Dữ liệu cần lưu mỗi campaign (phục vụ báo cáo):** campaign ID; hash hoặc phiên bản PCAP; model/firmware thiết bị; config JSON; số case thành công/lỗi; packet/giây; thời điểm crash đầu tiên; số crash xác nhận; mẫu bộ nhớ; CSV/PDF/SQLite; cách hồi phục. Lặp nhiều lần, **đổi thứ tự chạy** baseline/smart để giảm thiên lệch do nóng máy hoặc trạng thái tích lũy.

## 19. Cách đo từng chỉ số của đề cương từ dữ liệu SeedFuz

| Chỉ số đề cương | Lấy từ đâu | Lưu ý trung thực |
|---|---|---|
| Tốc độ fuzzing (gói/giây) | `metrics.packets_per_second` = `sent_cases / thời gian trôi` | Bao gồm cả `delay_seconds`, nên phụ thuộc cấu hình; dry-run mẫu 100 case ≈ 46 case/s |
| Số crash | `metrics.crashes` và sự kiện `target-crash` | Đếm lần vượt `crash_threshold`, **chưa loại trùng** |
| Giây thứ mấy crash | `timestamp` trong `target-crash`, `case` | Độ phân giải = chu kỳ health-check |
| Số case đến crash đầu tiên | Số `case` của sự kiện `target-crash` đầu tiên | Không có metric riêng; phải truy vấn `events` |
| Rò rỉ bộ nhớ | `metrics.memory_leak_rate` (điểm % / mẫu) | Chỉ có khi có telemetry |
| Độ phủ trường nhạy cảm | `metrics.sensitive_fields_covered` | Đếm cặp (seed, trường) đã bị chạm đột biến, cả baseline cũng được tính nếu byte ngẫu nhiên rơi vào trường |
| Tái lập | `payload_hex` ở `test_cases` và `last_payload_hex` ở sự kiện crash | Cần cùng `random_seed` để lặp cả chuỗi |

Truy vấn mẫu để lấy case đến crash đầu tiên:
```bash
sqlite3 results/seedfuz.db \
 "SELECT json_extract(data_json,'$.case') FROM events WHERE campaign_id='<id>' AND kind='target-crash' ORDER BY id LIMIT 1;"
```

**Số liệu dry-run tham chiếu** (báo cáo tuần 1): 100 case, 100 gửi, 0 lỗi, 0 crash, 3150 byte, phân bố 34 bit-flip / 33 byte-boundary / 33 smart-field. Chỉ chứng minh pipeline chạy, **không** chứng minh khả năng tìm lỗi.

## 20. Điểm không khớp giữa tài liệu và code (cần sửa hoặc nêu rõ)
1. **“Crash duy nhất”** xuất hiện trong README và hướng dẫn báo cáo, nhưng code **chưa loại trùng** crash. Hoặc bổ sung tính năng, hoặc không dùng thuật ngữ này.
2. **“Thời gian đến crash đầu tiên”** chưa là metric có sẵn; phải suy từ bảng `events`.
3. **Nút dừng** có ở API, chưa có ở dashboard.
4. **Boofuzz**: đề cương ghi “nạp vào Boofuzz”, code chính dùng mutator riêng.
5. **Báo cáo tuần 1** còn ghi thiếu PCAPNG/IPv6 và “13 test”; cần cập nhật theo code hiện tại.
6. **Đề cương nhắc “script ping”**; code có cả ba cách (ping/TCP/HTTP) và lệnh `seedfuz monitor`.

## 21. Kiến thức nền bổ sung
- **Nmap**: quét cổng; `-sV` dò phiên bản dịch vụ.
- **tcpdump / Wireshark filter**: ví dụ `tcp.port == 80 && ip.addr == <IP>`, `udp.port == 1900`, loại bỏ `arp || broadcast`.
- **UPnP/SSDP** (UDP 1900): thiết bị quảng bá dịch vụ bằng bản tin dạng HTTP qua UDP, không đăng nhập; thường dễ fuzz.
- **DHCP** (UDP 67/68): cấp IP, cấu trúc nhị phân cố định, có trường độ dài option — mục tiêu điển hình của heuristic độ dài.
- **Watchdog**: bộ đếm trong firmware tự reset thiết bị khi tiến trình treo; là “tín hiệu thứ hai” xác nhận crash.
- **Power-cycle / smart plug**: tắt rồi bật nguồn để hồi phục; gắn vào `recovery_command`.
- **Fuzzing có phản hồi độ phủ** (AFL/AFLnet): dùng instrumentation để biết input nào đi vào code mới; không áp dụng được cho router đóng.
- **Độ tin cậy thống kê**: một cặp chạy baseline/smart chưa đủ; cần lặp, báo cáo trung bình và độ lệch.

## 22. Kết luận rà soát
Sau phần 11–21, tài liệu bao phủ: yêu cầu trường, thuật toán và code, vận hành an toàn, đo lường, lưu trữ, API/CLI, test. **Chưa thể bao phủ** những thứ chỉ có sau khi chạy thật: PCAP và đặc tả thiết bị thật, số liệu A/B, kết quả crash/bộ nhớ, kế hoạch phân công nhóm.
