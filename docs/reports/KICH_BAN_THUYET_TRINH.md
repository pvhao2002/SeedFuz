# Kịch bản thuyết trình & demo SeedFuz

Dựa trên `docs/word/SLIDE_SEEDFUZ.pptx` (22 slide). Thứ tự trình bày: **Cường → Đăng → Đức**.
Tổng thời lượng dự kiến: **~22 phút** + hỏi đáp.

| Người | Slide | Nội dung | Thời gian |
|---|---|---|---|
| **Cường** | 1 – 7 | Mở đầu, bối cảnh, mục tiêu, cơ sở lý thuyết | ~6 phút |
| **Đăng** | 8 – 17 | Thuật toán, phân tích – thiết kế, **Demo 1: Dashboard** | ~9 phút |
| **Đức** | 18 – 22 | Kiểm thử, thí nghiệm A/B, **Demo 2: test + A/B**, kết luận | ~7 phút |

---

## Chuẩn bị trước buổi báo cáo (cả nhóm, làm trước 15 phút)

```bash
cd SeedFuz
source .venv/bin/activate
python -m pip install -e .            # đảm bảo lệnh `seedfuz` chạy được
python scripts/generate_sample_pcap.py # tạo datasets/sample_http.pcap nếu chưa có
python -m pytest -q                   # chạy thử 1 lần: phải thấy 26 passed
```

- Mở sẵn **2 cửa sổ terminal** (chữ cỡ lớn, nền tối) và **1 tab trình duyệt**.
- Terminal 1: chạy sẵn `seedfuz serve --host 127.0.0.1 --port 8000` → tab trình duyệt mở `http://127.0.0.1:8000`.
- Terminal 2: đứng ở thư mục gốc project, dành cho Đức.
- Mở sẵn thư mục chứa `datasets/sample_http.pcap` để kéo thả.
- **Phương án dự phòng:** chụp màn hình Dashboard sau khi chạy xong + file `results/demo-report.pdf` để chiếu nếu demo lỗi.

---

## PHẦN 1 — CƯỜNG (Slide 1 – 7)

### Slide 1 — Trang bìa (~30s)

> Em chào thầy và hội đồng. Nhóm em gồm Cường, Đăng và Đức, xin trình bày khóa luận **"SeedFuz – Tối ưu hóa Mutational Fuzzing với cơ chế chọn hạt giống thông minh trong dò quét lỗ hổng IoT"**, dưới sự hướng dẫn của thầy Đinh Huy Hoàng.
>
> Bài trình bày gồm ba phần: em trình bày bối cảnh và cơ sở lý thuyết; bạn Đăng trình bày thuật toán, thiết kế hệ thống và demo Dashboard; bạn Đức trình bày kết quả kiểm thử, thí nghiệm A/B và kết luận.

### Slide 2 — Vì sao cần fuzzing thông minh cho IoT (~1 phút)

> Router, camera IP, cảm biến… phần lớn chạy firmware viết bằng C/C++, được tối ưu chi phí nên phần xử lý dữ liệu đầu vào thường ít được kiểm thử.
>
> Chỉ một gói tin dị dạng cũng có thể gây tràn bộ đệm, cạn tài nguyên, treo dịch vụ hoặc làm thiết bị khởi động lại. Ví dụ kinh điển: trường độ dài khai báo **10 ký tự** nhưng thực tế gửi **10.000 ký tự** → tràn bộ đệm.
>
> Vấn đề là fuzzing ngẫu nhiên rất tốn thời gian: phần lớn đột biến rơi vào những byte ít ý nghĩa, hiếm khi chạm đúng trường nhạy cảm.
>
> Vì vậy nhóm xây dựng **SeedFuz**: lấy gói tin PCAP thật làm hạt giống, suy luận trạng thái giao thức, và **ưu tiên đột biến** các trường độ dài, định danh, ký tự phân tách.

### Slide 3 — Mục tiêu và phạm vi (~1 phút)

> Đề tài có 5 mục tiêu: (1) hệ thống hóa lý thuyết về bề mặt tấn công IoT, gói tin, PCAP, đồ thị trạng thái; (2) cài đặt bit flipping, byte mutation và đột biến trường nhạy cảm; (3) xây dựng kiến trúc module hoàn chỉnh từ parser đến báo cáo; (4) Web Dashboard theo dõi thời gian thực; (5) thí nghiệm A/B so sánh fuzzing ngẫu nhiên với chọn hạt giống thông minh.
>
> Về phạm vi: nhóm chạy dry-run và TCP/UDP trên lab được cấp phép, thí nghiệm có kiểm soát trên bộ seed mẫu. Nhóm **không** làm khai thác lỗ hổng, không chạy trên môi trường sản xuất.

### Slide 4 — Bề mặt tấn công IoT (~1 phút)

> Một thiết bị IoT điển hình mở nhiều dịch vụ: HTTP/HTTPS cổng 80/443, UPnP/SSDP cổng UDP 1900, DNS/DHCP, RTSP 554 trên camera. Mỗi cổng mở là một điểm nhận dữ liệu từ bên ngoài, trong khi firmware thường thiếu ASLR, stack canary, kiểm tra biên.
>
> Mô hình đe dọa của nhóm: kẻ tấn công cùng mạng LAN/WiFi, **black-box**, chỉ quan sát phản ứng bên ngoài. Bốn loại lỗi chính nhóm nhắm tới: tràn bộ đệm, cạn kiệt tài nguyên, lỗi parsing và rò rỉ bộ nhớ.

### Slide 5 — Phân loại fuzzing và vị trí SeedFuz (~1 phút)

> Fuzzing được phân loại theo ba trục: cách sinh đầu vào (mutation hay generation), mức hiểu biết về mục tiêu (black-box hay grey/white-box), và có mô hình trạng thái hay không.
>
> SeedFuz chọn **mutation-based, black-box, state-aware**: đột biến từ PCAP thật nên không cần đặc tả giao thức, chi phí triển khai thấp, nhưng vẫn có đồ thị trạng thái suy luận để gửi gói đúng thứ tự.

### Slide 6 — Cấu trúc gói tin và PCAP (~40s)

> Gói tin được đóng gói Ethernet → IP → TCP/UDP → payload. Nhóm chỉ đột biến **payload tầng ứng dụng**, vì nếu đột biến các tầng thấp như MAC, checksum, sequence thì ngăn xếp mạng sẽ loại bỏ ngay, rất lãng phí.
>
> Parser tự viết hỗ trợ IPv4, IPv6, VLAN, và cả hai định dạng PCAP cổ điển lẫn PCAPNG.

### Slide 7 — Suy luận đồ thị trạng thái (~40s)

> Fuzzing không trạng thái thường gửi gói vào sai thời điểm nên bị thiết bị bỏ qua. SeedFuz không cần đặc tả giao thức mà ánh xạ mỗi gói thành trạng thái dựa vào cờ TCP: SYN là syn-sent, SYN+ACK là syn-ack, gói có payload là application-data, RST là reset…
>
> Chuỗi trạng thái theo thời gian giúp chọn seed theo đúng thứ tự thực tế.
>
> **Chuyển lời:** Phần cơ sở lý thuyết em xin dừng ở đây. Tiếp theo, bạn Đăng sẽ trình bày cách nhóm đột biến dữ liệu và thiết kế hệ thống.

---

## PHẦN 2 — ĐĂNG (Slide 8 – 17 + Demo 1)

### Slide 8 — Ba phép đột biến xoay vòng (~1 phút)

> Em xin tiếp tục. SeedFuz dùng 3 phép đột biến, xoay vòng theo chỉ số test case chia lấy dư cho 3:
>
> - **Bit flipping**: đảo 1 bit ngẫu nhiên — thay đổi nhỏ nhất, dễ khoanh vùng nguyên nhân.
> - **Byte mutation**: thay 1 byte bằng giá trị biên như 00, 7F, 80, FF — bộc lộ lỗi số có dấu và kiểm tra biên mảng.
> - **Smart-field**: ghi đè cả trường độ dài/định danh bằng giá trị cực đại — nhắm thẳng vào tràn bộ đệm và lỗi parsing.

### Slide 9 — Chấm điểm trường nhạy cảm (~1 phút)

> Đây là điểm cải tiến chính của đề tài. Mỗi offset trong payload được **cộng dồn điểm** khi thỏa nhiều dấu hiệu: nằm trong header, gần ký tự phân tách, là giá trị biên, hoặc trông giống trường độ dài.
>
> Offset điểm cao được ưu tiên cho phép smart-field. Cách này không cần biết trước giao thức nên áp dụng chung cho HTTP, SSDP, DNS, RTSP. Và nhóm vẫn giữ **2/3 lượt ngẫu nhiên** để bù sai số của heuristic — tức là dồn trọng tâm nhưng không bỏ khám phá.

### Slide 10 — Khảo sát công cụ (~40s)

> So với Boofuzz, AFLNet, Peach: AFLNet cần biên dịch lại firmware để lấy độ phủ, Boofuzz và Peach cần viết đặc tả giao thức. SeedFuz nhắm vào thiết bị đóng: không cần mã nguồn, không cần đặc tả. Đề tài liên quan trực tiếp đến các hạng mục OWASP IoT Top 10: I2, I3, I5, I8.

### Slide 11 — Nghiệp vụ một chiến dịch (~40s)

> Một chiến dịch gồm 4 bước: trinh sát bằng Nmap để liệt kê cổng; thu seed bằng Wireshark; sinh và gửi gói đột biến theo trạng thái với giới hạn số case, độ trễ, timeout; cuối cùng là giám sát, ghi crash kèm hex payload và tự động khôi phục thiết bị.

### Slide 12 — Yêu cầu chức năng / phi chức năng (~40s)

> Nhóm đặc tả 10 yêu cầu chức năng từ RF-01 phân tích PCAP đến RF-10 cảnh báo an ninh. Về phi chức năng, **an toàn là ràng buộc hàng đầu**: chặn mục tiêu IP public, bắt buộc xác nhận được cấp phép. Ngoài ra là tính tái lập — cùng random seed cho ra cùng chuỗi đột biến — và đo hiệu năng packets/giây thời gian thực.

### Slide 13 — Kiến trúc phân tầng (~30s)

> Hệ thống chia 4 tầng: tầng trình bày gồm Web Dashboard và CLI; tầng dịch vụ là FastAPI chạy chiến dịch nền; tầng lõi fuzzing; và tầng dữ liệu SQLite cùng báo cáo CSV/PDF.

### Slide 14 — Module lõi (~30s)

> Mỗi module một trách nhiệm: `pcap.py` đọc capture và chấm điểm trường, `state_machine.py` dựng đồ thị trạng thái, `mutation.py` sinh đột biến tái lập được, `campaign.py` điều phối và đo chỉ số, `transport` và `monitor` lo gửi gói và giám sát.

### Slide 15 — Cơ sở dữ liệu và REST API (~40s)

> SQLite có 4 bảng: campaigns, test_cases, health_samples, events. Đặc biệt mỗi test case đều lưu **hex payload** để tái lập lỗi. API FastAPI cung cấp upload PCAP, tạo/dừng chiến dịch, đọc sự kiện, tổng hợp cảnh báo và xuất báo cáo.

### Slide 16 — Cơ chế an toàn và giám sát (~40s)

> Mặc định hệ thống chạy **dry-run** — không gửi gói ra mạng. Muốn chạy TCP/UDP phải bật `authorized = true`, và IP public luôn bị chặn. Crash chỉ được ghi khi **2 lần giám sát hỏng liên tiếp** để giảm báo động giả. Giám sát black-box qua 3 tín hiệu: ping, TCP connect, HTTP 5xx; nếu thiết bị có endpoint bộ nhớ thì dùng hồi quy tuyến tính ước lượng rò rỉ.

### Slide 17 — Web Dashboard → **DEMO 1** (~4 phút)

> Sau đây em xin demo trực tiếp Web Dashboard.

*(Chuyển sang trình duyệt `http://127.0.0.1:8000`.)*

| Bước | Thao tác | Lời nói |
|---|---|---|
| 1 | Kéo thả `datasets/sample_http.pcap` vào ô **"Kéo thả PCAP vào đây"** | "Em nạp file PCAP bắt từ lưu lượng HTTP bình thường. Hệ thống phân tích ngay: **2 gói tin, 2 seed**, và đồ thị trạng thái start → application-data → end." |
| 2 | Giữ cấu hình: Dry-run, **100** test case, seed **1337**, tick cả *Ưu tiên trường nhạy cảm* và *Bảo toàn thứ tự state machine* | "Em chạy ở chế độ dry-run cho an toàn. Random seed 1337 giúp chạy lại sẽ ra đúng chuỗi đột biến này." |
| 3 | Bấm **Bắt đầu chiến dịch** | "Campaign monitor cập nhật thời gian thực: số case đã gửi, tốc độ packets/giây, số crash, thanh tiến trình và nhật ký sự kiện." |
| 4 | Chờ chạy xong (~vài giây) → bấm **Tải PDF** (và **Tải CSV**) | "Khi kết thúc, có thể xuất báo cáo PDF/CSV, trong đó mỗi test case kèm hex payload để tái lập." |
| 5 | Kéo xuống phần **Cảnh báo trạng thái an ninh** và **Lịch sử** | "Đây là bảng cảnh báo an ninh — khi thiết bị thật bị sập, sự kiện security-alert sẽ hiện ở đây; và lịch sử các chiến dịch có thể lọc lại." |
| 6 *(minh họa an toàn)* | Đổi Giao thức → **TCP**, IP `8.8.8.8`, tick *Tôi xác nhận có quyền…*, bấm chạy | "Nếu cố nhắm vào một IP public, hệ thống **từ chối** — nhật ký sự kiện báo *Không thể chạy: … Public targets are disabled*. Đây là cơ chế an toàn nhóm cài sẵn." → đổi lại Dry-run. |

> **Chuyển lời:** Phần thiết kế và demo Dashboard em xin kết thúc. Bạn Đức sẽ trình bày kết quả kiểm thử và thí nghiệm A/B.

---

## PHẦN 3 — ĐỨC (Slide 18 – 22 + Demo 2)

### Slide 18 — Kiểm thử tự động (~40s)

> Em xin trình bày kết quả. Hệ thống có **26 test, pass 26/26** trên 8 module kiểm thử bằng pytest, độ phủ toàn gói **73%** trên 1.123 câu lệnh, mã nguồn tuân thủ PEP 8 và qua kiểm tra ruff.
>
> Các test dùng dữ liệu tổng hợp: đọc PCAP TCP/PCAPNG/IPv6, bit flip, tính tái lập, chuyển trạng thái, monitor, chặn mục tiêu public và chạy end-to-end.

**→ DEMO 2a (~40s)** — Terminal 2:

```bash
python -m pytest -q
```

> "Thầy có thể thấy kết quả: **26 passed**."

### Slide 19 — Thí nghiệm A/B: số test case để phủ đủ 20 trường (~1 phút)

> Thiết kế thí nghiệm: cùng máy, cùng seed `sample_http.pcap` gồm 2 payload với 20 trường nhạy cảm, chạy dry-run. 3 độ dài chiến dịch × 2 nhánh × 5 random seed = **30 lần chạy**. Hai nhánh chỉ khác nhau đúng một biến `smart_selection`.
>
> Kết quả: nhánh A ngẫu nhiên cần trung bình **khoảng 268** test case mới chạm đủ 20 trường, nhánh B thông minh chỉ cần **khoảng 60** — tức **ít hơn khoảng 4,5 lần**.

### Slide 20 — Tỷ lệ chạm và thông lượng (~1 phút)

> Ở nhánh B, **khoảng 57%** test case chạm trường nhạy cảm, so với **35%** ở nhánh A. Phân bố toán tử trên 1.000 case: nhánh A không có smart-field nào, nhánh B chia đều 1/3 cho mỗi phép.
>
> Quan trọng là thông lượng hai nhánh **tương đương**, nên lợi ích về độ phủ không phải đánh đổi bằng tốc độ.

**→ DEMO 2b (~2 phút)** — Terminal 2, chạy lại một lần A/B với cùng random seed 1337, 300 case:

```bash
seedfuz run experiments/ab_random.json   # nhánh A: smart_selection = false
seedfuz run experiments/ab_smart.json    # nhánh B: smart_selection = true
```

Chỉ vào các dòng trong kết quả JSON:

| Chỉ số | Nhánh A (random) | Nhánh B (smart) |
|---|---|---|
| `sensitive_fields_covered` | **19** / 20 | **20** / 20 |
| `operator_counts` | bit-flip 100, byte-boundary 200 | bit-flip 100, byte-boundary 100, **smart-field 100** |
| `packets_per_second` | ~tương đương | ~tương đương |

> "Cùng 300 test case, cùng random seed: nhánh ngẫu nhiên vẫn sót 1 trường, còn nhánh thông minh phủ đủ 20/20, và tốc độ hai bên như nhau. Đúng như kết quả thống kê trên slide."

*(Lưu ý: tốc độ thực tế phụ thuộc máy demo, chỉ nhấn mạnh là **hai nhánh ngang nhau**.)*

### Slide 21 — Hạn chế và hướng phát triển (~1 phút)

> Nhóm xin trung thực về hạn chế: hệ thống **chưa thực nghiệm trên router/camera thật**, nên chưa đo được crash và rò rỉ bộ nhớ thật; đồ thị trạng thái còn tổng quát, giao thức đăng nhập nhiều bước hoặc TLS cần adapter riêng; chấm điểm là heuristic; Dashboard chưa có xác thực người dùng.
>
> Hướng phát triển: dựng lab cô lập 192.168.50.0/24 với ESP32/Raspberry Pi chạy firmware có lỗ hổng chủ đích để làm A/B trên phần cứng; viết adapter HTTP/UPnP/RTSP/DNS và tích hợp sâu Boofuzz; chọn hạt giống học từ phản hồi; bổ sung xác thực, phân quyền và đóng gói Docker.

### Slide 22 — Kết luận (~40s)

> Tóm lại, nhóm đã chứng minh rằng một heuristic chấm điểm trường đơn giản có thể thay thế một phần tín hiệu độ phủ mã trong fuzzing black-box cho thiết bị IoT đóng: **ít hơn 4,5 lần** test case để phủ đủ trường nhạy cảm, **57%** test case chạm trường nhạy cảm so với 35%, hệ thống đạt **26/26** test với độ phủ 73%.
>
> Nhóm em xin cảm ơn thầy Đinh Huy Hoàng đã hướng dẫn, cảm ơn thầy và hội đồng đã lắng nghe. Nhóm em sẵn sàng nhận câu hỏi.

---

## Phân công trả lời câu hỏi

| Chủ đề câu hỏi | Người trả lời chính |
|---|---|
| Lý thuyết fuzzing, IoT, PCAP, state machine, phạm vi đề tài | **Cường** |
| Thuật toán chấm điểm, đột biến, kiến trúc, API, Dashboard, an toàn | **Đăng** |
| Kiểm thử, thiết kế thí nghiệm A/B, số liệu, hạn chế | **Đức** |

**Câu hỏi dễ gặp — gợi ý trả lời:**

- *"Sao chưa test trên thiết bị thật?"* (Đức) — Do giới hạn thời gian và yêu cầu an toàn/cấp phép; nhóm đã có sẵn cấu hình `experiments/hardware.example.json`, cơ chế giám sát ping/TCP/HTTP và recovery; hướng tiếp theo là lab ESP32/Raspberry Pi cô lập.
- *"Độ phủ trường có thật sự phản ánh khả năng tìm lỗi không?"* (Đức) — Đây là **proxy**, nhóm nêu rõ trong giới hạn; lỗi tràn bộ đệm/parsing thường nằm ở trường độ dài, định danh nên chạm được các trường này làm tăng xác suất kích hoạt lỗi.
- *"Heuristic chọn sai trường thì sao?"* (Đăng) — Vẫn giữ 2/3 lượt bit-flip và byte ngẫu nhiên để khám phá, nên không bỏ sót hoàn toàn vùng khác.
- *"Làm sao tái lập một crash?"* (Đăng) — Mỗi test case lưu operator, offset và hex payload trong SQLite/CSV; cùng random seed cho cùng chuỗi đột biến.
- *"Khác gì Boofuzz?"* (Cường) — Boofuzz cần tự viết đặc tả request; SeedFuz lấy trực tiếp PCAP thật, tự suy luận trạng thái và trường nhạy cảm; Boofuzz chỉ là adapter tùy chọn.
