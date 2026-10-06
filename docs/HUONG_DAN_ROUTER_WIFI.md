# Hướng dẫn chạy SeedFuz với Router WiFi — dành cho người mới bắt đầu

> Tài liệu này viết cho người **chưa biết gì** về fuzzing, mạng hay Linux.
> Bạn chỉ cần biết dùng máy tính cơ bản. Làm **theo đúng thứ tự từ trên xuống**,
> mỗi bước có lệnh để **copy – dán**. Nếu kẹt, xem mục [Khắc phục sự cố](#13-khắc-phục-sự-cố).

---

## 🛑 ĐỌC TRƯỚC KHI LÀM — CẢNH BÁO AN TOÀN

Fuzzing là **cố tình gửi hàng ngàn gói tin "lỗi" để làm thiết bị treo/sập**. Vì vậy:

1. **Chỉ dùng router của chính bạn** (router cũ mua lại / router nhà mạng đã bỏ). Fuzzing router của người khác, của trường, của công ty, hay của nhà mạng là **phạm pháp**.
2. **KHÔNG cắm dây internet (cổng WAN) vào router mục tiêu.** Mạng lab phải **tách rời Internet**.
3. Fuzzing có thể làm router **mất cấu hình, treo, hoặc hỏng luôn**. Hãy chấp nhận rủi ro đó với một chiếc router bạn sẵn sàng vứt đi.
4. Router đang chạy sẽ **tự khởi động lại** nhiều lần — đó là điều bình thường trong thí nghiệm này.

Nếu bạn chỉ muốn **thử cho biết mà chưa có router**, hãy làm [Phần A — Tập dượt không cần router](#phần-a--tập-dượt-trên-máy-không-cần-router) rồi dừng lại. Phần đó hoàn toàn an toàn.

---

## 1. SeedFuz là gì? (giải thích trong 30 giây)

SeedFuz giúp bạn **tìm lỗi bảo mật trên router WiFi** theo 4 ý:

1. Bạn dùng **Wireshark** ghi lại các gói tin lúc router hoạt động bình thường → lưu thành file `.pcap` (gọi là **"hạt giống" / seed**).
2. SeedFuz đọc file đó, **tự sửa đổi (đột biến)** các gói tin thành phiên bản "nửa đúng nửa sai".
3. SeedFuz **bắn** các gói tin méo mó đó vào router, đồng thời **ping router liên tục** để biết router chết lúc nào.
4. Mọi thứ hiện trên một **trang web (Dashboard)**: tốc độ bắn, số lần router treo, biểu đồ bộ nhớ, và nút **tải báo cáo CSV/PDF**.

Điểm đặc biệt (**"Chọn hạt giống thông minh"**): thay vì sửa lung tung, SeedFuz ưu tiên sửa đúng các **trường nhạy cảm** (ô độ dài chuỗi, ô ID…) — nơi dễ gây lỗi nhất → tìm ra lỗi **nhanh gấp 2–3 lần**.

---

## 2. Bạn cần chuẩn bị gì (danh sách mua sắm)

| # | Thứ cần có | Ghi chú |
|---|---|---|
| 1 | **1 laptop/PC** | Sẽ cài Linux để chạy SeedFuz. Máy nào cũng được. |
| 2 | **1 router WiFi cũ** | Mục tiêu để fuzzing. Router nhà mạng cũ (TP-Link, Tenda, Totolink, router FPT/Viettel cũ…) đều ổn. |
| 3 | **1 dây mạng LAN** (dây Ethernet) | Nối laptop với router. |
| 4 | **1 USB ≥ 8GB** (chỉ khi cần cài Linux) | Để tạo USB cài Ubuntu. |

> Không cần switch, không cần thiết bị đắt tiền. **1 laptop + 1 router + 1 dây mạng** là đủ.

> **Giải pháp thay thế cho mục tiêu (GVHD gợi ý):** router thương mại là "hộp đen" — khó biết chính xác lúc nào nó crash. Nếu muốn **kiểm soát và quan sát lỗi rõ hơn**, có thể nạp một **firmware chứa lỗ hổng chủ đích** lên bo mạch nhúng như **ESP32** hoặc **Raspberry Pi**. Khi đó bạn lấy được log và **memory telemetry qua Serial/SSH**, xác nhận chính xác thời điểm tràn bộ đệm/crash. Có thể làm song song: router thương mại để chứng minh thực tế, ESP32/RPi để lấy số liệu chi tiết.

Sơ đồ mạng lab của chúng ta rất đơn giản — laptop nối thẳng vào router bằng dây, **router KHÔNG nối ra Internet**:

```
   ┌───────────────────────┐        dây mạng LAN        ┌────────────────────────┐
   │   LAPTOP (chạy SeedFuz)│ ─────────────────────────▶│   ROUTER WiFi (mục tiêu)│
   │   Ubuntu/Kali Linux    │                            │   IP: 192.168.50.1      │
   │   Wireshark + SeedFuz  │ ◀─────────────────────────│   (cổng WAN để TRỐNG)   │
   └───────────────────────┘                            └────────────────────────┘
          ▲
          │  cổng WAN của router KHÔNG cắm gì cả  → mạng lab tách rời Internet
```

Trong toàn bộ hướng dẫn, ta dùng các **con số ví dụ** sau (bạn có thể giữ nguyên vì đây là mạng riêng):

| Tên | Giá trị ví dụ | Nghĩa là gì |
|---|---|---|
| IP của router (mục tiêu) | `192.168.50.1` | Địa chỉ trang quản trị router. **Đây là thứ ta sẽ fuzzing.** |
| Cổng dịch vụ | `80` | Cổng web quản trị router (giao diện HTTP). |
| IP của laptop | tự động do router cấp | Router tự phát IP cho laptop (ví dụ `192.168.50.100`). |

> **Lưu ý:** Mỗi router có IP quản trị khác nhau (`192.168.1.1`, `192.168.0.1`, `192.168.50.1`…). Bước 6 sẽ chỉ cách **tìm đúng IP router của bạn**. Khi tìm được, hãy thay `192.168.50.1` trong các bước sau bằng IP thật đó.

---

## 3. Sơ đồ toàn bộ quy trình (để bạn biết mình đang ở đâu)

```
Phần A: Tập dượt (không router)  →  làm quen dashboard, an toàn 100%
        │
Phần B: Làm thật với router
   Bước 4  Cài Linux + Python
   Bước 5  Tải & cài SeedFuz
   Bước 6  Nối dây, tìm IP router, ping thử
   Bước 7  Dùng Wireshark bắt gói tin bình thường → file .pcap (seed)
   Bước 8  Mở Dashboard, kéo-thả .pcap vào
   Bước 9  Chạy thử "dry-run" an toàn trên dashboard
   Bước 10 FUZZING THẬT vào router + xem crash
   Bước 11 Đọc kết quả, tải báo cáo CSV/PDF
   Bước 12 (Nâng cao) Chứng minh "nhanh gấp 2-3 lần"
```

---

# PHẦN A — Tập dượt trên máy (không cần router)

Phần này giúp bạn hiểu SeedFuz **trước khi** đụng tới router. Chạy được trên cả **Windows, macOS, Linux**. Hoàn toàn an toàn vì dùng chế độ **dry-run** (chỉ giả lập, không gửi gì ra mạng).

### A.1. Cài Python
- Vào https://www.python.org/downloads/ tải **Python 3.10 trở lên**, cài đặt.
- **Windows:** khi cài nhớ **tích vào ô "Add Python to PATH"**.

### A.2. Tải SeedFuz và cài thư viện
Mở **Terminal** (macOS/Linux) hoặc **PowerShell** (Windows), gõ từng dòng:

```bash
# đi vào thư mục chứa SeedFuz (sửa lại đường dẫn cho đúng máy bạn)
cd duong-dan/den/SeedFuz

# tạo môi trường ảo (một "hộp" riêng cho thư viện, không làm bẩn máy)
python -m venv .venv

# bật môi trường ảo:
#   Windows (PowerShell):
.venv\Scripts\Activate.ps1
#   macOS / Linux:
source .venv/bin/activate

# cài tất cả thư viện cần thiết
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

> Sau khi bật môi trường ảo thành công, đầu dòng lệnh sẽ có chữ `(.venv)`.

### A.3. Tạo dữ liệu mẫu rồi mở Dashboard
```bash
# tạo một file .pcap mẫu để nghịch thử
python scripts/generate_sample_pcap.py

# mở trang Dashboard
python -m seedfuz serve
```
Mở trình duyệt vào địa chỉ: **http://127.0.0.1:8000**

### A.4. Nghịch thử trên Dashboard
1. **Kéo thả** file `datasets/sample_http.pcap` vào ô "Kéo thả PCAP vào đây".
2. Giữ nguyên **Giao thức = Dry-run** (an toàn, không bắn ra mạng).
3. Bấm **"Bắt đầu chiến dịch"**.
4. Xem các ô **Đã gửi / Tốc độ / Crash** nhảy số và **thanh tiến trình** chạy.
5. Khi xong, bấm **Tải CSV** / **Tải PDF** để xem báo cáo.

🎉 Nếu bạn thấy số liệu chạy và tải được báo cáo → bạn đã hiểu toàn bộ cách dùng. Giờ qua Phần B làm thật với router.

> Để dừng Dashboard: quay lại cửa sổ Terminal, nhấn **Ctrl + C**.

---

# PHẦN B — Làm thật với Router WiFi

> ⚠️ Theo yêu cầu đề cương, **fuzzing thật phải chạy trên Linux (Ubuntu hoặc Kali)**.
> Nếu laptop bạn đang là Windows, hãy làm Bước 4 để cài Ubuntu.

## Bước 4 — Cài Ubuntu (Linux) và Python

Nếu máy bạn **đã chạy Ubuntu/Kali** → bỏ qua, nhảy tới [Bước 5](#bước-5--tải-và-cài-seedfuz).

Cách dễ nhất cho người mới: **cài Ubuntu song song hoặc trên máy ảo**.

**Cách 1 — Máy ảo (khuyên dùng, không đụng vào Windows):**
1. Tải **VirtualBox**: https://www.virtualbox.org
2. Tải file cài **Ubuntu Desktop** (bản `.iso`): https://ubuntu.com/download/desktop
3. Mở VirtualBox → *New* → chọn file `.iso` Ubuntu → bấm Next liên tục → *Start* để cài.
   > Lưu ý: dùng máy ảo thì phần Wireshark bắt gói của router sẽ phức tạp hơn một chút (phải gắn card mạng ở chế độ *Bridged*). Người mới nên dùng **Cách 2** nếu có thể.

**Cách 2 — Cài Ubuntu thẳng lên một laptop cũ (bắt gói tin dễ nhất):**
1. Dùng phần mềm **Rufus** (https://rufus.ie) tạo USB cài Ubuntu từ file `.iso`.
2. Cắm USB, khởi động lại máy, vào Boot Menu (thường nhấn `F12`/`F2`/`Esc`), chọn boot từ USB.
3. Làm theo trình cài đặt Ubuntu trên màn hình.

Sau khi vào được Ubuntu, mở **Terminal** (nhấn `Ctrl + Alt + T`) và cài công cụ:
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git wireshark
```
> Khi cài Wireshark nó hỏi *"Should non-superusers be able to capture packets?"* → chọn **Yes**.

Cài xong, cho tài khoản của bạn quyền bắt gói (gõ 1 lần rồi **đăng xuất/đăng nhập lại**):
```bash
sudo usermod -aG wireshark $USER
```

---

## Bước 5 — Tải và cài SeedFuz

```bash
# chép thư mục SeedFuz vào máy (nếu dùng git), hoặc copy thủ công rồi cd vào
cd ~/SeedFuz          # sửa đường dẫn cho đúng

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Kiểm tra cài đúng chưa:
```bash
python -m pytest -q
```
Thấy dòng toàn dấu chấm và không có chữ `failed` là **OK**.

---

## Bước 6 — Nối dây, tìm IP router, và ping thử

### 6.1. Nối dây đúng cách
1. Lấy router WiFi cũ, **cắm nguồn** cho nó sáng đèn.
2. **KHÔNG cắm gì vào cổng WAN** (cổng màu khác, thường ghi `WAN` / `Internet`).
3. Dùng dây mạng nối **cổng LAN của router** ↔ **cổng mạng của laptop**.

### 6.2. Tìm IP của router (đây sẽ là "mục tiêu")
Trên Ubuntu, mở Terminal gõ:
```bash
ip route | grep default
```
Dòng kết quả ví dụ: `default via 192.168.50.1 dev ...`
→ **`192.168.50.1` chính là IP router của bạn.** Ghi nhớ con số này; các bước sau ta gọi nó là **IP_ROUTER**.

> Không ra kết quả? Thử rút–cắm lại dây, hoặc xem [Khắc phục sự cố](#13-khắc-phục-sự-cố).

### 6.3. Ping thử để chắc chắn laptop "nói chuyện" được với router
```bash
ping -c 4 192.168.50.1      # thay bằng IP_ROUTER của bạn
```
Thấy các dòng `64 bytes from ... time=...ms` là **laptop và router đã thông nhau** ✅

### 6.4. Quét "bề mặt tấn công" bằng Nmap (GVHD khuyến nghị)
Trước khi bắt seed, hãy xem router đang **mở những cổng/dịch vụ nào** để biết nên nhắm vào đâu:
```bash
sudo apt install -y nmap          # nếu chưa có
nmap -sV 192.168.50.1             # thay bằng IP_ROUTER của bạn
```
Kết quả liệt kê các cổng mở, thường gặp:
| Cổng | Dịch vụ | Ghi chú cho fuzzing |
|---|---|---|
| 80 / 443 | Web Admin (HTTP/HTTPS) | Nhiều dữ liệu, nhưng thường **cần đăng nhập** (xem Bước 10) |
| 53 | DNS | Thường **không cần đăng nhập** — nên thử trước |
| 1900 | UPnP | Thường **không cần đăng nhập** — nên thử trước |

> **Mẹo của GVHD:** giai đoạn đầu nên fuzzing các **dịch vụ không cần đăng nhập** (UPnP 1900, DHCP) để kiểm chứng pipeline chạy ổn, rồi mới sang Web Admin (cần xử lý session — xem Bước 10).

---

## Bước 7 — Dùng Wireshark bắt "hạt giống" (seed PCAP)

Mục tiêu: ghi lại **gói tin bình thường** giữa laptop và router để SeedFuz có mẫu mà đột biến.

1. Mở **Wireshark** (gõ `wireshark` trong Terminal, hoặc tìm trong menu ứng dụng).
2. Chọn đúng **card mạng đang nối với router** (thường tên `enpXsY` hoặc `eth0`; chọn cái có lưu lượng nhảy).
3. Nhấn nút **vây cá mập xanh** (góc trên trái) để **bắt đầu ghi**.
4. **Tạo lưu lượng bình thường:** mở trình duyệt, vào trang quản trị router: `http://192.168.50.1` (thay bằng IP_ROUTER). Đăng nhập, bấm vài menu. Mỗi click sẽ tạo gói tin HTTP — chính là seed ta cần.
   > Nếu trang quản trị dùng `https://` (có khóa), hãy thử trang `http://` thường để có gói tin dạng rõ (dễ fuzzing hơn cho người mới).
5. Sau ~30 giây, nhấn nút **vuông đỏ** để **dừng ghi**.
6. **Lọc sạch nhiễu (GVHD khuyến nghị):** gõ bộ lọc chỉ giữ đúng luồng dịch vụ mục tiêu, loại bỏ ARP/broadcast không liên quan. Ví dụ với Web Admin:
   ```
   tcp.port == 80 && !(arp || icmpv6)
   ```
   (dịch vụ khác đổi cổng tương ứng: `udp.port == 1900` cho UPnP, `udp.port == 53` cho DNS). Sau khi lọc, dùng **File → Export Specified Packets…** để chỉ xuất các gói còn hiển thị → seed sạch, ít gói rác.
7. Lưu file: **File → Save As…** (hoặc **Export Specified Packets…** nếu đã lọc ở bước 6), đặt tên `router_seed.pcap`. SeedFuz **đọc được cả `pcap` cổ điển lẫn `pcapng`** (định dạng mặc định của Wireshark) nên định dạng nào cũng nạp được.
8. Lưu file vào thư mục uploads của SeedFuz cho tiện:
   ```bash
   mkdir -p ~/SeedFuz/datasets/uploads
   # rồi chép router_seed.pcap vào đó (qua trình quản lý file, hoặc lệnh cp)
   ```

Kiểm tra nhanh file seed có dùng được không:
```bash
cd ~/SeedFuz && source .venv/bin/activate
python -m seedfuz analyze datasets/uploads/router_seed.pcap
```
Nếu thấy **`Unique payload seeds:`** là một số **lớn hơn 0** → file tốt ✅
Nếu bằng 0 → gói bạn bắt chưa có dữ liệu ứng dụng; quay lại bấm thêm vài trang web trên router rồi bắt lại.

---

## Bước 8 — Mở Dashboard và nạp seed

```bash
cd ~/SeedFuz && source .venv/bin/activate
python -m seedfuz serve
```
Mở trình duyệt: **http://127.0.0.1:8000**

Trên trang:
1. **Kéo thả** file `router_seed.pcap` vào ô upload.
2. Dưới ô upload sẽ hiện tóm tắt: số packet, số seed, giao thức, số trạng thái. Đây là bằng chứng SeedFuz đã **bóc tách Header/Payload và dựng State Machine** từ file của bạn.

---

## Bước 9 — Chạy thử "dry-run" trên dashboard (bắt buộc, để chắc chắn mọi thứ ổn)

Trước khi bắn thật, chạy một lần **dry-run** (không gửi ra router):
1. Mục **Giao thức** chọn **Dry-run**.
2. **Số test case** để `100`.
3. Bấm **Bắt đầu chiến dịch** → xem số liệu chạy → tải thử CSV/PDF.

Nếu dry-run chạy mượt → sang bước fuzzing thật.

---

## Bước 10 — 🎯 FUZZING THẬT vào router

> Giờ là lúc "bắn đạn thật". Router có thể treo/khởi động lại — **đó là mục đích**.

Trên Dashboard:
1. **Giao thức** chọn **TCP**.
2. Hiện ra 2 ô mạng — điền:
   - **IP thiết bị** = `192.168.50.1` (IP_ROUTER của bạn)
   - **Cổng** = `80`
3. **Tích vào ô "Tôi xác nhận có quyền kiểm thử thiết bị này"** (bắt buộc — SeedFuz chặn chạy nếu không tích).
4. **Số test case**: bắt đầu nhỏ, ví dụ `500`.
5. Để nguyên 2 ô đã tích sẵn: **"Ưu tiên trường nhạy cảm"** và **"Bảo toàn thứ tự state machine"**.
6. Bấm **Bắt đầu chiến dịch**.

Ngay khi chạy, SeedFuz sẽ **tự động ping router song song**. Theo dõi:
- Ô **Đã gửi** và **Tốc độ** (packets/giây) tăng dần.
- Ô **Crash** = số lần router **ngừng trả lời ping** (nghi treo/sập).
- Ô **Bộ nhớ** = xu hướng rò rỉ bộ nhớ (nếu router có hỗ trợ — xem phần nâng cao).
- **Nhật ký sự kiện** sẽ hiện dòng đỏ `target-crash` kèm **mốc thời gian chính xác router chết** — đây chính là "ghi lại thiết bị crash vào giây thứ mấy" mà đề cương yêu cầu.
- Mục **"Cảnh báo trạng thái an ninh"** (phía dưới trang) sẽ bật cảnh báo đỏ kèm payload nghi gây lỗi — đáp ứng yêu cầu "giám sát từ xa và cảnh báo trạng thái an ninh" của đề cương.

> **Giám sát "hộp đen" (GVHD lưu ý — đã hỗ trợ trong SeedFuz):** router thương mại không cho lấy RAM/CPU nếu không có quyền shell, nên **đừng kỳ vọng số liệu bộ nhớ** (để `memory_probe_url` là `null`, ô Bộ nhớ sẽ là `—`). Thay vào đó, `monitor.py` có thể coi thiết bị là "chết" theo **3 dấu hiệu mạng**: mất phản hồi **ping liên tục** (ICMP timeout), **cổng TCP đóng đột ngột**, hoặc trang quản trị trả về **mã lỗi HTTP 5xx (500/502)**. Bật bằng cấu hình trong file experiment:
> ```json
> "memory_probe_url": null,
> "monitor_http_url": "http://192.168.50.1/",   // ưu tiên: coi 5xx là chết
> "monitor_tcp_port": 80                          // hoặc: coi cổng đóng là chết
> ```
> (không điền cả hai thì SeedFuz tự quay về **ping**.) Kiểm tra tay nhanh:
> ```bash
> ping 192.168.50.1                    # ICMP còn sống không
> curl -s -o /dev/null -w "%{http_code}\n" http://192.168.50.1   # 200/404 = còn sống, 000/500/502 = nghi chết
> ```

> **Quy trình khôi phục khi router treo (GVHD yêu cầu — đã tự động hóa):** khi phát hiện `target-crash`, SeedFuz có thể **tự chờ thiết bị sống lại** trước khi bắn tiếp, nhờ 2 tùy chọn trong file cấu hình:
> ```json
> "recovery_wait_seconds": 30.0,                       // chờ tối đa 30s, poll tới khi ping/HTTP/TCP thông lại
> "recovery_command": "tapo-plug cycle --name router"  // (tùy chọn) lệnh khởi động lại qua ổ cắm thông minh
> ```
> Nếu để `recovery_command` là `null`, bạn **rút–cắm nguồn thủ công** trong lúc SeedFuz đang chờ. Khi thiết bị thông lại, nhật ký hiện `target-recovered` và chiến dịch chạy tiếp; nếu không kịp sẽ hiện `recovery-timeout`. Nhờ vậy các case sau không "bắn vào thiết bị đã chết".

> **Script heartbeat riêng (GVHD gợi ý "một script nhỏ liên tục ping/heartbeat"):** chạy độc lập để nhìn **chính xác mili-giây** thiết bị mất phản hồi:
> ```bash
> python -m seedfuz monitor --host 192.168.50.1                 # ping
> python -m seedfuz monitor --host 192.168.50.1 --tcp-port 80   # hoặc theo cổng TCP
> python -m seedfuz monitor --host 192.168.50.1 --http-url http://192.168.50.1/  # hoặc theo HTTP 5xx
> ```
> Mỗi dòng in mốc thời gian + UP/DOWN + số ms kể từ lúc bắt đầu; khi chuyển trạng thái sẽ in rõ `went DOWN at ...`.

> **Nếu mục tiêu là Web Admin cần đăng nhập (đã hỗ trợ):** bật `"preserve_session": true` trong file cấu hình — SeedFuz sẽ **giữ nguyên giá trị Cookie / Authorization / token** trong seed và chỉ đột biến phần thân dữ liệu, nhờ đó test case không bị "văng" khỏi phiên đăng nhập. Dù vậy, giai đoạn đầu vẫn nên fuzzing dịch vụ **không cần đăng nhập** trước (UPnP 1900, DHCP) như Bước 6.4.

> **Muốn dừng giữa chừng:** bấm vào chiến dịch và dùng API dừng, hoặc đơn giản tắt router rồi tắt trang. (Nút dừng qua API: `POST /api/campaigns/<id>/stop`.)

---

## Bước 11 — Đọc kết quả và tải báo cáo

Khi chiến dịch **Hoàn tất** (hoặc bạn dừng), khu vực báo cáo hiện ra:
- Bấm **Tải CSV** → file bảng tính liệt kê từng test case, loại đột biến, phản hồi, lỗi.
- Bấm **Tải PDF** → báo cáo tóm tắt đẹp để nộp: tốc độ fuzzing, số crash, xu hướng bộ nhớ.

Các con số quan trọng cho báo cáo khóa luận:
| Chỉ số | Xem ở đâu | Ý nghĩa đề cương |
|---|---|---|
| **Tốc độ Fuzzing** | ô "Tốc độ" / cột trong CSV | số gói tin/giây |
| **Số lượng Crash** | ô "Crash" / sự kiện `target-crash` | số lỗi phát hiện được |
| **Thời điểm crash** | Nhật ký sự kiện (có timestamp) | router chết vào giây thứ mấy |
| **Độ phủ trường nhạy cảm** | `sensitive_fields_covered` trong metrics | số trường nhạy cảm đã được đột biến (dùng so sánh A/B) |
| **Payload gây crash** | `last_payload_hex` trong sự kiện `target-crash` | hex gói cuối trước khi mất kết nối, để tái lập |
| **Rò rỉ bộ nhớ** | ô "Bộ nhớ" | xu hướng tăng bộ nhớ |

> **Đo rò rỉ bộ nhớ (tùy chọn, nâng cao):** chỉ hoạt động nếu router/thiết bị cung cấp một URL trả về JSON có trường `memory_percent`. Khi có, chạy bằng file cấu hình và điền `"memory_probe_url": "http://192.168.50.1/status.json"`. Đa số router rẻ **không có** endpoint này → ô Bộ nhớ sẽ hiện `—`, đó là bình thường.

---

## Bước 12 — (Nâng cao) Chứng minh "nhanh gấp 2–3 lần"

Đề cương yêu cầu so sánh **Fuzzing thường** với **Chọn hạt giống thông minh**. Cách làm:

Tạo 2 file cấu hình giống hệt nhau, chỉ khác dòng `smart_selection`. Dùng mẫu sau (sửa `target_host` thành IP_ROUTER của bạn):

**File `experiments/router_smart.json`** (thông minh — BẬT):
```json
{
  "name": "Router - smart seed ON",
  "seed_path": "datasets/uploads/router_seed.pcap",
  "protocol": "tcp",
  "target_host": "192.168.50.1",
  "target_port": 80,
  "authorized": true,
  "max_cases": 2000,
  "delay_seconds": 0.02,
  "smart_selection": true,
  "state_aware": true,
  "crash_threshold": 2
}
```

**File `experiments/router_random.json`** (thường — TẮT): y hệt trên nhưng đổi tên và `"smart_selection": false`.

Chạy lần lượt rồi so sánh **số test case tới crash đầu tiên** và **thời gian**:
```bash
python -m seedfuz run experiments/router_random.json   # chạy kiểu thường trước
python -m seedfuz run experiments/router_smart.json    # rồi chạy kiểu thông minh
```
Mỗi lệnh in ra JSON có `metrics`. Kiểu "thông minh" thường **tìm thấy crash sớm hơn / ít gói hơn** → đó là bằng chứng cải tiến. Lặp lại vài lần với `random_seed` khác nhau để lấy số trung bình cho báo cáo.

**Tiêu chí so sánh (GVHD) — đã có sẵn trong `metrics`:**
- `sent_cases` / số case tới khi `crashes` tăng → **số test case cần để crash**.
- `sensitive_fields_covered` → **độ phủ các trường nhạy cảm** (kiểu thông minh thường cao hơn hẳn kiểu ngẫu nhiên).
- `packets_per_second` và thời gian chạy → **thời gian thực thi**.

> **Lưu vết để tái tạo (GVHD yêu cầu — đã tự ghi):** khi crash, sự kiện `target-crash` trong nhật ký **đã kèm sẵn `last_payload_hex`** = chuỗi byte gói tin cuối cùng trước khi mất kết nối, nên bạn chỉ cần copy từ nhật ký/sự kiện là tái lập được. Muốn xem nhiều case quanh thời điểm crash thì truy vấn thêm:
> ```bash
> sqlite3 results/seedfuz.db \
>   "SELECT case_number, created_at, outcome, payload_hex FROM test_cases WHERE campaign_id='<id>' ORDER BY case_number DESC LIMIT 5;"
> ```
> Cột `payload_hex` chính là chuỗi byte gói tin; dòng có `outcome` báo crash (hoặc ngay trước nó) là test case cần lưu để tái lập.

Xuất báo cáo cho một chiến dịch đã chạy bằng CLI:
```bash
python -m seedfuz report <campaign_id> --format pdf
```
(`<campaign_id>` chính là chuỗi in ra trong kết quả JSON ở trên.)

---

## 13. Khắc phục sự cố

| Hiện tượng | Nguyên nhân & cách xử lý |
|---|---|
| `python: command not found` | Dùng `python3` thay cho `python`; hoặc cài lại Python và nhớ tích "Add to PATH". |
| Bật venv báo lỗi trên Windows | Chạy PowerShell với quyền Admin: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` rồi thử lại. |
| `ip route` không có dòng `default` | Dây mạng lỏng, hoặc router chưa cấp IP. Rút–cắm lại dây; chờ 20 giây; thử `sudo dhclient`. |
| `ping` router **không** phản hồi | Sai IP router (xem lại Bước 6.2); hoặc router chặn ICMP (vẫn fuzzing TCP được bình thường). |
| Upload PCAP báo file không hợp lệ | SeedFuz đọc cả `pcap` và `pcapng`; nếu vẫn lỗi, file có thể bị hỏng — lưu lại từ Wireshark hoặc bắt lại. |
| `Unique payload seeds: 0` | File bắt chưa có dữ liệu ứng dụng. Vào lại trang web router bấm nhiều hơn, rồi bắt lại. |
| Dashboard không mở được | Kiểm tra Terminal còn chạy `serve` không; mở đúng `http://127.0.0.1:8000`. |
| Bấm chạy TCP báo "requires authorized=true" | Bạn quên **tích ô xác nhận quyền kiểm thử** ở Bước 10. |
| Báo "Public targets are disabled" | IP mục tiêu không phải IP mạng riêng. Chỉ dùng dải `192.168.x.x` / `10.x.x.x` của lab. |
| Router treo và **không bật lại** | Rút điện 10 giây, cắm lại. Nếu vẫn hỏng → đó là rủi ro đã cảnh báo; dùng router khác. |
| Wireshark không thấy card mạng | Chưa cấp quyền: chạy lại `sudo usermod -aG wireshark $USER` rồi **đăng xuất/đăng nhập lại**. |

---

## 14. Dọn dẹp sau khi xong

1. Trong Terminal đang chạy dashboard: nhấn **Ctrl + C** để tắt.
2. Tắt môi trường ảo: gõ `deactivate`.
3. **Cắm điện lại cho router và reset về mặc định** (thường giữ nút Reset 10 giây) nếu bạn còn muốn dùng nó.
4. File kết quả nằm trong thư mục `results/` (database SQLite, CSV, PDF). Giữ lại để viết báo cáo.

---

## 15. Giải thích thuật ngữ (tra nhanh)

- **PCAP**: file ghi lại các gói tin mạng (như "băng ghi âm" của mạng).
- **Seed (hạt giống)**: gói tin bình thường dùng làm mẫu gốc để đột biến.
- **Fuzzing / đột biến**: cố tình sửa gói tin thành "nửa đúng nửa sai" để dò lỗi.
- **Bit flipping / Byte mutation**: đảo 1 bit / thay 1 byte trong gói tin.
- **Chọn hạt giống thông minh**: chỉ sửa các trường dễ gây lỗi (độ dài, ID) thay vì sửa lung tung.
- **State Machine (đồ thị trạng thái)**: sơ đồ các bước giao tiếp (ví dụ: kết nối → đăng nhập → gửi lệnh).
- **Crash**: router treo/sập, biểu hiện là ngừng trả lời ping.
- **Dry-run**: chế độ chạy thử an toàn, không gửi gì ra mạng thật.
- **Dashboard**: trang web để điều khiển và theo dõi SeedFuz.

---

✅ **Xong!** Bạn đã: dựng lab → bắt seed → nạp vào SeedFuz → fuzzing router → thu thập crash, tốc độ, bộ nhớ → xuất báo cáo CSV/PDF. Đây là đúng toàn bộ quy trình mà đề cương khóa luận yêu cầu.
