# Hướng dẫn thiết lập, chạy và kiểm thử SeedFuz

Tài liệu này hướng dẫn toàn bộ quy trình từ dựng mạng lab cô lập, chuẩn bị router/camera IoT, cài môi trường, thu PCAP, chạy kiểm thử không phần cứng, đến chạy chiến dịch trên thiết bị thật và xuất báo cáo.

> **Cảnh báo an toàn:** Chỉ chạy SeedFuz trên thiết bị thuộc sở hữu của bạn hoặc thiết bị mà bạn được cấp quyền kiểm thử rõ ràng. Không nối mục tiêu fuzzing vào mạng gia đình, mạng trường/công ty hoặc Internet. Fuzzing có thể làm treo, khởi động lại, mất cấu hình hoặc hỏng thiết bị.

## 1. Phạm vi và giới hạn hiện tại

SeedFuz hiện hỗ trợ:

- Python 3.10 trở lên; Ubuntu hoặc Kali Linux là môi trường chính.
- Classic PCAP với Ethernet/VLAN, IPv4, TCP và UDP.
- Phân tích payload, suy luận state graph, bit flipping, byte mutation và chọn trường nhạy cảm.
- Campaign `dry-run`, TCP hoặc UDP.
- Lưu SQLite, xuất CSV/PDF và theo dõi qua Web Dashboard.
- Ping mục tiêu để phát hiện thời điểm mất phản hồi.
- Đọc telemetry bộ nhớ nếu thiết bị cung cấp HTTP endpoint trả JSON có trường `memory_percent`.

Các giới hạn cần nhớ:

- Chưa hỗ trợ PCAPNG và IPv6.
- PCAP phải có payload ứng dụng TCP/UDP không rỗng; chỉ có ARP, ICMP, TCP handshake hoặc ACK sẽ không tạo được seed.
- TCP transport hiện mở một kết nối mới cho mỗi test case. Giao thức cần phiên đăng nhập dài, TLS, token động hoặc nhiều bước phức tạp có thể cần bổ sung adapter riêng.
- Dashboard chưa có đăng nhập. Chỉ chạy trên `127.0.0.1` hoặc mạng lab tin cậy.
- Ping thất bại không luôn đồng nghĩa thiết bị crash. Firewall hoặc cấu hình chặn ICMP cũng tạo kết quả tương tự.
- Campaign mặc định dùng mutator riêng của SeedFuz; Boofuzz 0.4.2 được cài để phục vụ adapter và phát triển kịch bản giao thức chuyên biệt.

## 2. Giá trị ví dụ dùng trong tài liệu

Hãy thay các giá trị sau cho đúng mạng lab của bạn:

| Biến | Giá trị ví dụ | Ý nghĩa |
|---|---:|---|
| `<LAB_SUBNET>` | `192.168.50.0/24` | Dải IPv4 private riêng của lab |
| `<LAB_ROUTER_IP>` | `192.168.50.1` | IP quản trị router lab |
| `<FUZZER_IP>` | `192.168.50.10` | IP máy Ubuntu/Kali chạy SeedFuz |
| `<TARGET_IP>` | `192.168.50.50` | IP router/camera/IoT mục tiêu |
| `<TARGET_PORT>` | `80` | Cổng dịch vụ được phép kiểm thử |
| `<PROTOCOL>` | `tcp` | `tcp` hoặc `udp` |
| `<IFACE>` | `enp3s0` | Interface kết nối vào mạng lab |
| `<PROJECT_DIR>` | `~/SeedFuz` | Thư mục project trên Linux |

Không sao chép nguyên `<...>` vào lệnh. Ví dụ:

```bash
ping -c 4 192.168.50.50
```

## 3. Chuẩn bị phần cứng và dựng mạng lab

### 3.1. Thiết bị tối thiểu

- Một máy Ubuntu/Kali chạy SeedFuz và Wireshark.
- Một router WiFi cũ dùng làm router lab; hoặc một switch riêng nếu đã có thiết bị định tuyến lab.
- Một mục tiêu được cấp phép: chính router lab, router thứ hai, camera IP hoặc thiết bị IoT.
- Cáp Ethernet; ưu tiên kết nối dây để kết quả ổn định.
- Nguồn điện riêng và nút reset/adapter nguồn dễ tiếp cận.
- Tùy chọn: một máy/điện thoại client để tạo lưu lượng bình thường với camera/IoT.

### 3.2. Hai mô hình mạng được hỗ trợ

**Mô hình A — fuzz chính router cũ:**

```text
Máy Ubuntu/Kali chạy SeedFuz
        192.168.50.10
               |
          cáp LAN/WiFi lab
               |
Router mục tiêu 192.168.50.1
        Cổng WAN để trống
```

Trong mô hình này, `<TARGET_IP>` là `192.168.50.1`. Chỉ fuzz cổng quản trị hoặc dịch vụ đã xác định trên router.

**Mô hình B — fuzz camera/IoT qua router lab:**

```text
Máy Ubuntu/Kali 192.168.50.10
               |
        Router lab 192.168.50.1
               |
Camera/IoT mục tiêu 192.168.50.50
        Cổng WAN để trống
```

Trong mô hình này, router chỉ tạo mạng cô lập; `<TARGET_IP>` là IP camera/IoT.

> Không dùng router Internet chính của gia đình làm mục tiêu. Không cấu hình port forwarding từ WAN vào thiết bị lab.

### 3.3. Ghi lại trạng thái trước khi thay đổi

Trước khi setup:

1. Chụp ảnh nhãn model, phiên bản phần cứng và nguồn điện.
2. Ghi firmware hiện tại.
3. Sao lưu cấu hình router nếu giao diện quản trị hỗ trợ.
4. Xác định nút factory reset và thời gian giữ nút theo hướng dẫn của nhà sản xuất.
5. Ghi tài khoản lab vào trình quản lý mật khẩu; không commit thông tin đăng nhập vào project.
6. Chuẩn bị phương án ngắt nguồn và factory reset nếu thiết bị không hồi phục.

### 3.4. Cấu hình router lab

Tên menu khác nhau tùy hãng, nhưng cần đạt các trạng thái sau:

1. Factory reset router cũ nếu không cần giữ cấu hình trước đó.
2. Chỉ nối máy kiểm thử vào cổng **LAN**. Để cổng **WAN/Internet** trống.
3. Mở trang quản trị bằng IP mặc định in trên nhãn hoặc tài liệu thiết bị.
4. Đổi mật khẩu quản trị mặc định.
5. Đặt LAN IPv4 thành `192.168.50.1/24` hoặc dải private khác không trùng mạng đang dùng.
6. Bật DHCP, ví dụ dải `192.168.50.100`–`192.168.50.200`.
7. Tạo DHCP reservation cho:
   - Máy SeedFuz: `192.168.50.10`.
   - Camera/IoT: `192.168.50.50`.
8. Nếu dùng WiFi, tạo SSID riêng như `SeedFuz-Lab`; đặt mật khẩu riêng, không chia sẻ với mạng thật.
9. Tắt các tính năng không cần thiết:
   - Remote management từ WAN.
   - UPnP.
   - WPS.
   - Cloud management hoặc auto port forwarding, nếu thiết bị cho phép.
10. Nếu camera/IoT cần giao tiếp trực tiếp với máy SeedFuz, tắt **AP isolation/client isolation** trên SSID lab.
11. Không đặt DNS/gateway ra Internet nếu thí nghiệm không cần.
12. Khởi động lại router và thiết bị mục tiêu.

### 3.5. Đặt IP cho máy SeedFuz

Khuyến nghị dùng DHCP reservation. Nếu cần đặt IP tĩnh bằng NetworkManager:

```bash
nmcli device status
nmcli connection show
```

Xác định đúng tên connection, sau đó thay `<CONNECTION_NAME>`:

```bash
sudo nmcli connection modify "<CONNECTION_NAME>" \
  ipv4.method manual \
  ipv4.addresses 192.168.50.10/24 \
  ipv4.gateway 192.168.50.1 \
  ipv4.dns ""
sudo nmcli connection up "<CONNECTION_NAME>"
```

Kiểm tra:

```bash
ip -br address
ip route
```

Kết quả mong đợi:

- `<IFACE>` có IP `192.168.50.10/24`.
- Có route đến `192.168.50.0/24`.
- Không có route ngoài lab nếu bạn muốn cô lập tuyệt đối.

### 3.6. Checklist kết nối trước khi cài SeedFuz

```bash
ping -c 4 192.168.50.1
ping -c 4 192.168.50.50
ip neigh show
```

Kiểm tra một cổng TCP đã được cho phép:

```bash
nc -vz -w 2 192.168.50.50 80
```

Kiểm tra UDP không thể xác nhận chắc chắn chỉ bằng `nc`, nhưng có thể gửi probe:

```bash
nc -vzu -w 2 192.168.50.50 5683
```

Trước khi tiếp tục, phải trả lời được:

- Máy có ping được router lab không?
- Máy có nhìn thấy MAC của mục tiêu trong `ip neigh` không?
- IP mục tiêu có ổn định sau khi khởi động lại không?
- Protocol và port nào sẽ được kiểm thử?
- Có thể đăng nhập/quản lý hoặc reset mục tiêu khi nó treo không?
- Có xác nhận quyền kiểm thử thiết bị không?

## 4. Cài Ubuntu/Kali và các công cụ cần thiết

### 4.1. Cập nhật package index

```bash
sudo apt update
```

Không bắt buộc nâng cấp toàn bộ hệ điều hành ngay trước phiên thí nghiệm. Nếu chạy `sudo apt full-upgrade`, hãy khởi động lại và kiểm tra lại interface/IP trước khi thu dữ liệu.

### 4.2. Cài Python, Git, Wireshark và công cụ mạng

```bash
sudo apt install -y \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  build-essential \
  git \
  wireshark \
  tshark \
  tcpdump \
  iproute2 \
  iputils-ping \
  netcat-openbsd \
  curl \
  sqlite3
```

Khi trình cài Wireshark hỏi **“Should non-superusers be able to capture packets?”**, chọn **Yes** trên máy lab một người dùng.

Xác nhận phiên bản:

```bash
python3 --version
git --version
wireshark --version
dumpcap --version
tcpdump --version
sqlite3 --version
```

Python phải từ 3.10 trở lên.

### 4.3. Cấp quyền bắt gói không cần chạy Wireshark bằng root

Thêm user hiện tại vào nhóm `wireshark`:

```bash
sudo usermod -aG wireshark "$USER"
```

Đăng xuất rồi đăng nhập lại, hoặc khởi động lại máy. Sau đó:

```bash
groups
dumpcap -D
```

Kết quả mong đợi:

- `groups` có nhóm `wireshark`.
- `dumpcap -D` liệt kê các interface mà không cần `sudo`.

Nếu package chưa cấu hình quyền đúng:

```bash
sudo dpkg-reconfigure wireshark-common
```

Chọn **Yes**, sau đó chạy lại `usermod`, đăng xuất/đăng nhập và kiểm tra `dumpcap -D`.

Không chạy `sudo wireshark`. Theo hướng dẫn [Wireshark Capture Privileges](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges), chỉ thành phần capture cần quyền giới hạn.

## 5. Lấy source và tạo môi trường Python

### 5.1. Mở đúng thư mục project

Nếu đã có source:

```bash
cd ~/SeedFuz
```

Nếu lấy từ Git, thay URL thật của repository:

```bash
git clone <REPOSITORY_URL> ~/SeedFuz
cd ~/SeedFuz
```

Kiểm tra đúng thư mục:

```bash
pwd
ls
```

Phải thấy `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `src/`, `tests/`, `datasets/` và `experiments/`.

### 5.2. Tạo và kích hoạt virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Khi kích hoạt thành công, prompt thường có tiền tố `(.venv)`.

Xác minh kỹ interpreter và pip:

```bash
which python
which pip
python --version
python -m pip --version
```

`which python` và đường dẫn pip phải nằm dưới `<PROJECT_DIR>/.venv/`. Virtual environment giúp dependency của project tách khỏi Python hệ thống; xem thêm [tài liệu `venv` của Python](https://docs.python.org/3/library/venv.html).

### 5.3. Cài dependencies

Để chạy ứng dụng và toàn bộ công cụ test:

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` cài project ở chế độ editable cùng pytest, coverage, Ruff và các dependencies chạy dashboard. Boofuzz 0.4.2 cũng được cài theo `pyproject.toml`; tài liệu chính thức của Boofuzz khuyến nghị dùng virtual environment trên Ubuntu/Debian.

Kiểm tra package:

```bash
python -m pip check
python -m pip show seedfuz boofuzz fastapi uvicorn pytest ruff
seedfuz --help
```

Kết quả mong đợi:

- `pip check` in `No broken requirements found.`
- `seedfuz --help` hiển thị bốn lệnh `analyze`, `run`, `report`, `serve`.

Nếu shell chưa nhận lệnh `seedfuz`, dùng dạng tương đương:

```bash
python -m seedfuz --help
```

### 5.4. Ghi chú cho Windows PowerShell và WSL

PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-dev.txt
python -m seedfuz --help
```

Nếu PowerShell chặn script kích hoạt, chỉ thay policy cho process hiện tại:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

WSL dùng các lệnh Ubuntu ở trên. Tuy nhiên, Wireshark/USB/NIC trong WSL có giới hạn khác Linux native. Để thu PCAP ổn định, ưu tiên Wireshark trên Windows hoặc Ubuntu/Kali cài trực tiếp; sau đó chép file classic PCAP vào project trong WSL.

## 6. Chạy kiểm thử tự động

Luôn kích hoạt `.venv` và đứng tại thư mục gốc project trước khi chạy.

### 6.1. Chạy toàn bộ suite

```bash
python -m pytest
```

Kết quả đạt khi pytest kết thúc với exit code `0` và không có test failed/error. Suite mặc định dùng dữ liệu tổng hợp, không gửi gói fuzz tới phần cứng.

### 6.2. Chạy một module test tập trung

```bash
python -m pytest tests/test_mutation.py -q
```

Các module hữu ích khác:

```bash
python -m pytest tests/test_pcap.py -q
python -m pytest tests/test_config.py -q
python -m pytest tests/test_campaign.py -q
python -m pytest tests/test_api.py -q
```

### 6.3. Chạy coverage

```bash
python -m pytest --cov=seedfuz --cov-report=term-missing
```

Coverage là độ bao phủ mã nguồn, không chứng minh thiết bị thật hoạt động ổn định.

### 6.4. Kiểm tra style/static lint

```bash
python -m ruff check src tests
```

Kết quả đạt khi Ruff in `All checks passed!` hoặc kết thúc không có lỗi.

## 7. Chạy thử hoàn toàn an toàn bằng dữ liệu mẫu

### 7.1. Tạo lại PCAP mẫu

Repository đã có `datasets/sample_http.pcap`. Có thể tạo lại file xác định bằng:

```bash
python scripts/generate_sample_pcap.py
ls -lh datasets/sample_http.pcap
```

Script phải in đường dẫn đến `datasets/sample_http.pcap` và file phải có kích thước lớn hơn 0.

### 7.2. Phân tích PCAP

Dạng dễ đọc:

```bash
seedfuz analyze datasets/sample_http.pcap
```

Dạng JSON chi tiết:

```bash
seedfuz analyze datasets/sample_http.pcap --json
```

Nếu command wrapper chưa hoạt động:

```bash
python -m seedfuz analyze datasets/sample_http.pcap --json
```

Kết quả JSON cần có:

- `packets` lớn hơn 0.
- `seeds` lớn hơn 0.
- `protocols` có `tcp` hoặc `udp`.
- `state_graph` là object JSON.
- `sensitive_fields` có offset, length, score và lý do khi tìm thấy trường nhạy cảm.

### 7.3. Chạy dry-run

```bash
seedfuz run experiments/dry_run.example.json
```

Dry-run không mở kết nối tới thiết bị mạng. Kết quả được lưu mặc định vào `results/seedfuz.db`.

Kết quả mong đợi là JSON dạng:

```json
{
  "campaign_id": "<UUID>",
  "metrics": {
    "total_cases": 100,
    "sent_cases": 100,
    "failed_cases": 0
  }
}
```

Sao chép giá trị `campaign_id` để dùng ở các bước sau.

### 7.4. Kiểm tra SQLite

```bash
ls -lh results/seedfuz.db
sqlite3 results/seedfuz.db ".tables"
sqlite3 results/seedfuz.db "SELECT id, name, status, created_at FROM campaigns ORDER BY created_at DESC LIMIT 5;"
```

Phải thấy campaign vừa chạy và trạng thái `completed`.

### 7.5. Xuất CSV và PDF

Thay `<CAMPAIGN_ID>` bằng UUID thật:

```bash
seedfuz report <CAMPAIGN_ID> --format csv
seedfuz report <CAMPAIGN_ID> --format pdf
ls -lh results/<CAMPAIGN_ID>.csv results/<CAMPAIGN_ID>.pdf
```

Có thể chỉ định output khác:

```bash
seedfuz report <CAMPAIGN_ID> --format csv --output results/dry-run.csv
seedfuz report <CAMPAIGN_ID> --format pdf --output results/dry-run.pdf
```

## 8. Chạy Web Dashboard

### 8.1. Khởi động local

```bash
seedfuz serve --host 127.0.0.1 --port 8000
```

Giữ terminal này mở. Mở terminal thứ hai, kích hoạt `.venv`, rồi kiểm tra API:

```bash
curl http://127.0.0.1:8000/api/health
```

Kết quả mong đợi:

```json
{"status":"ok"}
```

Mở trình duyệt tại:

```text
http://127.0.0.1:8000
```

### 8.2. Quy trình dry-run trên dashboard

1. Kéo `datasets/sample_http.pcap` vào vùng upload.
2. Chờ thông báo PCAP hợp lệ và xác nhận `seed_count > 0`.
3. Đặt tên campaign.
4. Chọn `Dry-run`.
5. Đặt `Số test case = 100`.
6. Giữ `Seed ngẫu nhiên = 1337` và `Trễ mỗi gói = 0.01`.
7. Bật ưu tiên trường nhạy cảm và state machine.
8. Nhấn **Bắt đầu chiến dịch**.
9. Theo dõi số case, packet/second, log và trạng thái `Hoàn tất`.
10. Tải CSV/PDF từ khu vực báo cáo.

### 8.3. Cho phép máy khác trong lab truy cập dashboard

Chỉ dùng khi thật sự cần:

```bash
seedfuz serve --host 192.168.50.10 --port 8000
```

Truy cập `http://192.168.50.10:8000` từ máy trong cùng lab. Không bind `0.0.0.0` trên mạng không tin cậy và không mở port 8000 ra Internet vì dashboard chưa có xác thực.

Dừng server bằng `Ctrl+C`.

## 9. Thu PCAP thật làm hạt giống

### 9.1. Chọn nơi capture đúng

Máy tính thường không nhìn thấy toàn bộ lưu lượng giữa hai thiết bị khác chỉ nhờ bật promiscuous mode trên mạng switched/WiFi. Chọn một trong các cách:

- Tạo lưu lượng bình thường trực tiếp từ máy SeedFuz đến mục tiêu và capture trên chính máy đó.
- Capture trên máy client đang giao tiếp với camera/IoT.
- Dùng switch có port mirroring/SPAN.
- Capture tại router lab nếu firmware hỗ trợ tcpdump/packet capture.

Không dùng ARP spoofing/MITM trong tài liệu này.

### 9.2. Xác định interface

```bash
ip -br link
ip -br address
dumpcap -D
```

Tạo một lượt ping và quan sát interface tăng packet:

```bash
ping -c 4 192.168.50.50
```

Ví dụ interface dây là `enp3s0`, WiFi có thể là `wlan0` hoặc `wlp2s0`.

### 9.3. Tạo lưu lượng bình thường có chủ đích

Tùy thiết bị, thực hiện những thao tác hợp lệ và lặp lại được:

- Mở trang status hoặc trang quản trị lab.
- Đăng nhập rồi đăng xuất bằng tài khoản lab.
- Đọc trạng thái cảm biến.
- Xem snapshot camera hoặc gọi API nội bộ được phép.
- Bật/tắt một chức năng không nguy hiểm.

Ghi nhật ký thời điểm và thao tác để sau này giải thích state graph. Không capture mật khẩu hoặc token thật; chỉ dùng tài khoản lab tạm thời.

### 9.4. Capture bằng Wireshark GUI

1. Mở Wireshark với user thường.
2. Chọn đúng `<IFACE>` có lưu lượng lab.
3. Nhập capture filter trước khi bắt, ví dụ:

   ```text
   host 192.168.50.50 and tcp port 80
   ```

   Hoặc UDP:

   ```text
   host 192.168.50.50 and udp port 5683
   ```

4. Nhấn Start.
5. Thực hiện chuỗi thao tác bình thường đã chuẩn bị.
6. Nhấn Stop.
7. Dùng display filter để kiểm tra, ví dụ:

   ```text
   ip.addr == 192.168.50.50 && tcp.port == 80
   ```

8. Xem `Follow TCP Stream` hoặc payload để chắc chắn có dữ liệu ứng dụng.
9. Chọn **File → Save As**.
10. Chọn định dạng **Wireshark/tcpdump/... - pcap**, không chọn pcapng.
11. Lưu thành `datasets/uploads/device_seed.pcap`.

### 9.5. Capture bằng tcpdump

TCP ví dụ:

```bash
sudo tcpdump -i enp3s0 -nn -s 0 \
  -w datasets/uploads/device_seed.pcap \
  'host 192.168.50.50 and tcp port 80'
```

UDP ví dụ:

```bash
sudo tcpdump -i enp3s0 -nn -s 0 \
  -w datasets/uploads/device_seed.pcap \
  'host 192.168.50.50 and udp port 5683'
```

Trong khi tcpdump chạy, tạo lưu lượng bình thường. Nhấn `Ctrl+C` để dừng. `tcpdump -w` tạo classic PCAP theo mặc định.

Kiểm tra file:

```bash
file datasets/uploads/device_seed.pcap
capinfos datasets/uploads/device_seed.pcap
tcpdump -nn -r datasets/uploads/device_seed.pcap | head
```

### 9.6. Xác nhận PCAP bằng SeedFuz

```bash
seedfuz analyze datasets/uploads/device_seed.pcap --json
```

Không chạy fuzzing nếu:

- Parser báo không phải classic PCAP.
- `seeds` bằng 0.
- Protocol/port không đúng dịch vụ dự kiến.
- Capture chứa dữ liệu nhạy cảm không nên lưu.
- State/payload không phản ánh chuỗi thao tác bình thường.

Giữ nguyên PCAP gốc. Nếu cần lọc hoặc rút gọn, tạo file mới; không ghi đè dữ liệu gốc.

## 10. Tạo cấu hình cho thiết bị thật

### 10.1. Sao chép file mẫu

Không sửa trực tiếp `experiments/hardware.example.json`:

```bash
cp experiments/hardware.example.json experiments/router_lab.json
```

Mở `experiments/router_lab.json` bằng editor và thay giá trị phù hợp:

```json
{
  "name": "Router lab TCP port 80 - smart",
  "seed_path": "datasets/uploads/device_seed.pcap",
  "protocol": "tcp",
  "target_host": "192.168.50.50",
  "target_port": 80,
  "authorized": true,
  "allow_public_target": false,
  "max_cases": 50,
  "delay_seconds": 0.10,
  "timeout_seconds": 1.0,
  "random_seed": 1337,
  "smart_selection": true,
  "state_aware": true,
  "monitor_interval": 1.0,
  "memory_probe_url": null,
  "crash_threshold": 3
}
```

### 10.2. Ý nghĩa từng trường

| Trường | Cách đặt |
|---|---|
| `name` | Tên chứa thiết bị, protocol/port, baseline hay smart và lần chạy |
| `seed_path` | Classic PCAP đã phân tích thành công |
| `protocol` | `dry-run`, `tcp` hoặc `udp`; phải khớp dịch vụ đích |
| `target_host` | IPv4 explicit, ví dụ `192.168.50.50`; không dùng hostname |
| `target_port` | Cổng 1–65535 của dịch vụ được phép kiểm thử |
| `authorized` | Bắt buộc `true` với TCP/UDP; là xác nhận quyền kiểm thử |
| `allow_public_target` | Giữ `false` trong lab; IP public sẽ bị chặn |
| `max_cases` | Số case, từ 1 đến 1.000.000; bắt đầu 10–50 |
| `delay_seconds` | Trễ sau mỗi case; bắt đầu `0.10`–`1.00` để giảm tải |
| `timeout_seconds` | Timeout kết nối/response và ping; phải lớn hơn 0 |
| `random_seed` | Giữ giống nhau khi cần tái lập/so sánh hai chiến dịch |
| `smart_selection` | `false` cho baseline, `true` cho cơ chế chọn trường nhạy cảm |
| `state_aware` | `true` để luân phiên seed theo thứ tự state đã suy luận |
| `monitor_interval` | Khoảng mong muốn giữa health sample; độ chính xác phụ thuộc delay/case |
| `memory_probe_url` | URL tùy chọn trả JSON `{"memory_percent": <0..100>}` |
| `crash_threshold` | Số health-check thất bại liên tiếp trước khi ghi một crash |

Kiểm tra JSON hợp lệ:

```bash
python -m json.tool experiments/router_lab.json
```

## 11. Quy trình chạy an toàn trên thiết bị thật

### 11.1. Cổng kiểm soát trước khi gửi packet

Không bỏ qua checklist này:

```bash
ping -c 4 192.168.50.50
nc -vz -w 2 192.168.50.50 80
seedfuz analyze datasets/uploads/device_seed.pcap --json
python -m json.tool experiments/router_lab.json
```

Đồng thời xác nhận:

- Cổng WAN lab đang để trống hoặc bị firewall chặn.
- IP trong config đúng mục tiêu, không phải gateway/máy khác ngoài ý muốn.
- Có người theo dõi thiết bị và có thể ngắt nguồn/reset.
- Không có người dùng thật hoặc dữ liệu quan trọng trên thiết bị.
- Đã sao lưu cấu hình cần thiết.

### 11.2. Chạy dry-run với PCAP thật trước

Tạo bản config mới, giữ `seed_path` thật nhưng đặt:

```json
"protocol": "dry-run",
"authorized": false,
"max_cases": 50
```

Sau đó:

```bash
seedfuz run experiments/router_lab_dry_run.json
```

Chỉ chuyển sang TCP/UDP sau khi dry-run hoàn tất, không lỗi seed và tạo được báo cáo.

### 11.3. Chạy smoke campaign 10–50 case

Mở terminal giám sát riêng:

```bash
ping 192.168.50.50
```

Mở terminal khác và chạy:

```bash
seedfuz run experiments/router_lab.json
```

Quan sát đồng thời:

- Đèn nguồn/network và khả năng phản hồi của thiết bị.
- Ping liên tục.
- Cảnh báo `send-error`.
- `sent_cases`, `failed_cases`, packet/second và crash.
- Log thiết bị nếu có quyền truy cập.

CLI hiện không có lệnh stop tương tác cho campaign đồng bộ. Nếu cần dừng khẩn cấp, nhấn `Ctrl+C`; sau đó kiểm tra tính nhất quán của campaign/report. Dashboard có API stop cho campaign đang chạy, nhưng giao diện hiện chưa có nút dừng.

### 11.4. Phân loại sự cố

Khi mất ping hoặc dịch vụ:

1. Dừng gửi packet.
2. Ghi lại giờ, case gần nhất, campaign ID và trạng thái đèn.
3. Kiểm tra liệu chỉ ICMP bị chặn hay dịch vụ cũng mất:

   ```bash
   nc -vz -w 2 192.168.50.50 80
   ip neigh show 192.168.50.50
   ```

4. Chờ khoảng thời gian hồi phục đã quy định trong kế hoạch thí nghiệm.
5. Nếu không hồi phục, power-cycle theo quy trình an toàn của thiết bị.
6. Chỉ factory reset khi power-cycle không đủ và đã lưu bằng chứng.
7. Không chạy tiếp cho đến khi trạng thái ban đầu được phục hồi và ghi nhận.

Một crash đáng tin cậy nên có ít nhất hai tín hiệu, ví dụ mất ping và mất dịch vụ, hoặc watchdog reboot/log thiết bị. Không kết luận chỉ từ một lần timeout.

### 11.5. Tăng quy mô có kiểm soát

Chỉ tăng tải sau khi smoke campaign ổn định:

1. 10–50 case, delay `0.5`–`1.0` giây.
2. 100–500 case, delay `0.1`–`0.5` giây.
3. Campaign dài hơn theo kế hoạch nghiên cứu, có người giám sát và thời gian nghỉ giữa các lần chạy.

Mỗi lần chỉ thay một nhóm biến. Không đồng thời tăng `max_cases`, giảm delay và đổi seed nếu mục tiêu là so sánh có kiểm soát.

## 12. Memory telemetry tùy chọn

SeedFuz chỉ đo memory trend khi thiết bị cung cấp endpoint HTTP trả JSON:

```json
{"memory_percent": 42.5}
```

Ví dụ config:

```json
"memory_probe_url": "http://192.168.50.50:9100/metrics/memory"
```

Kiểm tra thủ công trước:

```bash
curl --max-time 2 http://192.168.50.50:9100/metrics/memory
```

Yêu cầu:

- HTTP response là JSON hợp lệ.
- Có key chính xác `memory_percent`.
- Giá trị số nằm trong khoảng 0–100.
- Endpoint chỉ tồn tại trong lab và không chứa credential trong URL.

Nếu không có endpoint, để `memory_probe_url: null`. Dashboard hiển thị `—`; đây không phải lỗi. Không suy diễn “không rò rỉ bộ nhớ” khi không có dữ liệu telemetry.

## 13. Thiết kế thực nghiệm baseline và smart selection

### 13.1. Tạo hai cấu hình

Tạo hai file riêng:

- `experiments/router_baseline.json`: `smart_selection=false`.
- `experiments/router_smart.json`: `smart_selection=true`.

Giữ giống nhau tất cả trường còn lại:

- Cùng PCAP.
- Cùng target IP, protocol và port.
- Cùng `max_cases`.
- Cùng `delay_seconds` và timeout.
- Cùng `random_seed`.
- Cùng `state_aware`.
- Cùng điều kiện khởi động và thời gian nghỉ của thiết bị.

### 13.2. Thứ tự chạy đề xuất

1. Đưa mục tiêu về trạng thái ban đầu.
2. Ghi nhiệt độ/phần trăm bộ nhớ ban đầu nếu có.
3. Chạy baseline.
4. Xuất CSV/PDF và sao lưu database/log.
5. Khôi phục mục tiêu, chờ ổn định.
6. Chạy smart selection.
7. Xuất CSV/PDF.
8. Đổi thứ tự chạy ở lần lặp tiếp theo để giảm bias do nóng máy hoặc trạng thái tích lũy.
9. Lặp nhiều lần trước khi kết luận.

Không tuyên bố cải tiến nhanh gấp 2–3 lần chỉ từ một cặp campaign.

### 13.3. Dữ liệu cần lưu cho mỗi campaign

- Campaign ID, tên và thời gian bắt đầu/kết thúc.
- Hash hoặc tên/version của PCAP gốc.
- Model, firmware và trạng thái khởi động của mục tiêu.
- Toàn bộ config JSON.
- Số case gửi thành công/thất bại.
- Packets per second.
- Thời điểm đến crash đầu tiên và số crash có xác nhận.
- Memory samples/trend nếu có telemetry.
- CSV, PDF, SQLite và log thiết bị.
- Cách thiết bị hồi phục: tự hồi phục, reboot, power-cycle hay factory reset.

## 14. Kiểm tra kết quả và lưu bằng chứng

Liệt kê file sinh ra:

```bash
find results -maxdepth 1 -type f -printf '%TY-%Tm-%Td %TH:%TM %10s %f\n' | sort
```

Truy vấn campaign gần nhất:

```bash
sqlite3 -header -column results/seedfuz.db \
  "SELECT id, name, status, created_at, finished_at, error FROM campaigns ORDER BY created_at DESC LIMIT 10;"
```

Khi sao lưu kết quả, tạo thư mục ngoài Git hoặc trong khu vực lưu trữ nghiên cứu được bảo vệ. Không commit:

- Credential/token.
- Public target address.
- PCAP chứa dữ liệu nhạy cảm.
- Database/log lớn.
- Kết quả có thông tin nhận dạng người dùng thật.

## 15. Xử lý lỗi thường gặp

| Hiện tượng/thông báo | Nguyên nhân thường gặp | Cách xử lý |
|---|---|---|
| `No module named pytest` | Chưa kích hoạt `.venv` hoặc chỉ cài requirements runtime | `source .venv/bin/activate`, rồi `python -m pip install -r requirements-dev.txt` |
| `seedfuz: command not found` | Console script không nằm trên PATH hoặc package chưa cài | Kiểm tra `which python`; cài lại requirements; dùng `python -m seedfuz` |
| `No module named seedfuz` | Đứng sai environment hoặc editable install thất bại | Chạy từ root repo và `python -m pip install -e '.[dev]'` |
| Python dưới 3.10 | Hệ điều hành quá cũ | Cài Python 3.10+ rồi tạo lại `.venv`; không di chuyển/reuse venv cũ |
| `dumpcap -D` không thấy interface | Sai quyền hoặc interface chưa up | Kiểm tra `ip -br link`, nhóm `wireshark`, đăng nhập lại; chạy `dpkg-reconfigure wireshark-common` |
| `Permission denied` khi capture | User chưa có quyền dumpcap | Không chạy GUI bằng root; cấu hình nhóm/quyền Wireshark như mục 4.3 |
| SeedFuz báo chỉ nhận classic PCAP | File đang là PCAPNG | Wireshark Save As → pcap hoặc capture lại bằng `tcpdump -w` |
| `PCAP contains no non-empty TCP/UDP application payloads` | Capture chỉ có handshake/ACK/ICMP hoặc sai filter | Tạo lại lưu lượng ứng dụng, kiểm tra Follow Stream và capture đúng IP/port |
| `target_host must be an explicit IP address` | Dùng hostname | Thay bằng IPv4 cụ thể như `192.168.50.50` |
| `Network fuzzing requires authorized=true` | Chưa xác nhận quyền trong JSON/dashboard | Chỉ sau khi có quyền, đặt `authorized: true` hoặc tick xác nhận |
| `Public targets are disabled` | IP không thuộc private/loopback/link-local | Dừng lại và chuyển mục tiêu vào mạng private cô lập; giữ `allow_public_target=false` |
| `target_port must be between 1 and 65535` | Port 0 hoặc ngoài phạm vi | Xác định đúng port dịch vụ và sửa config |
| Nhiều `send-error` | Sai IP/port/protocol, dịch vụ đóng hoặc target treo | Kiểm tra ping, `ip neigh`, `nc`, protocol capture và log thiết bị |
| Dashboard báo upload lỗi | Sai định dạng, file quá 100 MiB hoặc PCAP lỗi | Dùng classic `.pcap/.cap`, rút gọn capture và phân tích bằng CLI trước |
| Dashboard mở nhưng không chạy được | PCAP có `seed_count=0` hoặc config mạng sai | Upload PCAP có application payload; kiểm tra protocol/IP/port/authorized |
| `Address already in use` ở port 8000 | Port đã bị process khác dùng | Dùng `ss -ltnp | grep ':8000'` rồi dừng đúng process hoặc chọn `--port 8001` |
| Không truy cập được dashboard từ máy khác | Server bind `127.0.0.1` hoặc firewall chặn | Bind đúng `<FUZZER_IP>` chỉ trong lab; kiểm tra firewall; không mở ra Internet |
| Ping fail nhưng dịch vụ còn hoạt động | Thiết bị chặn ICMP | Không dùng ping làm tín hiệu duy nhất; xác minh port/API/log và điều chỉnh tiêu chí crash |
| Dashboard hiển thị bộ nhớ `—` | Không có hoặc lỗi memory endpoint | Để `null` nếu không hỗ trợ; kiểm tra JSON/key/range bằng `curl` |
| Report không tìm thấy campaign | Sai UUID hoặc dùng database khác | Truy vấn `results/seedfuz.db`; truyền đúng `--database` nếu đã dùng đường dẫn khác |
| CSV/PDF không sinh ra | Thư mục không ghi được hoặc campaign ID sai | Kiểm tra quyền `results/`, ID và lỗi CLI; không chạy bằng root để “chữa” quyền |

## 16. Checklist tổng hợp

### Trước buổi lab

- [ ] Có văn bản/xác nhận quyền kiểm thử.
- [ ] Router/camera không chứa dữ liệu thật cần bảo vệ.
- [ ] WAN để trống; không port forwarding; mạng lab cô lập.
- [ ] Đã ghi model, firmware, IP, protocol và port.
- [ ] Có backup/reset/power-cycle plan.
- [ ] Python virtual environment và dependencies đã cài.
- [ ] `python -m pytest` và Ruff đạt.
- [ ] Dry-run bằng PCAP mẫu đạt.

### Trước campaign thật

- [ ] PCAP là classic PCAP, IPv4 TCP/UDP và có seed.
- [ ] PCAP không chứa credential/token thật.
- [ ] IP mục tiêu là private và đã kiểm tra lại trực tiếp.
- [ ] `authorized=true`, `allow_public_target=false`.
- [ ] Smoke campaign chỉ 10–50 case, có delay bảo thủ.
- [ ] Ping/service monitor đang chạy.
- [ ] Có người theo dõi và có thể ngắt nguồn.

### Sau campaign

- [ ] Ghi campaign ID và trạng thái hoàn tất/thất bại.
- [ ] Xuất CSV/PDF và lưu config JSON.
- [ ] Ghi crash, thời điểm, bằng chứng và cách khôi phục.
- [ ] Xác nhận thiết bị trở lại trạng thái ban đầu.
- [ ] Nghỉ giữa các campaign để giảm ảnh hưởng tích lũy.
- [ ] Không commit dữ liệu nhạy cảm hoặc kết quả lớn.

## 17. Chuỗi lệnh nhanh cho dry-run

Sau khi đã cài các package hệ điều hành:

```bash
cd ~/SeedFuz
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-dev.txt
python -m pip check
python -m pytest
python -m pytest --cov=seedfuz --cov-report=term-missing
python -m ruff check src tests
python scripts/generate_sample_pcap.py
seedfuz analyze datasets/sample_http.pcap --json
seedfuz run experiments/dry_run.example.json
seedfuz serve --host 127.0.0.1 --port 8000
```

Mở `http://127.0.0.1:8000`, upload `datasets/sample_http.pcap` và chạy Dry-run. Chỉ chuyển sang thiết bị thật sau khi toàn bộ chuỗi kiểm tra không phần cứng hoàn tất.

## 18. Tài liệu tham khảo vận hành

- [Python `venv` — tạo môi trường ảo](https://docs.python.org/3/library/venv.html)
- [Boofuzz 0.4.2 — hướng dẫn cài đặt](https://boofuzz.readthedocs.io/en/stable/user/install.html)
- [Wireshark — Capture Privileges](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges)
- [`README.md`](../README.md) — tổng quan kiến trúc và lệnh nhanh của SeedFuz.
- [`experiments/dry_run.example.json`](../experiments/dry_run.example.json) — cấu hình dry-run mẫu.
- [`experiments/hardware.example.json`](../experiments/hardware.example.json) — cấu hình thiết bị thật mẫu.
- [`docs/PROJECT_STATUS.md`](PROJECT_STATUS.md) — phạm vi đã hoàn thành và giới hạn kiểm chứng hiện tại.

---

**Phạm vi kiểm chứng của tài liệu:** Các lệnh CLI, trường cấu hình, endpoint, giới hạn parser và luồng dashboard trong tài liệu được đối chiếu với mã nguồn hiện tại. Việc cấu hình router, capture Wireshark, TCP/UDP campaign, crash detection và memory telemetry trên phần cứng thật phải được xác nhận lại trong lab với model/firmware cụ thể; tài liệu này không tuyên bố các bước phần cứng đã được chạy thành công trên mọi thiết bị.
