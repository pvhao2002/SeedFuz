# SeedFuz — Runbook Demo (bản ngắn)

Tất cả bước dưới là **dry-run, an toàn trên laptop, không cần thiết bị thật**.
Kịch bản thuyết trình đầy đủ: `KICH_BAN_THUYET_TRINH.md`. File này chỉ là phần lệnh để chạy.

## Chuẩn bị
Mở **2 terminal**, cả hai cùng kích hoạt venv:
```bash
source .venv/bin/activate
```

## 6 bước demo

**1. Seed PCAP + phân tích** *(yêu cầu 1, 3, 4)*
```bash
seedfuz analyze datasets/sample_http.pcap --json
```
Cho xem: số packet, số seed sau loại trùng, số **state**, danh sách **trường nhạy cảm**.

**2. Mở Dashboard** *(yêu cầu 8, 9)* — terminal 2, để nguyên suốt buổi
```bash
seedfuz serve --host 127.0.0.1 --port 8000
```
Mở `http://127.0.0.1:8000`, kéo thả `datasets/sample_http.pcap` để demo upload + thanh tiến trình.

**3. A/B: random vs smart** *(yêu cầu 5, 7 — điểm nhấn)* — terminal 1
```bash
seedfuz run experiments/ab_random.json   # nhánh A: random
seedfuz run experiments/ab_smart.json    # nhánh B: smart
```
Cùng seed=1337, cùng 300 case. So **crash / tốc độ / độ phủ trường nhạy cảm**.
Mỗi lệnh in ra `campaign_id` — **ghi lại**.

**4. Xuất báo cáo** *(yêu cầu 7, 9)*
```bash
seedfuz report <campaign_id_smart> --format csv
seedfuz report <campaign_id_smart> --format pdf
```
File ra ở `results/`. PDF có crash + timestamp + hex payload + memory trend.

**5. Giám sát + cảnh báo an ninh** *(yêu cầu 6, 10)* — tùy chọn, cần IP đích
```bash
python -m seedfuz monitor --host <IP_router_hoac_camera> --interval 1
```
Không có thiết bị thì trỏ `--host 127.0.0.1` để minh họa cơ chế heartbeat.

## Thứ tự kể chuyện
Seed thật (B1) → nạp dashboard (B2) → random vs smart chứng minh đóng góp đề tài (B3) → báo cáo đo đạc (B4) → giám sát & cảnh báo thiết bị (B5).

## Dự phòng
Chạy trọn **B1→B4 một lần trước buổi demo** để có sẵn `campaign_id` + PDF/CSV, phòng khi live trục trặc.

---

# Chạy với ROUTER THẬT (lab)

> ⚠️ Chỉ chạy với router **bạn sở hữu / được cấp phép**, trên **mạng lab cô lập** (tách khỏi mạng nhà/trường). Fuzzing có thể làm router **treo / reboot / mất cấu hình**. Có sẵn nút reset cứng trước khi bắt đầu.

Config mẫu đã dựng sẵn: `experiments/router_wifi.json` (web admin cổng 80, TCP) và `experiments/router_wifi_upnp.json` (UPnP/SSDP cổng 1900, UDP, không cần login).

### B1. Xác định IP router
```bash
ip route | grep default        # Linux: dòng "default via <IP>"
ping -c 2 <IP_router>          # chắc chắn tới được
```

### B2. Bắt seed PCAP thật từ router (thay cho sample_http.pcap)
Dùng Wireshark hoặc tcpdump, thao tác bình thường với router (đăng nhập web admin, đổi 1 setting) để bắt traffic thật:
```bash
sudo tcpdump -i <interface> host <IP_router> -w datasets/uploads/router_seed.pcap
# thao tác với router vài giây rồi Ctrl+C
seedfuz analyze datasets/uploads/router_seed.pcap --json   # kiểm tra tách được seed/state
```

### B3. Sửa config trỏ đúng thiết bị
Mở `experiments/router_wifi.json`, chỉnh:
- `"seed_path"`: `"datasets/uploads/router_seed.pcap"` (seed thật ở B2)
- `"target_host"`: IP router thật
- `"target_port"` + `"monitor_tcp_port"`: cổng dịch vụ (80 web, 1900 UPnP…)
- `"monitor_http_url"`: `http://<IP_router>/` (để monitor biết router sống/chết)
- `"authorized": true` ← bắt buộc, nếu `false` sẽ không gửi ra mạng
- `"allow_public_target"`: để `false` — chốt chặn, chặn bắn nhầm IP public
- (tùy chọn) `"recovery_command"`: lệnh bật/tắt ổ cắm thông minh để tự khôi phục khi router treo

### B4. Tiền kiểm (pre-flight)
```bash
ping -c 2 <IP_router>
nc -zv <IP_router> 80          # xác nhận cổng đang mở
```

### B5. Mở heartbeat giám sát — terminal riêng (đo chính xác thời điểm crash)
```bash
python -m seedfuz monitor --host <IP_router> --tcp-port 80 --http-url http://<IP_router>/ --interval 1
```
Để chạy liên tục; khi router ngừng trả lời nó in timestamp mất phản hồi.

### B6. Chạy campaign fuzzing
```bash
seedfuz run experiments/router_wifi.json
```
Theo dõi trên Dashboard (`seedfuz serve`) hoặc log: tốc độ case/giây, crash + hex payload gây lỗi, memory trend, bảng cảnh báo an ninh. Campaign tự ghi crash vào `results/seedfuz.db`.

### B7. Sau khi xong
```bash
seedfuz report <campaign_id> --format pdf
```
Nếu router treo mà không có `recovery_command`: power-cycle tay, kiểm tra lại cấu hình.

**Mẹo an toàn khi chạy thật:** bắt đầu với `max_cases` nhỏ (vd 100–200) để xác nhận luồng đúng trước khi bắn full 2000; giữ `delay_seconds` ≥ 0.1 để không làm nghẽn thiết bị yếu.
