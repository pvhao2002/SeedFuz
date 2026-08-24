# SeedFuz

SeedFuz là hệ thống **Mutational Fuzzing có nhận biết trạng thái** dành cho nghiên cứu an toàn IoT. Project nhận PCAP thu bằng Wireshark từ hoạt động bình thường của router/camera, tách payload, sinh dữ liệu “nửa đúng nửa sai”, ưu tiên đột biến các trường nhạy cảm và theo dõi phản ứng của thiết bị qua Web Dashboard.

Project bám theo đề cương HUIT năm học 2025–2026 trong [`docs/university/`](docs/university/). Chỉ sử dụng SeedFuz với thiết bị thuộc sở hữu hoặc đã được cấp phép, trên mạng lab cô lập.

## Tính năng chính

- Phân tích classic PCAP: Ethernet/VLAN, IPv4, TCP và UDP.
- Tách payload, loại seed trùng và suy luận State Machine từ chuỗi gói tin.
- Bit flipping, Byte mutation và smart-field mutation.
- Cơ chế chọn thông minh dựa trên Header, delimiter, giá trị biên và trường độ dài nghi vấn.
- Campaign chạy tái lập bằng random seed; có giới hạn số case và delay.
- Chế độ `dry-run`, TCP, UDP và adapter Boofuzz 0.4.2.
- Giám sát ping, thời điểm crash, tốc độ fuzzing và xu hướng bộ nhớ tùy chọn.
- SQLite lưu lịch sử; xuất CSV/PDF.
- FastAPI và dashboard trực quan để upload PCAP, chạy và theo dõi chiến dịch.

## Kiến trúc

```text
Wireshark PCAP
      │
      ▼
PCAP parser ──► Payload seeds ──► State graph
      │                 │              │
      └────────► Smart field scoring ◄─┘
                        │
                        ▼
             Bit / Byte / Field mutator
                        │
                 Dry-run / TCP / UDP
                        │
           Device monitor + SQLite events
                        │
              Dashboard / CSV / PDF
```

Các module chính:

| Module | Trách nhiệm |
|---|---|
| `pcap.py` | Đọc capture, giải mã packet, tách payload và tìm trường nhạy cảm |
| `state_machine.py` | Suy luận các chuyển trạng thái từ gói tin |
| `mutation.py` | Sinh đột biến có thể tái lập |
| `campaign.py` | Điều phối test case, đo tốc độ, crash và bộ nhớ |
| `transport.py` | Dry-run, TCP và UDP transport |
| `monitor.py` | Ping và endpoint telemetry bộ nhớ |
| `storage.py` | Schema và thao tác SQLite |
| `api.py` | REST API, upload và background runner |
| `reporting.py` | Xuất CSV/PDF |
| `boofuzz_adapter.py` | Tạo Boofuzz session/request graph |

## Cài đặt

Yêu cầu Python 3.10 trở lên. Ubuntu hoặc Kali Linux là môi trường mục tiêu theo đề cương.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Dependencies chính gồm Boofuzz, FastAPI, Uvicorn, ReportLab và pytest. Không cần quyền root để chạy dry-run hoặc dashboard.

## Chạy nhanh bằng dữ liệu mẫu

Tạo classic PCAP demo và phân tích:

```bash
python scripts/generate_sample_pcap.py
seedfuz analyze datasets/sample_http.pcap --json
```

Chạy chiến dịch an toàn, không gửi dữ liệu ra mạng:

```bash
seedfuz run experiments/dry_run.example.json
```

Kết quả được lưu mặc định trong `results/seedfuz.db`. Lệnh trả về `campaign_id`; dùng ID này để xuất báo cáo:

```bash
seedfuz report <campaign_id> --format csv
seedfuz report <campaign_id> --format pdf
```

## Web Dashboard

```bash
seedfuz serve --host 127.0.0.1 --port 8000
```

Mở `http://127.0.0.1:8000`, upload `.pcap`, xem số packet/seed/state và chạy campaign. Dashboard cập nhật số case, packet/giây, crash, memory trend và event log; khi kết thúc có thể tải CSV/PDF.

Các endpoint quan trọng:

- `POST /api/pcaps`: upload và phân tích PCAP.
- `POST /api/campaigns`: tạo chiến dịch từ `config_json` multipart field.
- `GET /api/campaigns/{id}`: trạng thái, metrics, health và event.
- `POST /api/campaigns/{id}/stop`: yêu cầu dừng.
- `GET /api/campaigns/{id}/report.csv` hoặc `report.pdf`: xuất báo cáo.

## Cấu hình chiến dịch

Xem [`experiments/dry_run.example.json`](experiments/dry_run.example.json) và [`experiments/hardware.example.json`](experiments/hardware.example.json). Các trường quan trọng:

- `seed_path`: classic PCAP đầu vào.
- `protocol`: `dry-run`, `tcp` hoặc `udp`.
- `target_host`, `target_port`: thiết bị và dịch vụ đích.
- `authorized`: bắt buộc là `true` khi dùng mạng.
- `max_cases`, `delay_seconds`, `timeout_seconds`: giới hạn chiến dịch.
- `random_seed`: tái lập cùng chuỗi đột biến.
- `smart_selection`, `state_aware`: bật cải tiến của đề tài.
- `memory_probe_url`: endpoint JSON tùy chọn trả `memory_percent`.
- `crash_threshold`: số health-check thất bại liên tiếp để ghi nhận crash.

IP public bị chặn mặc định. Không đặt `allow_public_target=true` trong môi trường học tập; hãy dùng IP private của mạng lab.

## Quy trình thí nghiệm đề xuất

1. Kết nối máy Linux và thiết bị IoT trong VLAN/mạng riêng.
2. Dùng Wireshark ghi lưu lượng bình thường thành classic `.pcap`.
3. Kiểm tra PCAP bằng `seedfuz analyze` và xác nhận payload/state hợp lý.
4. Chạy dry-run ngắn để kiểm tra seed, cấu hình và đường ghi kết quả.
5. Chạy baseline với `smart_selection=false`, ghi random seed và số case.
6. Chạy lại cùng điều kiện với `smart_selection=true`.
7. So sánh packet/giây, thời gian đến crash đầu tiên, số crash duy nhất và memory trend.
8. Lặp nhiều phiên; không kết luận “nhanh hơn 2–3 lần” nếu chưa có số liệu thực nghiệm đủ mạnh.

## Kiểm thử và chất lượng

```bash
python -m pytest
python -m pytest --cov=seedfuz --cov-report=term-missing
ruff check src tests
```

Test phần cứng phải đánh dấu `@pytest.mark.hardware` và không chạy trong suite mặc định. Test hiện bao phủ parser, mutation, state graph, validation an toàn, SQLite, API và dry-run campaign.

## Cấu trúc thư mục

```text
src/seedfuz/       mã nguồn và static dashboard
tests/             unit/integration tests
datasets/          PCAP seed; uploads không commit
experiments/       cấu hình campaign tái lập
results/           SQLite, CSV, PDF và log sinh ra
docs/university/   yêu cầu chính thức của trường
docs/research/     ghi chú nghiên cứu/kỹ thuật
docs/reports/      nội dung phục vụ báo cáo
papers/            tài liệu tham khảo
```

## Giới hạn và lộ trình

Bộ đọc hiện chỉ hỗ trợ classic PCAP/Ethernet/IPv4; PCAPNG và IPv6 chưa được xử lý. State graph là mô hình suy luận tổng quát, cần tinh chỉnh theo giao thức thật. Đo bộ nhớ cần telemetry do thiết bị cung cấp. Boofuzz adapter đã có nhưng campaign mặc định sử dụng mutator riêng để bảo đảm thuật toán smart selection của đề tài có thể đo và giải thích độc lập.

Xem trạng thái chi tiết, phần đã làm và việc còn lại tại [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md).

