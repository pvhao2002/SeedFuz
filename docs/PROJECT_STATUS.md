# Trạng thái triển khai SeedFuz

> Cập nhật: 24/08/2026. Tài liệu này phản ánh đúng trạng thái mã nguồn hiện tại, không thay thế đề cương chính thức trong `docs/university/`.

## Cơ sở triển khai

Project đã được xây dựng theo yêu cầu của đề tài **“Nghiên cứu Tối ưu hóa Kỹ thuật Mutational Fuzzing với Cơ chế Chọn Hạt giống Thông minh trong Dò quét Lỗ hổng IoT”**. Các nguồn đã đối chiếu gồm `ATTT_009.docx`, `ATTT09.docx` và `requirement.jpeg`.

## Những phần đã làm

- Khởi tạo Python package `seedfuz`, dependency manifest, CLI và cấu trúc kiểm thử.
- Đọc classic PCAP, giải mã Ethernet/VLAN, IPv4, TCP/UDP, tách Header/Payload và loại payload trùng.
- Suy luận đồ thị trạng thái từ thứ tự gói tin và TCP flags.
- Cài đặt Bit flipping, Byte mutation và đột biến trường nhạy cảm.
- Chấm điểm trường Header, delimiter, giá trị biên và trường độ dài nghi vấn để chọn hạt giống thông minh.
- Xây dựng campaign runner có seed ngẫu nhiên tái lập, giới hạn test case, tốc độ gửi và chế độ state-aware.
- Hỗ trợ `dry-run`, TCP và UDP; mặc định không tạo lưu lượng mạng.
- Thêm chốt an toàn: chiến dịch mạng cần `authorized=true`; IP public bị từ chối mặc định.
- Thêm adapter tạo Boofuzz `Session`, `Target`, TCP/UDP connection và request graph từ các payload đã bắt.
- Giám sát ping liên tục, ghi thời điểm mất phản hồi, đếm crash theo ngưỡng liên tiếp và nhận telemetry bộ nhớ qua HTTP nếu thiết bị cung cấp.
- Lưu campaign, test case, health sample và event vào SQLite.
- Tính số gói/giây, số lỗi gửi, crash, byte đã gửi, phân bố toán tử và xu hướng rò rỉ bộ nhớ.
- Xuất báo cáo CSV và PDF.
- Xây dựng FastAPI, upload PCAP, REST API, chạy campaign nền, dừng campaign và tải báo cáo.
- Xây dựng Web Dashboard responsive bằng HTML/CSS/JavaScript để cấu hình, theo dõi tiến trình, telemetry, log và lịch sử.
- Viết test cho PCAP, mutation, state machine, cấu hình an toàn, SQLite, API và dry-run end-to-end.
- Thêm cấu hình mẫu cho dry-run và thiết bị thật cùng script sinh PCAP demo.

## Trạng thái xác minh

Đã cài môi trường Python 3.12, sinh và phân tích PCAP demo thành công. Toàn bộ **13/13 test đã pass**; test bao phủ parser, mutation, state graph, cấu hình an toàn, SQLite, API upload và campaign dry-run end-to-end. Coverage hiện tại là **63%** và Ruff báo `All checks passed`.

CLI dry-run 100 test case đã hoàn tất với 100 case gửi thành công, 0 lỗi gửi và đủ ba nhóm toán tử (34 Bit flip, 33 Byte mutation, 33 Smart-field). SQLite, CSV 100 dòng dữ liệu và PDF một trang đã được sinh/kiểm tra thành công trong `results/`.

Phần chưa xác minh là kiểm tra dashboard trực tiếp trên trình duyệt và chiến dịch trên router/camera thật. Kiểm thử thiết bị thật cần PCAP, thiết bị, giao thức cụ thể và sự cho phép của người dùng.

## Hạn chế hiện tại

- Bộ đọc tích hợp hỗ trợ classic PCAP, chưa hỗ trợ PCAPNG, IPv6 hay link-layer ngoài Ethernet.
- State machine được suy luận từ chuỗi gói tin; chưa học phiên riêng theo 5-tuple hoặc grammar giao thức chuyên biệt.
- Campaign runner dùng bộ đột biến riêng; Boofuzz adapter hiện là đường chạy mở rộng, chưa phải engine mặc định của dashboard.
- Chỉ số bộ nhớ cần endpoint trả JSON dạng `{"memory_percent": 42.5}`; ping không thể tự đo RAM của thiết bị từ xa.
- Crash hiện được xác nhận qua nhiều lần health-check thất bại; chưa có cơ chế tự khởi động lại thiết bị.
- Chưa có xác thực người dùng cho dashboard; chỉ nên bind vào localhost hoặc mạng lab tin cậy.

## Việc tiếp theo

1. Mở dashboard, kiểm tra upload, campaign nền, log và responsive layout.
2. Tăng coverage cho CLI, reporting, monitor, network transport và Boofuzz adapter.
3. Bổ sung PCAP thật của thiết bị mục tiêu và grammar/state theo giao thức thực tế.
4. Chạy baseline random so với smart selection, lặp nhiều phiên và tổng hợp tốc độ/crash/memory trend.
5. Sau khi có thiết bị được cấp phép, thực hiện hardware test trên mạng cô lập và hoàn thiện nội dung báo cáo khóa luận.
