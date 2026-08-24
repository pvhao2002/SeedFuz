# Trạng thái dự án SeedFuz

> Cập nhật ngày 24/08/2026

## Những phần đã hoàn thành

Mình đã xây dựng phiên bản đầu tiên của SeedFuz dựa trên yêu cầu trong `docs/university/`. Project hiện có thể:

- Đọc file PCAP, tách payload TCP/UDP và nhận biết một số trường dữ liệu nhạy cảm.
- Mô phỏng luồng giao tiếp bằng State Machine.
- Tạo dữ liệu đột biến bằng Bit flipping, Byte mutation và Smart-field mutation.
- Chạy chiến dịch ở chế độ an toàn `dry-run`, TCP hoặc UDP.
- Theo dõi tốc độ gửi, lỗi kết nối, thời điểm thiết bị mất phản hồi và xu hướng sử dụng bộ nhớ nếu thiết bị có hỗ trợ telemetry.
- Lưu kết quả vào SQLite và xuất báo cáo CSV/PDF.
- Upload PCAP, cấu hình và theo dõi chiến dịch bằng Web Dashboard.
- Tạo Boofuzz session từ các payload đã thu thập để tiếp tục phát triển theo giao thức thực tế.

Mình cũng đã bổ sung CLI, cấu hình mẫu, PCAP demo, kiểm tra tự động và hướng dẫn sử dụng trong `README.md`.

## Kết quả kiểm tra

- 13/13 test đã chạy thành công.
- Ruff không còn báo lỗi định dạng mã nguồn.
- Coverage hiện tại đạt 63%.
- Chiến dịch dry-run 100 test case hoàn tất với 100 case gửi thành công và không có lỗi.
- SQLite, CSV và PDF đã được tạo và kiểm tra.

## Phần cần làm tiếp

Project chưa được thử trực tiếp với router hoặc camera thật. Khi có thiết bị và PCAP thực tế, mình cần bổ sung cấu trúc giao thức cụ thể, kiểm tra dashboard trên môi trường lab và chạy hai nhóm thí nghiệm: đột biến ngẫu nhiên và chọn hạt giống thông minh. Kết quả nhiều lần chạy sẽ được dùng để so sánh tốc độ fuzzing, số crash và xu hướng rò rỉ bộ nhớ.

Hiện parser mới hỗ trợ classic PCAP, Ethernet, IPv4, TCP và UDP; chưa hỗ trợ PCAPNG hoặc IPv6. Dashboard cũng chưa có đăng nhập nên chỉ nên chạy trên localhost hoặc mạng thử nghiệm riêng.
