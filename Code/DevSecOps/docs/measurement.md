# Phương pháp đo

## Thời gian pipeline

`tools/test/measure_pipeline.py` gọi Semgrep, Gitleaks, Trivy filesystem và Checkov theo thứ tự, lặp tối thiểu ba lượt cho mỗi trạng thái. Mỗi lệnh có `wall_time_s` và `cpu_time_s`; CSV ghi trung bình theo bước, phase, `run_id`, `commit_sha` và `n_runs`. Mã thoát của từng lượt được giữ trong cột `exit_codes`, kể cả khi scanner phát hiện lỗi hoặc CLI chưa được cài.

`cpu_time_s` lấy từ CPU time của tiến trình con do hệ điều hành báo cáo. CPU của Docker daemon không được tính trong thời gian CPU của tiến trình `docker` phía client. Trên một số hệ điều hành, đặc biệt môi trường Windows không tương thích đầy đủ với Bash, số CPU con có thể không khả dụng; dùng Linux hoặc WSL để so sánh nhất quán.

Mặc định đo bốn scanner ở PR. Có thể thêm `--include-image` khi gọi script để đo build Docker và Trivy image. Baseline dùng `Dockerfile.vuln`; sau sửa dùng `Dockerfile.fixed`. Build image có thể thất bại nếu base image cũ không còn tải được; lỗi và mã thoát vẫn được lưu để không nhầm lượt thất bại với lượt thành công.

## Tuần tự và song song

`tools/test/benchmark_parallel.sh` chạy cùng bốn scanner tuần tự rồi qua GNU Parallel với bốn job. Mỗi cặp có `run_index`; thứ tự tuần tự/song song được luân phiên giữa các lượt để giảm thiên lệch do cache ấm. `speedup` được tính là `sequential_wall_time_s / parallel_wall_time_s`; giá trị lớn hơn 1 nghĩa là lượt song song hoàn tất nhanh hơn.

Chạy tối thiểu ba lượt và giữ cùng máy, cấu hình Docker, phiên bản scanner, trạng thái cache và tải hệ thống giữa baseline với after-fix. Database Trivy có thể tải/cập nhật qua mạng; kết quả thời gian bao gồm ảnh hưởng cache và kết nối. Đây là phép đo lab cục bộ, không phải SLO của runner CI.

## Tỷ lệ phát hiện

`verify_ground_truth.py` tính precision, recall và F1 theo từng tool so với các seed được đánh dấu `measured: true`. Báo cáo chưa khai báo trong ground truth được tính là finding chưa khớp cho precision; vì vậy đây là precision tương đối với bộ seed, không phải nhãn false positive đã được chuyên gia xác nhận. Seed chưa đo được loại khỏi recall và được giải thích trong `ground_truth/README.md`.
