# Phương pháp đo

## Thời gian pipeline

`tools/test/measure_pipeline.py` yêu cầu tối thiểu ba lượt; workflow CI dùng năm lượt cho mỗi phase. `--baseline` sao chép checkout vào thư mục tạm và đảo bốn patch remediation để khôi phục lỗi có chủ đích; `--after-fix` quét checkout hiện tại. Baseline không sửa file làm việc của bạn. Cả hai phase chạy Semgrep, Gitleaks, Trivy filesystem và Checkov; với `--include-image`, còn build image, chạy Trivy image và tạo SBOM CycloneDX bằng Syft.

Mỗi lượt giữ raw JSON trong `tests/results/experiments/<run-id>/<phase>/run-NN/raw/` và summary chuẩn hóa bên cạnh trong `summary/`. `environment.json` ghi runner, phiên bản công cụ và tình trạng cache; `pipeline_time.csv` lưu thời gian trung bình, còn `experiment.json` giữ thời gian và mã thoát riêng từng lượt. Workflow tải Trivy vulnerability DB trước khi tính thời gian; các phép đo được mô tả là warm-cache và không đại diện cho cold-start. Hàng có thiếu scanner/report được đánh dấu `invalid`; mã thoát 127 không được tính là một lần chạy nhanh thành công. Các hàng cũ từ máy thiếu scanner vẫn được giữ để truy vết nhưng không được dùng trong kết luận.

`cpu_time_s` lấy từ CPU time của tiến trình con do hệ điều hành báo cáo. CPU của Docker daemon không được tính vào thời gian CPU của tiến trình `docker` phía client. Trên Windows/WSL, dùng cùng môi trường Linux cho cả hai phase để so sánh. Thời gian database download, cache lạnh và tải hệ thống cần được ghi cùng điều kiện chạy.

## Trước/sau và gate

Workflow `Ground truth before-after experiment` chạy tự động trên pull request với hai phase cùng lúc; chạy thủ công thì có thể chọn một phase. Mỗi phase có năm lượt scan, báo cáo scan image, SBOM và kiểm tra gate từng lượt. Baseline kỳ vọng g1 và g2 chặn; after-fix kỳ vọng g1 và g2 vượt qua. Nếu scanner/report lỗi hoặc kỳ vọng gate không đạt, workflow phải thất bại và artifact được giữ để điều tra.

Workflow chính quét checkout đã sửa và lưu bằng chứng; workflow thực nghiệm là nơi tái tạo có chủ đích lỗi baseline. Không dùng fixture baseline làm ứng dụng để triển khai.

## Tuần tự và song song

`tools/test/benchmark_parallel.sh` chạy cùng bốn scanner tuần tự và bằng GNU Parallel, ba cặp cho mỗi phase trong workflow CI. `--baseline` dựng bản sao baseline bằng patch đảo; `--after-fix` đo checkout hiện tại. Mỗi cặp có `run_index`; thứ tự tuần tự/song song được luân phiên giữa các lượt để giảm thiên lệch thứ tự trên cùng cache ấm. `speedup` bằng `sequential_wall_time_s / parallel_wall_time_s`; giá trị lớn hơn 1 nghĩa là lượt song song hoàn tất nhanh hơn. Chỉ dùng cặp có `measurement_status=valid`.

Chạy tối thiểu ba lượt, trên cùng loại máy, phiên bản scanner, số job, trạng thái cache và trạng thái database. Kết quả lab cục bộ không đại diện cho SLO của runner CI. Thứ tự chạy được lưu qua `run_index` và phase để phân tích tác động cache; thời gian benchmark không tự suy ra tỷ lệ phát hiện.

## Tỷ lệ phát hiện và false positive

`verify_ground_truth.py` so finding với seed `measured: true` và xuất bảng `tests/results/triage/unmatched_findings_<phase>_<run-id>.csv` cho finding chưa khớp. Các cột `fp`, precision và F1 hiện chỉ là số liệu tương đối với ground truth khai báo; unmatched finding **không** tự động là false positive. Người đánh giá cần điền classification, reviewer, thời điểm và lý do triage trước khi báo cáo số false positive đã xác nhận. Với after-fix, CSV ghi số seed còn sót; seed đã xóa không bị tính thành false negative.

Trivy image report được giữ và seed `requests==2.19.0` đo một CVE image cố định. Các CVE khác của base image vẫn được giữ để triage; unmatched finding chỉ là FP tương đối với seed, không phải false positive đã xác nhận.

Đối chứng âm và seed không ổn định theo advisory/base image được đánh dấu `measured: false`, không nằm trong recall. Lưu ngày chạy, phiên bản scanner, image digest và report để giải thích khác biệt giữa hai lần chạy.
