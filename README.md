# Đường ống DevSecOps trước triển khai

Lab tái lập cho đề tài **“Xây dựng đường ống DevSecOps phát hiện cấu hình sai và lỗ hổng trước triển khai”**. Mục tiêu là đo các kiểm soát tự động, phân biệt cảnh báo với điều kiện chặn phát hành, và so sánh trạng thái có seed với trạng thái đã khắc phục.

Ứng dụng và cấu hình ban đầu cố ý chứa lỗi minh họa. Chỉ chạy scan trong môi trường lab; không deploy Terraform, image hoặc ứng dụng có seed lên môi trường thật.

## Kiến trúc

```text
Pull request
  ├─ pr-fast   ─ Semgrep + Gitleaks ─────────────── cảnh báo nhanh
  └─ pr-secure ─ Semgrep + Gitleaks + Trivy FS + Checkov
                  └─ chuẩn hóa finding ─ g0 ghi nhận ─ g1 chặn HIGH/CRITICAL

Nhánh main
  └─ build image cục bộ ─ Trivy image ─ Syft SBOM ─ g1/g2 gates ─ báo cáo artifact
```

Semgrep kiểm tra mã Python; Gitleaks tìm secret; Trivy kiểm tra dependency, cấu hình và image; Checkov kiểm tra Terraform. Conftest áp dụng gate trên report đã chuẩn hóa. Các workflow nằm trong `.github/workflows/`; hướng dẫn chi tiết ở [Code/DevSecOps/README.md](Code/DevSecOps/README.md).

## Chuẩn bị

Chạy các lệnh trong Linux hoặc WSL với GNU Make và Bash. Cần Python 3.12+, Docker Engine/Desktop đang chạy, Gitleaks, Trivy, Conftest, Syft và GNU Parallel. `make bootstrap` tạo `.venv` và cài Semgrep/Checkov theo phiên bản workflow; các CLI còn lại được cài ở cấp hệ thống.

```bash
make -C Code/DevSecOps bootstrap
make -C Code/DevSecOps check-tools
```

## Chạy lại lab

Ở trạng thái ban đầu, các finding được gieo làm một số gate thất bại có chủ đích. Lệnh `scan-all` vẫn lưu báo cáo để xem xét.

```bash
make -C Code/DevSecOps scan-all
make -C Code/DevSecOps gate
```

Để áp dụng toàn bộ bản sửa tham chiếu, chạy lệnh sau một lần từ workspace có trạng thái baseline:

```bash
make -C Code/DevSecOps fix
```

Sau đó chạy lại scan và gate. Các patch riêng, seed và quy tắc so khớp được mô tả trong [ground_truth/README.md](Code/DevSecOps/ground_truth/README.md).

Đo trung bình tối thiểu ba lượt cho baseline và sau khi sửa:

```bash
make -C Code/DevSecOps measure PHASE=baseline RUNS=3
make -C Code/DevSecOps measure PHASE=after-fix RUNS=3
make -C Code/DevSecOps benchmark PHASE=baseline RUNS=3
make -C Code/DevSecOps benchmark PHASE=after-fix RUNS=3
```

`measure` ghi thời gian từng scanner vào `Code/DevSecOps/tests/results/metrics/pipeline_time.csv`; thêm `INCLUDE_IMAGE=1` để đo build và scan image, hoặc truyền `--include-image` khi gọi script trực tiếp. `benchmark` cần GNU Parallel và ghi các cặp tuần tự/song song vào `parallel_vs_seq.csv`. Cách đọc số liệu và giới hạn đo nằm trong [docs/measurement.md](Code/DevSecOps/docs/measurement.md).

## Tài liệu và kết quả

- [Code/DevSecOps/README.md](Code/DevSecOps/README.md): cài đặt và chạy từng lớp.
- `Code/DevSecOps/reports/`: summary JSON và Markdown.
- `Code/DevSecOps/tests/results/metrics/`: thời gian và detection rate.
- `Code/DevSecOps/ground_truth/`: seed và patch phục vụ thí nghiệm.

Không thêm credentials thật vào repo. Chỉ dùng chuỗi giả được ghi rõ cho fixture. Workflow hiện chỉ quét, áp dụng gate và lưu bằng chứng; không cần tài khoản AWS.
