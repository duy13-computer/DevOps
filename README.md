# Đường ống DevSecOps trước triển khai

Lab tái lập cho đề tài **“Xây dựng đường ống DevSecOps phát hiện cấu hình sai và lỗ hổng trước triển khai”**. Checkout hiện tại là trạng thái đã khắc phục; phép đo baseline dựng một bản sao có seed trong thư mục tạm bằng cách đảo patch, không sửa checkout.

Baseline thực nghiệm cố ý tạo lỗi minh họa. Chỉ chạy scan trong môi trường lab; không deploy Terraform, image hoặc ứng dụng có seed lên môi trường thật.

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

Lệnh `scan-all` lưu báo cáo và gate có thể thất bại nếu phát hiện rủi ro vượt ngưỡng.

```bash
make -C Code/DevSecOps scan-all
make -C Code/DevSecOps gate
```

Nếu bạn có checkout baseline cũ chưa áp dụng patch, dùng lệnh sau để sửa. Checkout hiện tại đã có các bản sửa, nên không chạy lại lệnh này:

```bash
make -C Code/DevSecOps fix
```

Sau đó chạy lại scan và gate. Các patch riêng, seed và quy tắc so khớp được mô tả trong [ground_truth/README.md](Code/DevSecOps/ground_truth/README.md).

Đo tối thiểu ba lượt cho mỗi phase. `baseline` dựng bản sao dễ tổn thương tạm thời; `after-fix` quét checkout hiện tại:

```bash
make -C Code/DevSecOps measure PHASE=baseline RUNS=3
make -C Code/DevSecOps measure PHASE=after-fix RUNS=3
make -C Code/DevSecOps benchmark PHASE=baseline RUNS=3
make -C Code/DevSecOps benchmark PHASE=after-fix RUNS=3
```

`measure` ghi thời gian từng scanner vào `Code/DevSecOps/tests/results/metrics/pipeline_time.csv`; thêm `INCLUDE_IMAGE=1` để đo build và scan image, hoặc truyền `--include-image` khi gọi script trực tiếp. `benchmark` cần GNU Parallel và ghi các cặp tuần tự/song song vào `parallel_vs_seq.csv`. Cách đọc số liệu và giới hạn đo nằm trong [docs/measurement.md](Code/DevSecOps/docs/measurement.md).

Trên GitHub, chạy workflow `Ground truth before-after experiment` hai lần, chọn lần lượt `baseline` và `after-fix`. Artifact chứa report từng lượt, SBOM CycloneDX, thời gian, detection rate và bằng chứng gate. Các dòng cũ có `measurement_status=invalid` không phải kết quả đo hợp lệ.

## Tài liệu và kết quả

- [Code/DevSecOps/README.md](Code/DevSecOps/README.md): cài đặt và chạy từng lớp.
- [Ma trận yêu cầu và tự đánh giá](Code/DevSecOps/docs/requirements-matrix.md): mức đáp ứng, thiếu bằng chứng và danh sách hoàn tất.
- [Cơ sở lý thuyết và đánh giá](Code/DevSecOps/docs/theory-and-evaluation.md): shift-left, gate, CVSS, ngoại lệ, SBOM/provenance và giới hạn.
- [Ma trận seed và khắc phục](Code/DevSecOps/ground_truth/seed-remediation-matrix.md): lỗi gieo cài, scanner dự kiến và cách sửa.
- `Code/DevSecOps/reports/`: summary JSON và Markdown.
- `Code/DevSecOps/tests/results/metrics/`: thời gian và detection rate.
- `Code/DevSecOps/ground_truth/`: seed và patch phục vụ thí nghiệm.

Không thêm credentials thật vào repo. Chỉ dùng chuỗi giả được ghi rõ cho fixture. Workflow hiện chỉ quét, áp dụng gate và lưu bằng chứng; không cần tài khoản AWS.
