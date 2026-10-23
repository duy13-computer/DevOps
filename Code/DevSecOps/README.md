# DevSecOps Lab: security gates before deployment

Repository mẫu cho đề tài **Xây dựng đường ống DevSecOps phát hiện cấu hình sai và lỗ hổng trước triển khai**. Ứng dụng, Dockerfile và Terraform ban đầu cố ý có lỗi để sinh ra bằng chứng scan. Chỉ chạy trên máy lab; không deploy Terraform hay image ban đầu lên môi trường thật.

## Cấu trúc và luồng gate

Các workflow ở thư mục `.github/workflows/` tại gốc repository: `pr-fast.yml` chạy scan nhanh ở chế độ cảnh báo; `pr-secure.yml` chạy Semgrep, Gitleaks, Trivy filesystem và Checkov song song rồi áp dụng gate g1; `main-release.yml` build image đã harden, scan image và IaC, áp dụng g1/g2, sau đó đẩy image lên ECR và ký/attest bằng Cosign. Workflow hợp nhất cũ được giữ làm bản tham khảo tại `.github/workflows/security-pipeline.yml.disabled`.

`tools/test/summarize.py` chuẩn hóa JSON của Semgrep, Gitleaks, Trivy và Checkov thành `reports/summary.json`, đồng thời tạo bản tóm tắt PR và danh sách ngoại lệ được áp dụng:

Để chạy workflow phát hành, cấu hình GitHub Secrets `AWS_ROLE_ARN`, `AWS_REGION` và `ECR_REPOSITORY`. IAM role cần tin cậy GitHub OIDC cho repository/branch này và chỉ có quyền ECR cần thiết; workflow không dùng AWS access key tĩnh.

| Gate | Hành vi | Quy tắc |
|---|---|---|
| `g0` | Cảnh báo, pipeline tiếp tục | MEDIUM/LOW được ghi nhận để triage |
| `g1` | Chặn | HIGH hoặc CRITICAL từ SAST/SCA/image/IaC |
| `g2` | Chặn tuyệt đối | Bất kỳ secret nào hoặc CRITICAL trong IaC |

Gate chạy trên toàn bộ phát hiện chuẩn hóa. Vì vậy g2 là mức nghiêm ngặt bổ sung; g1 vẫn chặn HIGH/CRITICAL ở mọi nhóm findings. Báo cáo JSON, SARIF nếu có, SBOM CycloneDX và `timing.json` được lưu thành artifact của workflow; bình luận PR hiển thị số lượng theo mức độ.

## Cài đặt và chạy local

Chạy trong Linux hoặc WSL với GNU Make, Bash, Python 3.12+, Docker daemon, Gitleaks, Trivy, Conftest, Syft, Cosign và GNU Parallel. `make bootstrap` tạo `.venv` và cài các phiên bản Semgrep/Checkov đang pin trong workflow; các CLI khác cần có trên `PATH`.

Từ repository root:

```bash
make -C Code/DevSecOps bootstrap
make -C Code/DevSecOps check-tools
make -C Code/DevSecOps scan-all
make -C Code/DevSecOps gate
```

`scan-all` tạo report trong `tests/results/raw/`, `reports/summary.json`, bản PR Markdown và `tests/results/metrics/timing.json`. Gate baseline có thể trả lỗi vì lab cố ý chứa seed; báo cáo vẫn được ghi để xem xét.

Để đo trung bình thời gian mỗi scanner và benchmark tuần tự/song song, cần ít nhất ba lượt:

```bash
make -C Code/DevSecOps measure PHASE=baseline RUNS=3
make -C Code/DevSecOps benchmark PHASE=baseline RUNS=3
```

Sau khi áp dụng patch, đổi phase thành `after-fix`. Thêm `INCLUDE_IMAGE=1` vào target `measure` để đo cả Docker build và Trivy image. Định nghĩa metric, cache và giới hạn môi trường được ghi trong `docs/measurement.md`.

Có thể chạy riêng các policy trên report đã chuẩn hóa:

```bash
conftest test Code/DevSecOps/reports/summary.json --policy Code/DevSecOps/policy/g0 --all-namespaces
conftest test Code/DevSecOps/reports/summary.json --policy Code/DevSecOps/policy/g1 --policy Code/DevSecOps/rules/conftest --data Code/DevSecOps/policy/exceptions.json --all-namespaces
conftest test Code/DevSecOps/reports/summary.json --policy Code/DevSecOps/policy/g2 --policy Code/DevSecOps/rules/conftest --data Code/DevSecOps/policy/exceptions.json --all-namespaces
```

## Áp dụng ground truth patches

Tại gốc repository, có thể áp dụng toàn bộ bản sửa tham chiếu bằng:

```bash
make -C Code/DevSecOps fix
```

Target này kiểm tra cả bốn patch trước rồi mới áp dụng. Chỉ chạy một lần trên baseline chưa sửa.

So sánh kết quả chuẩn hóa với ground truth bằng `Code/DevSecOps/tools/test/verify_ground_truth.py`; xem quy ước match và các seed chỉ dùng làm đối chứng tại `Code/DevSecOps/ground_truth/README.md`.

Patch secret thay giá trị hardcode bằng biến môi trường; patch Docker nâng Python, cập nhật các dependency đã gieo lỗi và chạy UID không đặc quyền; patch Terraform giới hạn cổng quản trị theo `management_cidr` (mặc định ví dụ `10.20.0.0/16`), bật mã hóa S3 và ECR scan-on-push, đồng thời thay quyền AdministratorAccess bằng quyền ghi log giới hạn. Sau đó chạy lại pipeline. Nếu muốn áp dụng trạng thái sửa đầy đủ thay vì patch, dùng `Dockerfile.fixed`, `requirements-fixed.txt` và `main.fixed.tf.example` làm tham khảo. Không đưa credentials thật vào biến CI; dùng GitHub Secrets hoặc OIDC với quyền tối thiểu.

## Ngoại lệ có thời hạn

Chỉ thêm ID finding được duyệt vào `Code/DevSecOps/.trivyignore`; đặt ngay phía trên mỗi ID hai dòng comment `# owner: tên hoặc email` và `# expires: YYYY-MM-DD`. `tools/check_exceptions.py` từ chối thiếu owner, thiếu ngày hoặc ngoại lệ hết hạn. Tích hợp kiểm tra này vào CI trước bước Trivy khi chấp nhận ngoại lệ trong dự án thật. Mỗi ngoại lệ cần ticket/lý do trong triage, người chịu trách nhiệm và ngày hết hạn ngắn; khi đến hạn, xóa ngoại lệ hoặc cập nhật sau khi review. Không dùng ngoại lệ để bỏ qua secrets hay CRITICAL IaC vì g2 vẫn chặn các phát hiện đó.

## Đầu ra

- `tests/results/raw/`: report JSON của scanners, `findings.json`, CycloneDX SBOM.
- `tests/results/metrics/timing.json`: thời gian từng bước (giây).
- `tests/results/metrics/pipeline_time.csv`: trung bình wall time và CPU time từng scanner sau ít nhất ba lượt.
- `tests/results/metrics/parallel_vs_seq.csv`: thời gian từng cặp chạy tuần tự/song song và speedup.
- `tests/results/triage/`: nơi lưu ghi chú xử lý finding và ngoại lệ có phê duyệt.
- `ground_truth/patches/`: bản sửa dùng cho thí nghiệm trước/sau.
