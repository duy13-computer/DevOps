# DevSecOps Lab: security gates before deployment

Repository mẫu cho đề tài **Xây dựng đường ống DevSecOps phát hiện cấu hình sai và lỗ hổng trước triển khai**. Checkout hiện tại là trạng thái đã khắc phục; phép đo baseline dựng bản sao có seed tạm thời bằng cách đảo các patch. Chỉ chạy trên máy lab; không deploy Terraform hay image có seed lên môi trường thật.

## Cấu trúc và luồng gate

Các workflow ở thư mục `.github/workflows/` tại gốc repository: `pr-fast.yml` chạy scan nhanh ở chế độ cảnh báo; `pr-secure.yml` chạy Semgrep, Gitleaks, Trivy filesystem và Checkov song song rồi áp dụng g1; `main-release.yml` build image harden cục bộ, scan image/IaC, áp dụng g1/g2 và lưu báo cáo/SBOM thành artifact. `ground-truth-experiment.yml` chạy thủ công ba lượt cho baseline hoặc after-fix, giữ raw report, SBOM và thời gian. Các workflow không cần AWS và không đẩy image ra registry. Kết quả được đưa vào GitHub Step Summary và artifact; workflow hiện không tạo PR comment riêng. Workflow hợp nhất cũ được giữ làm bản tham khảo tại `.github/workflows/security-pipeline.yml.disabled`.

`tools/test/summarize.py` chuẩn hóa JSON của Semgrep, Gitleaks, Trivy và Checkov thành `reports/summary.json`, đồng thời tạo bản tóm tắt PR và danh sách ngoại lệ được áp dụng:

| Gate | Hành vi | Quy tắc |
|---|---|---|
| `g0` | Cảnh báo, pipeline tiếp tục | MEDIUM/LOW/UNKNOWN được ghi nhận để triage |
| `g1` | Chặn | HIGH hoặc CRITICAL từ SAST/SCA/image/IaC |
| `g2` | Chặn rủi ro bổ sung | Secrets và CRITICAL IaC không thể ngoại lệ; rule IaC nhạy cảm và HIGH/CRITICAL image cần ngoại lệ chính xác, còn hạn nếu được chấp nhận |

Gate chạy trên toàn bộ phát hiện chuẩn hóa. Vì vậy g2 là mức nghiêm ngặt bổ sung; g1 vẫn chặn HIGH/CRITICAL ở mọi nhóm findings. Báo cáo JSON, SBOM CycloneDX và timing được lưu thành artifact. Gate kiểm tra ngoại lệ trước khi áp dụng; thiếu hoặc sai cấu trúc chính sách sẽ làm CI thất bại.

## Cài đặt và chạy local

Chạy trong Linux hoặc WSL với GNU Make, Bash, Python 3.12+, Docker daemon, Gitleaks, Trivy, Conftest, Syft và GNU Parallel. `make bootstrap` tạo `.venv` và cài các phiên bản Semgrep/Checkov đang pin trong workflow; các CLI khác cần có trên `PATH`.

Từ repository root:

```bash
make -C Code/DevSecOps bootstrap
make -C Code/DevSecOps check-tools
make -C Code/DevSecOps scan-all
make -C Code/DevSecOps gate
```

`scan-all` quét checkout hiện tại và tạo report trong `tests/results/raw/`, `reports/summary.json`, bản Markdown trong `reports/` và `tests/results/metrics/timing.json`. Nếu finding vượt ngưỡng hoặc scanner lỗi, target trả lỗi nhưng vẫn giữ report để xem xét.

Để đo trung bình thời gian mỗi scanner và benchmark tuần tự/song song, cần ít nhất ba lượt:

```bash
make -C Code/DevSecOps measure PHASE=baseline RUNS=3
make -C Code/DevSecOps measure PHASE=after-fix RUNS=3
make -C Code/DevSecOps benchmark PHASE=baseline RUNS=3
```

Phase baseline tự đảo các patch trong bản sao tạm, không sửa checkout. Phase after-fix quét trạng thái hiện tại. Thêm `INCLUDE_IMAGE=1` để đo Docker build, Trivy image và tạo CycloneDX SBOM. Định nghĩa metric, cache và giới hạn môi trường được ghi trong `docs/measurement.md`.

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

Patch secret thay giá trị hardcode bằng biến môi trường; patch Docker loại dependency dễ tổn thương khỏi image baseline, dùng multi-stage build và user không đặc quyền; patch Terraform giới hạn cổng quản trị theo `management_cidr` (mặc định ví dụ `10.20.0.0/16`), bật mã hóa S3 và ECR scan-on-push, đồng thời thay quyền AdministratorAccess bằng quyền ghi log giới hạn. Sau đó chạy lại pipeline. Nếu muốn áp dụng trạng thái sửa đầy đủ thay vì patch, dùng `Dockerfile.fixed`, `requirements-fixed.txt` và `main.fixed.tf.example` làm tham khảo. Không đưa credentials thật vào biến CI.

## Ngoại lệ có thời hạn

Khai báo ngoại lệ được duyệt trong `policy/exceptions.json`; `policy/exceptions.example.json` chỉ minh họa schema và không được tự động nạp vào CI. `tools/check_exceptions.py` yêu cầu owner, lý do, timestamp RFC3339 còn hạn và scope chính xác theo `tool`, `category`, `severity`, `rule_id`, `file`. Không dùng `.trivyignore` để che findings. Secrets và CRITICAL IaC không thể được ngoại lệ hóa. Mỗi ngoại lệ cần ticket/phê duyệt trong triage; khi hết hạn phải xóa hoặc review lại.

## Đầu ra

- `tests/results/raw/`: report JSON của scanners, `findings.json`, CycloneDX SBOM.
- `tests/results/metrics/timing.json`: thời gian từng bước (giây).
- `tests/results/metrics/pipeline_time.csv`: trung bình wall time và CPU time từng scanner sau ít nhất ba lượt.
- `tests/results/metrics/detection_rate.csv`: TP/FP/FN theo seed khai báo; unmatched findings cần người review.
- `tests/results/experiments/<run-id>/<phase>/`: raw JSON, summary, SBOM, kết quả gate và trạng thái từng lượt.
- `tests/results/metrics/parallel_vs_seq.csv`: thời gian từng cặp chạy tuần tự/song song và speedup.
- `tests/results/triage/`: nơi lưu ghi chú xử lý finding và ngoại lệ có phê duyệt.
- `ground_truth/patches/`: bản sửa dùng cho thí nghiệm trước/sau.

## Tài liệu báo cáo

- `docs/requirements-matrix.md`: ma trận yêu cầu và tự đánh giá.
- `docs/theory-and-evaluation.md`: lý thuyết, ngưỡng gate, thiết kế đo và giới hạn.
- `ground_truth/seed-remediation-matrix.md`: seed, scanner dự kiến, cách sửa và kết quả mong đợi.
