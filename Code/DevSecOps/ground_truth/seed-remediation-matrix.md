# Ma trận lỗi gieo cài - phát hiện - khắc phục

Đây là ma trận **kỳ vọng theo thiết kế** của fixture, chưa phải kết quả quan sát. Kết quả thực tế phải lấy từ raw report và `detection_rate.csv` sau khi chạy workflow baseline/after-fix.

| Seed | Loại lỗi | Scanner / rule dự kiến | Vị trí | Khắc phục tham chiếu | Kết quả mong đợi sau sửa |
|---|---|---|---|---|---|
| SEEDED-SAST-01–03 | `eval`, SQL ghép chuỗi, shell injection | Semgrep: `python.lang.security.audit.eval`, `python.flask.security.sql-injection-string-format`, `python.lang.security.audit.subprocess-shell-true` | `src/app/app.py` | `patches/fix_sast.patch` | Không còn ba mẫu nguy hiểm trong code được quét |
| SEEDED-SCA-01–05 | Dependency cũ có advisory | Trivy FS: CVE khai báo trong manifest | `src/app/requirements.txt` | `patches/fix_docker.patch` và phiên bản `requirements-fixed.txt` | Các phiên bản cũ không còn trong dependency manifest baseline/after-fix tương ứng |
| SEEDED-SECRET-01–03 | AWS/GitHub/private-key marker giả | Gitleaks: `seeded-config-aws-key`, `seeded-config-github-token`, `seeded-config-rsa-key` | `src/app/config_dummy.py` | `patches/fix_secret.patch` | Giá trị đọc từ environment; không lưu secret trong source |
| SEEDED-SECRET-04 | Token demo trong workflow fixture | Gitleaks: `seeded-workflow-github-token` | `lab/workflows-vuln/leaky.yml` | `patches/fix_secret.patch` | Fixture không còn token hardcode và không nằm trong `.github/workflows` đang chạy |
| SEEDED-IAC-01–02 | SSH/RDP mở ra toàn Internet | Checkov: CKV_AWS_24/25 | `infra/main.tf` | `patches/fix_infra.patch` | CIDR giới hạn theo biến cấu hình quản trị |
| SEEDED-IAC-03–04 | Bucket thiếu kiểm soát mã hóa/public access | Checkov: CKV_AWS_145/20 | `infra/main.tf` | `patches/fix_infra.patch` | Bật mã hóa và chặn truy cập công khai |
| SEEDED-IAC-05 | IAM quyền quản trị quá rộng | Checkov: CKV_AWS_274 | `infra/main.tf` | `patches/fix_infra.patch` | Thay quyền wildcard/admin bằng quyền tối thiểu cho lab |
| SEEDED-IAC-06 | ECR repository thiếu kiểm soát | Checkov: CKV_AWS_51/136 | `infra/main.tf` | `patches/fix_infra.patch` | Bật scan-on-push và tag immutability theo fixture |
| SEEDED-DOCKER-02/04/05 | Dockerfile yếu: cấu hình package/user/healthcheck | Trivy FS misconfiguration: DS-0002, DS-0029, DS-0005 | `lab/docker/Dockerfile` | `patches/fix_docker.patch` | Multi-stage build, dependency đã sửa, non-root user và healthcheck |
| SEEDED-DOCKER-01 | Vulnerable `requests==2.19.0` trong image baseline | Trivy image: CVE-2018-18074 | `lab/docker/Dockerfile` baseline | `patches/fix_docker.patch` loại bỏ lệnh cài dependency cũ | CVE không còn trong image after-fix; phần image CVE bổ sung vẫn được triage riêng |
| SEEDED-DOCKER-03 | File dummy được copy vào image | Không kỳ vọng Gitleaks; đây là đối chứng âm | `lab/docker/dummy-secret.txt` | Loại khỏi image bằng `patches/fix_docker.patch` | Không được tính là secret detection |

## Cách đọc số liệu

- “Dự kiến” ở trên không chứng minh scanner đã phát hiện; chỉ raw JSON sau khi chạy mới là quan sát.
- Recall được tính trên các seed `measured: true`; hai đối chứng không đo được không nằm trong mẫu số.
- Finding không khớp seed được ghi là unmatched. Chỉ gọi là false positive sau khi review xác nhận.
- Trạng thái after-fix vẫn có thể chứa finding mới do scanner database hoặc base image thay đổi; giữ nguyên raw report và ngày chạy để tái lập.

