# Ground truth

`seeds.yaml` khai báo 23 trường hợp gieo cài/đối chứng. Mỗi trường hợp có loại finding, công cụ/rule hoặc CVE, đường dẫn, severity và cờ `measured`. Có 22 trường hợp đo được theo manifest. File dummy không phải secret là đối chứng âm; nó không tính vào recall cố định. Fixture Python 3.6 cũ không được build trong workflow thực nghiệm.

Ma trận seed, scanner dự kiến, cách khắc phục và kết quả mong đợi ở [seed-remediation-matrix.md](seed-remediation-matrix.md). Đây là kỳ vọng theo thiết kế, không phải số liệu quan sát.

## Tái tạo baseline và đo after-fix

Checkout hiện tại đã có patch remediation. `tools/test/measure_pipeline.py --baseline` sao chép repository vào thư mục tạm và dùng `git apply --reverse` trên bốn patch để khôi phục source, secret fixture, Dockerfile và Terraform baseline. Workspace ban đầu không bị thay đổi. `--after-fix` quét checkout đang mở.

Trên GitHub Actions, chạy thủ công workflow `Ground truth before-after experiment` một lần với phase `baseline` và một lần với `after-fix`. Mỗi lần chạy tối thiểu ba lần quét. Artifact giữ raw reports, summary chuẩn hóa, detection rate, thời gian, Trivy image report, SBOM CycloneDX và kết quả gate. Baseline phải bị g1 chặn; after-fix phải vượt qua g1/g2. Không có scanner/report thành công thì lượt đo được đánh dấu invalid.

Có thể gọi script từ repository root sau khi cài đủ scanner:

```bash
python Code/DevSecOps/tools/test/measure_pipeline.py --baseline --runs 3 --include-image
python Code/DevSecOps/tools/test/measure_pipeline.py --after-fix --runs 3 --include-image
```

## Cách hiểu metric

`verify_ground_truth.py` ghép finding với seed theo tool, category, rule/CVE, package/version và đường dẫn. Với baseline, `detection_rate.csv` ghi TP/FP/FN, precision, recall và F1. Với after-fix, file ghi seed còn sót và unmatched findings; seed đã loại bỏ không bị tính thành false negative. Unmatched finding chưa được xác nhận là false positive bởi chuyên gia. Một CVE image requests cố định được chấm; các CVE image khác vẫn cần triage. Không gọi unmatched rate là “false positive rate” nếu chưa triage thủ công.
