# Công cụ thí nghiệm

`measure_pipeline.py` thực hiện tối thiểu ba lượt. `--baseline` tạo bản sao tạm có seed bằng cách đảo patch remediation; `--after-fix` quét checkout hiện tại. `--include-image` build image tương ứng với phase, quét Trivy image và tạo CycloneDX SBOM. Raw reports và summary được giữ riêng cho từng lượt. Workflow PR chạy năm lượt mỗi phase, ghi phiên bản tool/runner và tạo bảng triage cho finding chưa khớp seed.

```bash
python Code/DevSecOps/tools/test/measure_pipeline.py --baseline --runs 5 --include-image
python Code/DevSecOps/tools/test/measure_pipeline.py --after-fix --runs 5 --include-image
```

`verify_ground_truth.py` tự chạy cuối phép đo để ghi `tests/results/metrics/detection_rate.csv` và file `PENDING_REVIEW` cho finding chưa khớp. `pipeline_time.csv` chỉ là dữ liệu hợp lệ khi `measurement_status=valid`; thiếu CLI/report không được tính thành một lần chạy nhanh. `fp` trong CSV đo lường chưa được người review xác nhận và không được trình bày như false positive đã xác nhận.

Định nghĩa metric, cache, gate kỳ vọng và giới hạn kết luận nằm trong `docs/measurement.md`. Ma trận các seed nằm trong `ground_truth/seed-remediation-matrix.md`.
