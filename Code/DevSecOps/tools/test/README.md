# Script đo và báo cáo

`run_pipeline_metrics.sh` chạy chuỗi scan local, lưu JSON trong `tests/results/raw/` và thời gian coarse-grained trong `tests/results/metrics/timing.json`. `summarize.py` chuẩn hóa report thành `reports/summary.json` và `reports/pr-summary.md`.

`measure_pipeline.py` chạy Semgrep, Gitleaks, Trivy FS và Checkov tối thiểu ba lần, ghi trung bình wall time/CPU time theo scanner vào `tests/results/metrics/pipeline_time.csv`. Chỉ định đúng trạng thái nguồn bằng `--baseline` hoặc `--after-fix`; thêm `--include-image` để build image phù hợp phase và đo Trivy image.

`benchmark_parallel.sh` so sánh tuần tự với GNU Parallel cho cùng bốn scanner, tối thiểu ba cặp lượt. Nó luân phiên thứ tự chạy để hạn chế ảnh hưởng cache và ghi `parallel_vs_seq.csv`.

Ví dụ từ gốc repository:

```bash
make -C Code/DevSecOps measure PHASE=baseline RUNS=3
make -C Code/DevSecOps benchmark PHASE=baseline RUNS=3
make -C Code/DevSecOps measure PHASE=after-fix RUNS=3
make -C Code/DevSecOps benchmark PHASE=after-fix RUNS=3
```

Chỉ số detection rate do `verify_ground_truth.py` tạo. Định nghĩa các metric và giới hạn của phép đo nằm trong `docs/measurement.md`.
