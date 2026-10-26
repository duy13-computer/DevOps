# Ma trận yêu cầu và tự đánh giá

Tài liệu này đối chiếu yêu cầu của đề tài với nội dung trong repository. Trạng thái “đã có” nghĩa là có cấu hình hoặc mã trong workspace; trạng thái đó **không** thay thế cho bằng chứng chạy thành công trên GitHub Actions.

## Đối chiếu yêu cầu

| Yêu cầu | Thành phần hiện có | Bằng chứng cần lưu | Trạng thái hiện tại |
|---|---|---|---|
| SAST, dependency, secret, IaC và image scanning | Semgrep, Trivy FS, Gitleaks, Checkov, Trivy image trong `.github/workflows/` | Raw JSON và `reports/summary.json` từ run thành công | Có một run main thành công [#39993266704](https://github.com/duy13-computer/DevOps/actions/runs/39993266704); cần thêm các lượt đo lặp |
| Báo cáo máy đọc được và tóm tắt PR | JSON chuẩn hóa, Markdown trong GitHub Step Summary, workflow artifacts | Ảnh Step Summary và artifact của PR | Đã cấu hình; workflow không tạo PR comment riêng |
| Gate cảnh báo/chặn | g0 cảnh báo LOW/MEDIUM/UNKNOWN; g1 chặn HIGH/CRITICAL; g2 không ngoại lệ hóa secret/CRITICAL IaC và bổ sung rule IaC/image nhạy cảm | Log Conftest cho baseline bị chặn và after-fix vượt qua | Đã cấu hình; cần chạy hai phase |
| Ngoại lệ có người sở hữu và ngày hết hạn | `policy/exceptions.json`, `tools/check_exceptions.py`, `rules/conftest/exceptions.rego` | JSON ngoại lệ được duyệt và log kiểm tra còn hạn | Đã cấu hình; secrets và CRITICAL IaC không được ngoại lệ |
| Lỗi gieo cài và bản sửa | `ground_truth/seeds.yaml`, bốn patch remediation | Ma trận seed/phát hiện/sửa và các summary theo từng lượt | 23 seed khai báo, 22 seed đo được theo manifest |
| Tỷ lệ phát hiện và thời gian | `measure_pipeline.py`, `verify_ground_truth.py`, workflow `ground-truth-experiment.yml` | `detection_rate.csv`, `pipeline_time.csv`, raw report từng lượt | Workflow đã cấu hình chạy baseline/after-fix năm lượt trên PR; chưa có artifact thực nghiệm từ phiên bản workflow mới |
| So sánh tuần tự/song song, cache | `benchmark_parallel.sh` và tài liệu đo | `parallel_vs_seq.csv`, cấu hình máy, cache/database state | Script có sẵn; cần chạy và ghi kết quả thật |
| SBOM và scan image trước/sau sửa | Syft CycloneDX và Trivy image trong workflow thực nghiệm | Mỗi phase có SBOM CycloneDX và Trivy JSON | Đã có một artifact scan main; artifact baseline/after-fix của workflow mới đang chờ PR run |
| Chạy thử image sau security gate | `main-release.yml` chạy image đã scan trên GitHub runner sau g1/g2, gọi `/health`, lưu deployment JSON và container log | Log step deploy cùng artifact `main-security-scan-evidence` | Đã cấu hình smoke deployment tạm; chưa chạy thật, không phải deploy production |
| Provenance và image signing | Có phần lý thuyết; workflow scan và chạy thử image cục bộ nhưng không publish image | Provenance có thể xác minh và chữ ký được kiểm tra | Ngoài phạm vi triển khai hiện tại; chưa tạo provenance hay ký image |
| CSA CCM/CIS | Bản đồ kiểm soát mức mục tiêu trong phần lý thuyết | Phiên bản benchmark và đối chiếu từng kiểm soát nếu báo cáo khẳng định tuân thủ | Chỉ đối chiếu khái niệm; không tuyên bố chứng nhận/tuân thủ |

## Những điểm đã sửa trong bản này

- Baseline thực nghiệm được dựng trong thư mục tạm bằng cách đảo các patch khắc phục; không còn quét nhầm trạng thái đã sửa rồi gắn nhãn baseline.
- Raw JSON và summary của từng lượt được giữ lại. Lượt thiếu scanner, thiếu report hoặc lỗi chuẩn hóa bị đánh dấu không hợp lệ.
- Các hàng thời gian cũ có mã thoát `127` được giữ làm lịch sử nhưng được ghi `measurement_status=invalid`; không dùng chúng để kết luận tốc độ.
- Ngoại lệ chuyển về một JSON chuẩn duy nhất với phạm vi chính xác theo tool/category/severity/rule/file, owner và timestamp hết hạn. Secrets và CRITICAL IaC luôn bị từ chối.
- Gate cảnh báo cả severity UNKNOWN; g2 chặn mọi finding CRITICAL thuộc IaC, kể cả rule chưa liệt kê.
- CI kiểm tra ngoại lệ trước khi áp dụng gate và không tự tạo file rỗng nếu file chính sách bị thiếu.
- Workflow thực nghiệm có thể chạy riêng `baseline` và `after-fix`, giữ SBOM/report image, rồi chứng minh kết quả gate mong đợi cho từng lượt.

## Tự đánh giá

| Hạng mục | Điểm hiện tại | Lý do |
|---|---:|---|
| Độ bao phủ pipeline | 8/10 | Đã cấu hình đủ năm nhóm quét theo yêu cầu; có PR workflow và nhánh chính |
| Rõ ràng của gate và ngoại lệ | 8/10 | Có mức cảnh báo/chặn, phạm vi ngoại lệ hẹp và hạn dùng; cần kiểm chứng trên runner |
| Khả năng tái lập thí nghiệm | 7/10 | Baseline có thể dựng từ patch và output được lưu theo lượt; cần chạy thử workflow để phát hiện khác biệt CLI/runtime |
| Deploy sau gate | 5/10 | Có smoke deployment chỉ bind loopback và tự dọn container; chưa xác nhận trên GitHub runner và không phải dịch vụ triển khai lâu dài |
| Chất lượng số liệu thực nghiệm | 3/10 | Có một run scan main thật và artifact, nhưng chưa có baseline/after-fix lặp lại, benchmark song song và triage xác nhận |
| Chuỗi cung ứng nâng cao | 4/10 | Có SBOM, nhưng chưa tạo/kiểm tra provenance hay chữ ký image |

**Đánh giá chung: phần thiết kế/pipeline khoảng 7–8/10; mức sẵn sàng nộp nếu chấm nặng bằng chứng hiện khoảng 5/10.** GitHub có một lượt scan thật trên commit `59748659c8ff2b917814049b8f4273cea701206d` với g1/g2 pass và artifact, nhưng chưa có thí nghiệm trước/sau nhiều lượt. Chưa thể kết luận đạt yêu cầu cho tới khi workflow mới chạy đủ baseline/after-fix, benchmark tuần tự/song song, triage và smoke deployment. Các số cũ không được trình bày như kết quả. `precision` trong công cụ là precision tương đối với seed đã khai báo, không phải tỷ lệ false positive được chuyên gia gán nhãn.

## Danh sách hoàn tất trước khi nộp

1. Chạy workflow `Ground truth before-after experiment` với phase `baseline`; lưu artifact và log chứng minh g1 chặn.
2. Chạy lại với phase `after-fix`; lưu log g1/g2 vượt qua, báo cáo Trivy image và SBOM CycloneDX.
3. Chạy workflow nhánh chính sau khi các gate pass; lưu `deployment.json`, container log và xác nhận container được dọn khỏi runner.
4. Chạy benchmark tuần tự/song song tối thiểu ba cặp với cùng runner/cấu hình cache; ghi rõ phiên bản tool và tình trạng cache.
5. Kiểm tra thủ công các finding unmatched; chỉ gọi là false positive sau khi người đánh giá xác nhận.
6. Nếu luận văn kết luận về provenance/signing, bổ sung registry thử nghiệm, tạo provenance có thể xác minh và kiểm tra chữ ký; nếu không, ghi đây là giới hạn của phạm vi.

