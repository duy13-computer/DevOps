# Cơ sở lý thuyết và cách đánh giá

## 1. Shift-left và defense in depth

Shift-left đưa các phép kiểm tra bảo mật đến gần thời điểm viết mã và review thay đổi. Lỗi được phát hiện ở pull request thường có phạm vi nhỏ và dễ gắn với commit/người sửa hơn lỗi chỉ xuất hiện sau khi triển khai. NIST SSDF mô tả các thực hành phát triển an toàn có thể tích hợp vào vòng đời phát triển; pipeline này hiện thực hóa một phần bằng scanner và policy tự động. [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)

Defense in depth dùng nhiều lớp vì không scanner đơn lẻ nào thấy hết rủi ro. SAST xem luồng mã nguồn; SCA kiểm tra thư viện và phiên bản; secret scanning tìm thông tin xác thực vô tình đưa vào source; IaC scanning phân tích cấu hình hạ tầng; image scanning đánh giá thành phần trong artifact đã build. Kết quả được chuẩn hóa trước khi chính sách quyết định cảnh báo hay chặn.

| Lớp | Câu hỏi được kiểm tra | Công cụ trong lab | Giới hạn chính |
|---|---|---|---|
| SAST | Mã có mẫu nguy hiểm như `eval`, SQL ghép chuỗi hoặc shell injection không? | Semgrep | Quy tắc tĩnh có thể bỏ sót ngữ cảnh runtime hoặc báo nhầm |
| SCA | Dependency có phiên bản/CVE đã biết không? | Trivy filesystem | Kết quả phụ thuộc lock/version metadata và database tại thời điểm quét |
| Secret | Có token/key bị commit không? | Gitleaks; Trivy secret là lớp bổ sung | Chuỗi giả của lab không chứng minh khả năng thu hồi/rotation |
| IaC | Terraform có mở mạng quá rộng, lưu trữ công khai hoặc cấp quyền quá mức không? | Checkov; Trivy misconfiguration | Rule ID/severity thay đổi theo tool/version; cần review ngữ cảnh |
| Image | Artifact cuối cùng có package/configuration rủi ro không? | Trivy image; Syft tạo SBOM | Base image và advisory DB thay đổi theo thời gian |

## 2. CVSS, exploitability và triage

CVSS chuẩn hóa mức độ nghiêm trọng của một lỗ hổng bằng vector các thuộc tính. CVSS v4.0 tách Base, Threat, Environmental và Supplemental metrics; nhóm Threat có Exploit Maturity phản ánh tình trạng kỹ thuật khai thác. Vì vậy điểm CVSS là một đầu vào ưu tiên, không tự nó mô tả đầy đủ mức rủi ro của deployment cụ thể. FIRST giải thích Exploitability, tác động và Exploit Maturity trong tài liệu đặc tả. [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document)

Trong thực tế cần kết hợp ít nhất: mức độ CVSS, khả năng khai thác hiện tại, khả năng truy cập từ mạng, mức quyền cần có, dữ liệu/tài sản bị ảnh hưởng, biện pháp giảm thiểu và khả năng có bản vá. Scanner severity có thể đến từ advisory hoặc mapping của tool, nên cần ghi lại phiên bản công cụ/database và ngày chạy.

False positive là cảnh báo mà review xác nhận không phải lỗi trong ngữ cảnh cụ thể. Finding không khớp với bộ seed **không tự động là false positive**; có thể là lỗi thật chưa khai báo trong ground truth. Vì vậy `verify_ground_truth.py` tính precision tương đối với bộ seed trên baseline, và kết quả cần được chuyên gia triage trước khi gọi là tỷ lệ false positive. Với after-fix, tool ghi số seed còn sót và finding chưa khớp; seed được khắc phục không bị tính thành false negative. Image report có một seed CVE cố định của requests; CVE bổ sung của base image cần triage vì advisory thay đổi theo thời gian.

## 3. Gate đề xuất và ngoại lệ

Gate được thiết kế để chặn rủi ro có hậu quả cao, đồng thời giữ các vấn đề mức thấp trong luồng triage. Ngưỡng cụ thể cần được nhóm phát triển hiệu chỉnh từ chất lượng finding và thời gian xử lý thực đo.

| Mức | Hành vi | Lý do |
|---|---|---|
| g0 | Ghi cảnh báo MEDIUM, LOW và UNKNOWN; pipeline vẫn chạy | Không che mất finding chưa được scanner phân loại; cho phép triage định kỳ |
| g1 | Chặn HIGH và CRITICAL | Rủi ro cao cần sửa hoặc được đánh giá/ngoại lệ có trách nhiệm trước merge |
| g2 | Chặn mọi secret và CRITICAL IaC không ngoại lệ; chặn thêm rule IaC nhạy cảm và HIGH/CRITICAL image | Secret có thể bị khai thác ngay; mở cổng quản trị/IAM rộng và image có CVE nghiêm trọng cần kiểm soát chặt |

Risk acceptance phải có owner, lý do, phạm vi hẹp, thời hạn và review. Lab lưu ngoại lệ ở `policy/exceptions.json`; phạm vi phải khớp chính xác tool, category, severity, rule ID và file. Không cho wildcard, không cho ngoại lệ secret hoặc CRITICAL IaC. Finding HIGH/CRITICAL image hoặc rule IaC nhạy cảm chỉ được chấp nhận bằng ngoại lệ cụ thể còn hạn. Khi hết hạn, gate không còn coi finding là được chấp nhận.

Đây là policy đề xuất để thử nghiệm, không phải ngưỡng phổ quát. Nếu HIGH/CRITICAL gây quá nhiều chặn sai, cần phân tích nguyên nhân, sửa rule/parser hoặc giới hạn đúng phạm vi; không nên hạ gate toàn cục chỉ để pipeline xanh.

## 4. Policy as code và cấu hình cloud

Policy as code biểu diễn quyết định bảo mật dưới dạng rule có thể review, version-control và chạy giống nhau giữa máy local và CI. Conftest áp dụng Rego trên report chuẩn hóa. Tách rule khỏi scanner giúp thay tool mà vẫn giữ được chính sách, đồng thời cho phép lưu lý do gate đã chặn.

Các seed Terraform mô phỏng những lỗi như cổng quản trị mở công khai, bucket yếu và quyền IAM quá rộng. Đây là vấn đề trong các lĩnh vực quản lý danh tính/quyền, bảo vệ dữ liệu, cấu hình hạ tầng và quản lý lỗ hổng. CSA Cloud Controls Matrix cung cấp khung mục tiêu kiểm soát cloud theo các domain; CIS Benchmarks đưa ra hướng dẫn hardening theo sản phẩm/cấu hình. Bản lab chỉ đối chiếu nhóm kiểm soát ở mức khái niệm, chưa làm audit từng control ID hay chứng minh tuân thủ. [CSA CCM](https://cloudsecurityalliance.org/research/cloud-controls-matrix), [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

## 5. SBOM, provenance và signing

SBOM là inventory máy đọc được về thành phần của phần mềm. Lab dùng Syft xuất CycloneDX cho image; Trivy scan chính image đó để có thể liên hệ thành phần với advisory tại thời điểm chạy. SBOM không phải giấy chứng nhận an toàn: nó cần gắn với digest artifact, có nguồn tạo rõ ràng và được cập nhật/đối chiếu khi advisory mới xuất hiện. CycloneDX mô tả BOM cho inventory và các tình huống minh bạch chuỗi cung ứng. [CycloneDX SBOM guide](https://cyclonedx.org/guides/sbom/)

Provenance là thông tin có thể kiểm tra về artifact được tạo từ source nào, bởi builder/workflow nào, và qua bước build nào. SLSA định nghĩa provenance để truy nguyên artifact qua chuỗi cung ứng. Chữ ký image xác nhận artifact tương ứng với danh tính/khóa ký; Cosign hỗ trợ ký và kiểm chứng container, gồm key-based và keyless với OIDC. Chữ ký chứng minh tính toàn vẹn/nguồn gốc theo trust policy, không chứng minh image không có lỗ hổng. [SLSA provenance](https://slsa.dev/spec/v1.2/provenance), [Cosign container signing](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)

Phạm vi workflow hiện tại không publish image, không kết nối AWS/ECR, không tạo provenance SLSA hay ký image. GitHub Actions chỉ giữ image scan, SBOM và summary làm artifact. Nếu luận văn cần thực nghiệm signing, có thể bổ sung registry thử nghiệm và xác minh signature; việc đó không bắt buộc phải dùng AWS nhưng cần một registry/trust configuration phù hợp. Không nên mô tả output hiện có như một image đã ký hoặc provenance đã xác minh.

## 6. Thiết kế đánh giá trong repository

Ground truth khai báo 23 lỗi/đối chứng. 22 seed được đánh dấu đo được; một file dummy không phải secret là đối chứng âm, không dùng tính recall. Một CVE image có package/version cố định được thêm làm seed; CVE khác của base image vẫn cần triage riêng. Bốn patch sửa SAST, secret, Docker/dependency và Terraform. Thí nghiệm cần chạy tối thiểu ba lần cho baseline và ba lần after-fix.

Workflow thủ công `Ground truth before-after experiment` tạo trạng thái baseline trong thư mục tạm bằng cách đảo patch, không thay đổi checkout. Mỗi lượt giữ raw JSON, summary JSON, Trivy image report, CycloneDX SBOM và kết quả gate. Chạy `baseline` kỳ vọng g1 chặn; chạy `after-fix` kỳ vọng g1/g2 vượt qua. Nếu scanner hoặc report hỏng, thí nghiệm phải được ghi là invalid, không tính là “0 findings”.

`pipeline_time.csv` lưu thời gian wall/CPU theo bước cùng mã thoát. `detection_rate.csv` tính detection metrics trên baseline và số seed còn sót sau sửa. So sánh tuần tự/song song bằng `benchmark_parallel.sh`; cần giữ cùng runner, phiên bản công cụ, số job, trạng thái cache và database để so sánh có ý nghĩa. Thời gian tải database/cache nên được báo riêng hoặc mô tả rõ trong phương pháp.

Kết luận về chất lượng khắc phục nên dùng ít nhất ba góc: finding nào được phát hiện; finding nào biến mất sau patch; và gate có tạo kết quả mong đợi không. Chỉ thời gian thấp không có ý nghĩa nếu scanner thất bại hoặc thiếu report. Số liệu hiện có trong CSV trước khi chạy workflow mới mang trạng thái `invalid` do CLI thiếu trên môi trường cũ.

## Tài liệu tham khảo

- [NIST SP 800-218, Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
- [FIRST, CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)
- [CSA, Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [CycloneDX, SBOM guide](https://cyclonedx.org/guides/sbom/)
- [SLSA, Provenance](https://slsa.dev/spec/v1.2/provenance)
- [Sigstore, Signing Containers](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)

