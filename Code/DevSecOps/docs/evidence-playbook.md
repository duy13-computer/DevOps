# Playbook bằng chứng thực nghiệm

Tài liệu này là lộ trình biến bằng chứng **đã chạy thật trên GitHub Actions** thành chương
thực nghiệm được chấm. Không bước nào yêu cầu bịa số liệu: mỗi bước chỉ kéo số liệu có thật
về và trình bày đúng phạm vi của nó.

## Nguyên tắc một dòng

> Chỉ công bố cái có `file + run_id + commit + người ký duyệt`. Thiếu một trong bốn thì ghi
> "chưa đo / còn mở" — không nội suy.

## Bước 0 — Xác định nguồn gốc (đã xác minh 27/10/2026)

| Thứ | Giá trị |
|---|---|
| Repository | `duy13-computer/DevOps` (public) |
| Workflow thực nghiệm | `Ground truth before-after experiment` |
| Run tham chiếu | `40346069403` (PR, commit `2d1449117edef1e7c69c4ea620fccc83e39de4b4`) |
| Artifact baseline | `ground-truth-baseline-40346069403` — 5 386 920 B, sha256 `f5f9524c…` |
| Artifact after-fix | `ground-truth-after-fix-40346069403` — 575 280 B, sha256 `e86540a1…` |
| Run nhánh chính | `40346092023` — `main-security-scan-evidence` (114 361 B) |
| Hết hạn artifact | **2027-01-24** → tải về trước mốc này |

Lịch sử workflow có 6 run: #1, #2 thất bại; #3–#6 thành công. Khi bảo vệ, khai báo cả lượt
thất bại như quá trình hiệu chỉnh — điều này làm tăng độ tin cậy, không giảm.

## Bước 1 — Kéo artifact về (2 cách)

**Cách A — trình duyệt (không cần cài gì):** mở run trên GitHub → mục *Artifacts* → tải 3 ZIP →
giải nén giữ nguyên cấu trúc `Code/DevSecOps/tests/results/...` về workspace.

**Cách B — `gh` CLI (tái lập được, tạo kèm manifest SHA-256):**

```bash
gh auth login
bash Code/DevSecOps/tools/evidence/fetch_artifacts.sh \
  --run-id 40346069403 --run-main 40346092023 --repo duy13-computer/DevOps
```

## Bước 2 — Sinh phụ lục từ số liệu thật

```bash
python3 Code/DevSecOps/tools/evidence/build_appendix.py \
  --source-label "GitHub run 40346069403 (duy13-computer/DevOps)" --strict
```

Đầu ra: `Code/DevSecOps/reports/evidence-appendix.md` (nội dung cho luận văn) và
`reports/evidence-index.json` (máy đọc được, kèm SHA-256 từng file). Mục 11 của phụ lục là
bảng **tuyên bố được phép / không được phép** — dán nguyên vào luận văn để tránh nói quá.

## Bước 3 — Lấp 3 lỗ hổng số liệu còn lại

Cả ba đều chạy lại được trên máy lab hoặc GitHub runner; không phải số liệu bịa:

1. **Benchmark tuần tự/song song** — hiện `parallel_vs_seq.csv` trống.

   ```bash
   make -C Code/DevSecOps bootstrap
   sudo apt-get install -y parallel          # cần GNU Parallel
   make -C Code/DevSecOps benchmark PHASE=after-fix RUNS=3
   ```

   Chấp nhận công bố speedup chỉ khi có ≥3 cặp `measurement_status=valid` trên cùng máy.

2. **Triage có người ký** — mở `tests/results/triage/unmatched_findings_*.csv`, điền
   `classification` (TRUE_POSITIVE / FALSE_POSITIVE / KNOWN_LIMITATION), `reviewer`,
   `reviewed_at`, `rationale`. Chỉ sau khi tất cả dòng có reviewer mới được viết "FPR = x%".

3. **Một ca ngoại lệ thật** — thêm vào `policy/exceptions.json` một ngoại lệ còn hạn
   (owner, ticket, `expires_at` RFC3339 tương lai, scope đúng tool/rule/file), kèm một ca
   hết hạn để chứng minh `check_exceptions.py` từ chối. Không ngoại lệ hóa secret hoặc
   CRITICAL IaC.

## Bước 4 — Đối chiếu với hội đồng chấm

| Tiêu chí thường bị trừ | File chứng minh | Trạng thái hiện tại |
|---|---|---|
| Log gate chặn baseline | `gate-results.txt` (baseline) | ✅ có trong artifact |
| After-fix vượt gate | `gate-results.txt` (after-fix) | ✅ có trong artifact |
| Raw report mỗi scanner | `run-*/raw/{semgrep,gitleaks,trivy-fs,trivy-image,checkov}.json` | ✅ có trong artifact |
| SBOM | `run-*/raw/sbom.cyclonedx.json` | ✅ có trong artifact |
| Thời gian trung bình | `pipeline_time.csv` (chỉ dòng `valid`) | ✅ có, lọc dòng `127` |
| Detection/recall theo seed | `detection_rate.csv` (baseline) | ✅ có, ghi đúng là "tương đối seed" |
| Benchmark song song | `parallel_vs_seq.csv` | ❌ phải chạy (Bước 3.1) |
| FPR được xác nhận | triage CSV có reviewer | ❌ phải ký (Bước 3.2) |
| Deploy sau gate | `deploy/deployment.json` + `container.log` | ✅ có trong artifact main |
| Xuất xứ máy/công cụ | `environment.json` | ✅ có trong artifact |
| Ngoại lệ có hạn | `policy/exceptions.json` + log kiểm tra | ❌ cần 1 ca thật (Bước 3.3) |

## Giới hạn phải viết thẳng vào luận văn

- Smoke deploy là **container tạm loopback trên runner**, không phải triển khai sản phẩm.
- Provenance và ký image **chưa làm** — ghi là phạm vi ngoài, không ghi là đã có.
- `P'`/`FP'` trong detection CSV là precision **tương đối với seed**, không phải FPR chuyên gia.
- Số đo là **warm-cache** (DB Trivy tải trước), không đại diện cold-start.
