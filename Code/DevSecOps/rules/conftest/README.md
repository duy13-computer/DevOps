# Conftest input contract

`tools/normalize_results.py` converts vendor-specific reports into `findings.json`:

```json
{"findings":[{"tool":"trivy","severity":"HIGH","category":"sca","title":"example","file":"src/app/requirements.txt","rule_id":"CVE-0000-0000"}],"scan_errors":[]}
```

Policies use the normalized contract so scanner output format changes stay isolated
from the gate logic. `g0` emits warnings, `g1` denies HIGH/CRITICAL, and `g2` denies
secrets plus CRITICAL IaC findings.
