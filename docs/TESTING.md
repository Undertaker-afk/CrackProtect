# Testing IronLock

Since IronLock is a Windows-targeted SDK, runtime behavioral validation should be executed on Windows 10/11 hosts (physical and virtual). CI can still run metadata/static checks on Linux.

## 1. QA Framework Entry Point (Mandatory)
Use the QA runner in `tests/qa/run_qa.py` for release gating:

```bash
python tests/qa/run_qa.py --commit <git-sha>
```

The runner generates CI artifacts in `artifacts/qa/`:
- `qa_report.json`: full report (static validation + matrix + metrics)
- `qa_summary.json`: gate result (`pass` true/false)
- `qa_trends.json`: append-only trend history across commits

## 2. Static Validation of Protected Binaries
Static validation consumes generated binary manifests from `tests/fixtures/protected_bin/` (or your real export path).

Required checks:
- PE sections contain at least `.text` and `.rdata`
- Metadata includes: `build_id`, `opcode_map_version`, `integrity_marker`
- Opcode map is non-empty
- Integrity markers list is present and non-empty

## 3. Scenario Matrix Execution
Scenario expectations are defined in `tests/qa/scenario_matrix.yaml`.

Mandatory scenario classes:
- **Clean host baseline**
- **Debugger present** (e.g., x64dbg)
- **VM/sandbox variants** (VirtualBox, VMware, sandbox service)
- **MITM/proxy cases** (Fiddler/explicit proxy interception)

Scenario outputs are compared against expected booleans from `scenario_results.json` (or your runtime capture source).

## 4. Detection Quality + Performance Budgets
The QA runner computes:
- False-positive rate (FPR)
- False-negative rate (FNR)
- Overall accuracy
- Runtime overhead vs baseline in milliseconds

Default overhead budget is `75ms` and can be overridden with `--budget-ms`.

## 5. CI Artifacts + Trend Reporting
GitHub Actions workflow: `.github/workflows/qa.yml`
- Runs QA on push and pull requests
- Uploads `artifacts/qa/` as a CI artifact bundle
- Persists trend history in `qa_trends.json` per commit SHA

## 6. Mandatory Release Pass Criteria
A release **MUST NOT** proceed unless all are true:
1. `qa_summary.json` has `pass: true`
2. Static validation passes with zero errors
3. Scenario matrix has zero failed assertions
4. Performance overhead is within declared budget
5. FPR <= 3% and FNR <= 2% on release candidate dataset
6. QA artifacts are attached to the release CI run and archived

## 7. Legacy Manual Verification (Recommended)
- Open compiled binary in **IDA Pro** and verify sensitive strings are encrypted/hashed.
- Validate critical NT calls are resolved via direct syscall path where expected.
- Cross-check anti-debug/anti-VM module responses on physical host and virtualized test beds.
