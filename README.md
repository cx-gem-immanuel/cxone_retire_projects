# CxOne Project Retirement Tool

## Introduction

Automates end-of-life processing for Checkmarx One projects. 

For each project in the input list, the tool generates a PDF security report, validates the download, and optionally deletes the project. 

Runs are resumable; progress is tracked via control files so interrupted runs can be safely restarted.

**Prerequisites**

- Python 3.10+ with `requests` installed (`pip install requests`)
- `config.ini` populated with CxOne host URLs and API credentials

---

## Usage

```
python cxone_retire_projects.py --config <ini> (--projects <names> | --csv <file>) [OPTIONS]
```

#### Usage examples

**Report only, two projects:**
```bash
python cxone_retire_projects.py --config prod.ini \
    --projects "ProjectAlpha,ProjectBeta"
```

**Report only, from CSV, larger batch:**
```bash
python cxone_retire_projects.py --config prod.ini \
    --csv retire_projects.csv --batch-size 10
```

**Full retirement (report + delete):**
```bash
python cxone_retire_projects.py --config prod.ini \
    --csv retire_projects.csv --poll-timeout 1200 --delete
```

**CSV format:** one project name per line; optional header row is skipped automatically. _See included sample_to_retire.csv for an example_

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `--config` | `config.ini` | CxOne credentials and host configuration file. |
| `--projects` | | Comma-separated project names. Mutually exclusive with `--csv`. |
| `--csv` | | Path to a CSV file of project names (first column used). Mutually exclusive with `--projects`. |
| `--output-dir` | `./reports` | Folder where PDF reports are saved. |
| `--control` | `.control` | Folder for resumability control files. |
| `--log-dir` | `./logs` | Folder for the timestamped log file. |
| `--batch-size` | `5` | Number of projects processed in parallel. |
| `--poll-interval` | `15` | Seconds between report status checks. |
| `--poll-timeout` | `300` | Maximum seconds to wait per report before moving on. |
| `--insecure` | off | Disable TLS certificate verification. |
| `--delete` | off | Delete each project after its PDF is validated. Omitting this flag leaves projects untouched. |

---

## Expected Output

One result line per project is printed after each batch. Detail goes to the log file.

```
==============================================================
  Batch 1 / 39  --  projects 1-7 of 271  (1m 47s)
  [OK]    SpaceX/GNC/Guidance/DVJA       REPORT_GENERATED
  [OK]    NASA/condor                     REPORT_GENERATED
  [FAIL]  IAM-PATCH-DA_prod              NO_SCAN_FOUND
  [OK]    legacy-auth-service             REPORT_GENERATED, PROJECT_DELETED
==============================================================
```

**Result codes**

| Code | OK/Fail | Meaning |
|---|---|---|
| `REPORT_GENERATED` | OK | PDF downloaded and validated. |
| `REPORT_GENERATED, PROJECT_DELETED` | OK | PDF validated and project deleted. |
| `SKIP_GENERATED` | OK | PDF already generated in a prior run. |
| `SKIP_DELETED` | OK | Project already deleted in a prior run. |
| `NO_SCAN_FOUND` | OK | No completed scan; project deleted if `--delete` is set. |
| `PROJECT_NOT_FOUND` | FAIL | Project name not found in CxOne. |
| `REPORT_REQUEST_ERROR` | FAIL | Report request rejected by the server. |
| `REPORT_TIMEOUT` | FAIL | Report did not finish within `--poll-timeout`. Saved for retry on next run. |
| `REPORT_GENERATION_FAILED` | FAIL | Server reported report generation failed. |
| `REPORT_DOWNLOAD_FAILED` | FAIL | PDF download failed. |
| `REPORT_PDF_INVALID` | FAIL | Downloaded file failed validation. |
| `PROJECT_DELETE_FAILED` | FAIL | Project deletion rejected by the server. |
| `UNEXPECTED_ERROR` | FAIL | Unexpected error; details in the log file. |

A summary with result counts and timing is printed at the end of each run.

---

## Resumability

Progress is tracked in the `--control` folder. On startup, projects already recorded are skipped.

| File | Written when | Effect on next run |
|---|---|---|
| `reported.txt` | PDF validated successfully. | Skips report generation; jumps to deletion if `--delete` is set. |
| `deleted.txt` | Project deleted successfully. | Project skipped entirely. |
| `report_timeout.csv` | Report times out. | Checks if the prior report has since completed and downloads it; otherwise submits a fresh request. Removed once resolved. |

**Recommended workflow**

1. Run without `--delete` to generate and review all PDFs.
2. Run again with `--delete` to retire projects. Already-reported projects skip straight to deletion.
3. To resume after an interruption, re-run the same command unchanged.

> To force a project to reprocess, remove its name from the relevant control file.
